// The Akashi platform service on Cloudflare: the web preview as static assets, and this API.
//   Public       GET  /api/v1/challenges, GET /api/v1/challenges/:id
//   Challengers  POST /api/v1/challenges                   Authorization: Bearer <challenger key>
//   GPU workers  POST /api/v1/prover/claim                 Authorization: Bearer <PROVER_TOKEN>
//                POST /api/v1/prover/jobs/:request_id      Authorization: Bearer <PROVER_TOKEN>
// The cron settles jobs whose leases ran out, and drives the mock GPUs while MOCK_GPUS is set.

import { file, invalid, one, recent, sha256, type Filing } from "./challenges";
import { claim, complete, expire, OUTCOMES, type Limits, type Result } from "./jobs";
import { mockGpus } from "./mock-gpu";

export interface Env {
  DB: D1Database;
  PROVER_TOKEN?: string;
  LEASE_MS: string;
  MAX_ATTEMPTS: string;
  MOCK_GPUS?: string;
}

const limits = (env: Env): Limits => ({ leaseMs: Number(env.LEASE_MS), maxAttempts: Number(env.MAX_ATTEMPTS) });

const json = (body: unknown, status = 200, headers: HeadersInit = {}) =>
  Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
const fail = (status: number, error: string, headers: HeadersInit = {}) => json({ error }, status, headers);

function bearer(req: Request): string | null {
  const m = /^Bearer (\S{16,512})$/.exec(req.headers.get("authorization") ?? "");
  return m ? m[1] : null;
}

async function body(req: Request): Promise<unknown> {
  if (Number(req.headers.get("content-length") ?? 0) > 4096) return null;
  try {
    return await req.json();
  } catch {
    return null;
  }
}

async function isProver(req: Request, env: Env): Promise<boolean> {
  const key = bearer(req);
  if (!key || !env.PROVER_TOKEN) return false;
  const [a, b] = await Promise.all([sha256(key), sha256(env.PROVER_TOKEN)]);
  const enc = new TextEncoder();
  return crypto.subtle.timingSafeEqual(enc.encode(a), enc.encode(b));
}

async function api(req: Request, env: Env, path: string[]): Promise<Response> {
  const now = Date.now();
  const route = `${req.method} ${path.join("/")}`;

  if (route === "GET challenges") {
    const limit = Math.min(100, Math.max(1, Number(new URL(req.url).searchParams.get("limit")) || 20));
    return json({ challenges: await recent(env.DB, limit) });
  }
  if (req.method === "GET" && path[0] === "challenges" && path.length === 2) {
    const c = await one(env.DB, path[1]);
    return c ? json(c) : fail(404, "No such challenge.");
  }
  if (route === "POST challenges") {
    const key = bearer(req);
    if (!key) return fail(401, "Send your challenger key as a bearer token.");
    const b = await body(req);
    const bad = invalid(b);
    if (bad) return fail(400, bad);
    const f = b as Filing;
    const r = await file(env.DB, await sha256(key), { ...f, note: f.note ?? "" }, now);
    if (!r.ok) return fail(r.status, r.error, r.retryAfter ? { "retry-after": String(r.retryAfter) } : {});
    return json(await one(env.DB, r.id), 201, { location: `/api/v1/challenges/${r.id}` });
  }

  if (path[0] === "prover") {
    if (!(await isProver(req, env))) return fail(401, "Unknown prover.");
    if (route === "POST prover/claim") {
      const b = (await body(req)) as { worker?: unknown } | null;
      if (typeof b?.worker !== "string" || !/^[\w.-]{1,64}$/.test(b.worker)) return fail(400, "worker must name the machine.");
      const job = await claim(env.DB, b.worker, now, limits(env));
      return job ? json({ request_id: job.request_id, lease: job.lease, lease_until: new Date(job.lease_until!).toISOString() }) : new Response(null, { status: 204 });
    }
    if (req.method === "POST" && path[1] === "jobs" && path.length === 3) {
      const b = (await body(req)) as ({ lease?: unknown } & Partial<Result>) | null;
      if (typeof b?.lease !== "string" || !OUTCOMES.includes(b.outcome!)) return fail(400, `Send lease and outcome (${OUTCOMES.join(", ")}).`);
      if (b.outcome !== "unavailable" && (typeof b.proof_digest !== "string" || !/^[0-9a-f]{64}$/.test(b.proof_digest)))
        return fail(400, "proof_digest must be a SHA-256 in lowercase hex.");
      if (b.proof_ms !== undefined && !(Number.isInteger(b.proof_ms) && b.proof_ms >= 0)) return fail(400, "proof_ms must be a whole number.");
      const ok = await complete(env.DB, path[2], b.lease, { outcome: b.outcome!, proof_digest: b.proof_digest, proof_ms: b.proof_ms }, now);
      return ok ? json({ request_id: path[2], outcome: b.outcome }) : fail(409, "This lease is not current. Claim again.");
    }
  }
  return fail(404, "No such route.");
}

export default {
  async fetch(req, env): Promise<Response> {
    const url = new URL(req.url);
    const [, root, version, ...rest] = url.pathname.split("/");
    if (root === "api") return version === "v1" ? api(req, env, rest) : fail(404, "No such route.");
    if (url.pathname === "/") return Response.redirect(`${url.origin}/app/`, 302);
    return new Response("Not found", { status: 404 });
  },

  async scheduled(_event, env, ctx): Promise<void> {
    const now = Date.now();
    ctx.waitUntil(
      (async () => {
        await expire(env.DB, now, limits(env));
        const gpus = Number(env.MOCK_GPUS ?? 0);
        if (gpus > 0) await mockGpus(env.DB, gpus, now, limits(env));
      })(),
    );
  },
} satisfies ExportedHandler<Env>;
