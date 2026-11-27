import { createExecutionContext, createScheduledController, env, SELF, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { claim, complete, expire } from "../src/jobs";
import { mockGpus, PROOF_MS } from "../src/mock-gpu";

const PROVER = { authorization: "Bearer test-prover-token-0001" };
const limits = { leaseMs: 600_000, maxAttempts: 3 };
const uuid = () => crypto.randomUUID();

function post(path: string, body: unknown, headers: Record<string, string>) {
  return SELF.fetch(`https://akashi.test/api/v1/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}
const challenge = (request_id: string, key = "holder-key-" + uuid(), extra = {}) =>
  post("challenges", { request_id, role: "regulator", reason: "model", ...extra }, { authorization: `Bearer ${key}` });
const get = (path: string) => SELF.fetch(`https://akashi.test/api/v1/${path}`);

describe("challenges", () => {
  it("files a challenge and shows it queued, then in the public list", async () => {
    const r = await challenge(uuid(), undefined, { note: "Routine check" });
    expect(r.status).toBe(201);
    const c = await r.json<{ id: string; state: string; note: string }>();
    expect(c).toMatchObject({ state: "queued", note: "Routine check" });
    expect(r.headers.get("location")).toBe(`/api/v1/challenges/${c.id}`);
    expect(await (await get(`challenges/${c.id}`)).json()).toEqual(c);
    const list = await (await get("challenges")).json<{ challenges: { id: string }[] }>();
    expect(list.challenges.map((x) => x.id)).toContain(c.id);
  });

  it("refuses a filing without a key or with a bad shape", async () => {
    expect((await post("challenges", { request_id: uuid(), role: "holder", reason: "model" }, {})).status).toBe(401);
    for (const bad of [{ request_id: "nope" }, { role: "king" }, { reason: "whim" }, { note: "x".repeat(121) }]) {
      expect((await challenge(uuid(), undefined, bad)).status).toBe(400);
    }
    expect((await get("challenges/chl_missing")).status).toBe(404);
  });

  it("shares one job per reply and holds 3 challenges per reply per day", async () => {
    const id = uuid();
    for (let i = 0; i < 3; i++) expect((await challenge(id)).status).toBe(201);
    const r = await challenge(id);
    expect(r.status).toBe(429);
    expect(r.headers.get("retry-after")).toBe("86400");
    const jobs = await env.DB.prepare("SELECT COUNT(*) AS n FROM jobs WHERE request_id = ?").bind(id).first<{ n: number }>();
    expect(jobs?.n).toBe(1);
  });

  it("lists the whole part of a fractional limit", async () => {
    for (let i = 0; i < 3; i++) expect((await challenge(uuid())).status).toBe(201);
    for (const [limit, count] of [["2.5", 2], ["1.5", 1]] as const) {
      const r = await get(`challenges?limit=${limit}`);
      expect(r.status).toBe(200);
      expect((await r.json<{ challenges: unknown[] }>()).challenges).toHaveLength(count);
    }
  });

  it("holds 10 challenges per key per hour", async () => {
    const key = "one-busy-holder-key";
    for (let i = 0; i < 10; i++) expect((await challenge(uuid(), key)).status).toBe(201);
    expect((await challenge(uuid(), key)).status).toBe(429);
  });
});

describe("prover", () => {
  it("lets only a known prover claim", async () => {
    expect((await post("prover/claim", { worker: "h100-01" }, {})).status).toBe(401);
    expect((await post("prover/claim", { worker: "h100-01" }, { authorization: "Bearer wrong-token-000000" })).status).toBe(401);
  });

  it("claims the oldest job, takes a result only with the current lease, and settles the challenge", async () => {
    await env.DB.exec("DELETE FROM jobs");
    const c = await (await challenge(uuid())).json<{ id: string; request_id: string }>();
    const job = await (await post("prover/claim", { worker: "h100-01" }, PROVER)).json<{ request_id: string; lease: string }>();
    expect(job.request_id).toBe(c.request_id);
    expect((await post("prover/claim", { worker: "h100-02" }, PROVER)).status).toBe(204);
    expect(await (await get(`challenges/${c.id}`)).json()).toMatchObject({ state: "proving" });

    const result = { outcome: "deviation", proof_digest: "ab".repeat(32), proof_ms: 58_800 };
    expect((await post(`prover/jobs/${job.request_id}`, { ...result, lease: "stale" }, PROVER)).status).toBe(409);
    expect((await post(`prover/jobs/${job.request_id}`, { ...result, proof_digest: "zz" , lease: job.lease }, PROVER)).status).toBe(400);
    expect((await post(`prover/jobs/${job.request_id}`, { ...result, lease: job.lease }, PROVER)).status).toBe(200);
    expect(await (await get(`challenges/${c.id}`)).json()).toMatchObject({ state: "settled", outcome: "deviation", proof_ms: 58_800 });
  });

  it("gives a job back when its lease runs out, and settles it unavailable after the last attempt", async () => {
    await env.DB.exec("DELETE FROM jobs");
    const c = await (await challenge(uuid())).json<{ id: string; request_id: string }>();
    let t = Date.now();
    const first = await claim(env.DB, "h100-01", t, limits);
    t += limits.leaseMs;
    expect(await complete(env.DB, c.request_id, first!.lease!, { outcome: "conformant", proof_digest: "00".repeat(32) }, t)).toBe(false);
    for (let i = 2; i <= 3; i++, t += limits.leaseMs) expect((await claim(env.DB, "h100-02", t, limits))?.attempts).toBe(i);
    expect(await claim(env.DB, "h100-03", t, limits)).toBeNull();
    expect(await expire(env.DB, t, limits)).toBe(1);
    expect(await (await get(`challenges/${c.id}`)).json()).toMatchObject({ state: "settled", outcome: "unavailable" });
    // A new challenge on that reply queues it again.
    expect(await (await challenge(c.request_id)).json()).toMatchObject({ state: "queued", outcome: null });
  });

  it("mock GPUs prove a queued job over two cron ticks", async () => {
    await env.DB.exec("DELETE FROM jobs");
    const c = await (await challenge(uuid())).json<{ id: string }>();
    const t = Date.now();
    await mockGpus(env.DB, 1, t, limits);
    expect(await (await get(`challenges/${c.id}`)).json()).toMatchObject({ state: "proving" });
    await mockGpus(env.DB, 1, t + PROOF_MS, limits);
    const done = await (await get(`challenges/${c.id}`)).json<{ state: string; outcome: string; proof_ms: number }>();
    expect(done).toMatchObject({ state: "settled", proof_ms: PROOF_MS });
    expect(["conformant", "deviation"]).toContain(done.outcome);
  });

  it("runs the cron without error", async () => {
    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController(), env, ctx);
    await waitOnExecutionContext(ctx);
  });
});

// Static assets are served before the Worker runs, so `wrangler dev` checks them, not this suite.
it("sends the root to the web preview", async () => {
  const root = await SELF.fetch("https://akashi.test/", { redirect: "manual" });
  expect(root.status).toBe(302);
  expect(root.headers.get("location")).toBe("https://akashi.test/app/");
});
