// Challenge intake and the public record. A challenge names one logged reply; every challenge on the same reply
// shares one proof job, so the GPUs prove each reply once. Quotas are those of specs/parameters.md (Rate Limits).

import type { Job } from "./jobs";

export const ROLES = ["holder", "regulator", "auditor", "thirdparty"] as const;
export const REASONS = ["model", "altered", "routine"] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOUR = 3_600_000;
export const PER_CHALLENGER_PER_HOUR = 10;
export const PER_REPLY_PER_DAY = 3;

export interface Filing {
  request_id: string;
  role: (typeof ROLES)[number];
  reason: (typeof REASONS)[number];
  note: string;
}

export type Intake =
  | { ok: true; id: string }
  | { ok: false; status: 400 | 429; error: string; retryAfter?: number };

/** Checks a filing's shape. Returns the error, or null when it is well formed. */
export function invalid(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "Send a JSON object.";
  const b = body as Record<string, unknown>;
  if (typeof b.request_id !== "string" || !UUID.test(b.request_id)) return "request_id must be a lowercase UUID.";
  if (!ROLES.includes(b.role as never)) return `role must be one of ${ROLES.join(", ")}.`;
  if (!REASONS.includes(b.reason as never)) return `reason must be one of ${REASONS.join(", ")}.`;
  if (b.note !== undefined && (typeof b.note !== "string" || b.note.length > 120)) return "note must be text of 120 characters at most.";
  return null;
}

export async function file(db: D1Database, challenger: string, f: Filing, now: number): Promise<Intake> {
  const counts = await db
    .prepare(
      `SELECT (SELECT COUNT(*) FROM challenges WHERE challenger = ?1 AND filed_at > ?3) AS mine,
              (SELECT COUNT(*) FROM challenges WHERE request_id = ?2 AND filed_at > ?4) AS reply`,
    )
    .bind(challenger, f.request_id, now - HOUR, now - 24 * HOUR)
    .first<{ mine: number; reply: number }>();
  if (counts && counts.mine >= PER_CHALLENGER_PER_HOUR)
    return { ok: false, status: 429, error: `At most ${PER_CHALLENGER_PER_HOUR} challenges per key per hour.`, retryAfter: 3600 };
  if (counts && counts.reply >= PER_REPLY_PER_DAY)
    return { ok: false, status: 429, error: `At most ${PER_REPLY_PER_DAY} challenges per reply per day.`, retryAfter: 86_400 };

  const id = "chl_" + hex(crypto.getRandomValues(new Uint8Array(8)));
  // One transaction. The insert repeats the quota test, so a race past the check above still cannot exceed it,
  // and the job is opened only if the challenge went in. A reply whose earlier proof was unavailable is queued again.
  const [inserted] = await db.batch([
    db
      .prepare(
        `INSERT INTO challenges (id, request_id, role, challenger, reason, note, filed_at)
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
         WHERE (SELECT COUNT(*) FROM challenges WHERE challenger = ?4 AND filed_at > ?8) < ?10
           AND (SELECT COUNT(*) FROM challenges WHERE request_id = ?2 AND filed_at > ?9) < ?11`,
      )
      .bind(id, f.request_id, f.role, challenger, f.reason, f.note, now, now - HOUR, now - 24 * HOUR, PER_CHALLENGER_PER_HOUR, PER_REPLY_PER_DAY),
    db
      .prepare(
        `INSERT INTO jobs (request_id, created_at) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM challenges WHERE id = ?3)
         ON CONFLICT (request_id) DO UPDATE SET state = 'pending', attempts = 0, outcome = NULL, done_at = NULL, created_at = ?2
         WHERE jobs.outcome = 'unavailable'`,
      )
      .bind(f.request_id, now, id),
  ]);
  if (!inserted.meta.changes) return { ok: false, status: 429, error: "Quota reached. Try again later.", retryAfter: 60 };
  return { ok: true, id };
}

export interface ChallengeView {
  id: string;
  request_id: string;
  role: string;
  reason: string;
  note: string;
  filed_at: string;
  /** queued: waiting for a GPU. proving: a GPU holds the job. settled: the outcome is final. */
  state: "queued" | "proving" | "settled";
  outcome: Job["outcome"];
  proving_since: string | null;
  settled_at: string | null;
  proof_digest: string | null;
  proof_ms: number | null;
}

const VIEW = `SELECT c.id, c.request_id, c.role, c.reason, c.note, c.filed_at,
  j.state AS job_state, j.outcome, j.leased_at, j.done_at, j.proof_digest, j.proof_ms
  FROM challenges c JOIN jobs j ON j.request_id = c.request_id`;

type Row = Omit<ChallengeView, "state" | "filed_at" | "proving_since" | "settled_at"> & {
  filed_at: number;
  job_state: Job["state"];
  leased_at: number | null;
  done_at: number | null;
};

const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());
const STATE = { pending: "queued", leased: "proving", done: "settled" } as const;

function view(r: Row): ChallengeView {
  return {
    id: r.id, request_id: r.request_id, role: r.role, reason: r.reason, note: r.note, filed_at: iso(r.filed_at)!,
    state: STATE[r.job_state], outcome: r.outcome,
    proving_since: r.job_state === "leased" ? iso(r.leased_at) : null,
    settled_at: iso(r.done_at), proof_digest: r.proof_digest, proof_ms: r.proof_ms,
  };
}

export async function one(db: D1Database, id: string): Promise<ChallengeView | null> {
  const r = await db.prepare(`${VIEW} WHERE c.id = ?1`).bind(id).first<Row>();
  return r && view(r);
}

export async function recent(db: D1Database, limit: number): Promise<ChallengeView[]> {
  const { results } = await db.prepare(`${VIEW} ORDER BY c.filed_at DESC LIMIT ?1`).bind(limit).all<Row>();
  return results.map(view);
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export async function sha256(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
