// The proof queue. GPU workers pull from it: they claim a job under a lease, prove, then report the result with
// that lease. A lease that runs out puts the job back in the queue; after MAX_ATTEMPTS the outcome is unavailable.

export type Outcome = "conformant" | "deviation" | "unavailable";
export const OUTCOMES: readonly Outcome[] = ["conformant", "deviation", "unavailable"];

export interface Job {
  request_id: string;
  state: "pending" | "leased" | "done";
  created_at: number;
  attempts: number;
  lease: string | null;
  worker: string | null;
  leased_at: number | null;
  lease_until: number | null;
  outcome: Outcome | null;
  proof_digest: string | null;
  proof_ms: number | null;
  done_at: number | null;
}

export interface Limits {
  leaseMs: number;
  maxAttempts: number;
}

export async function claim(db: D1Database, worker: string, now: number, limits: Limits): Promise<Job | null> {
  // One statement, so two workers can never hold the same job.
  return db
    .prepare(
      `UPDATE jobs SET state = 'leased', lease = ?1, worker = ?2, leased_at = ?3, lease_until = ?4, attempts = attempts + 1
       WHERE request_id = (
         SELECT request_id FROM jobs
         WHERE (state = 'pending' OR (state = 'leased' AND lease_until <= ?3)) AND attempts < ?5
         ORDER BY created_at LIMIT 1)
       RETURNING *`,
    )
    .bind(crypto.randomUUID(), worker, now, now + limits.leaseMs, limits.maxAttempts)
    .first<Job>();
}

export interface Result {
  outcome: Outcome;
  proof_digest?: string;
  proof_ms?: number;
}

/** Settles a leased job. False when the lease is not the current one or has run out. */
export async function complete(db: D1Database, requestId: string, lease: string, result: Result, now: number): Promise<boolean> {
  const row = await db
    .prepare(
      `UPDATE jobs SET state = 'done', outcome = ?3, proof_digest = ?4, proof_ms = ?5, done_at = ?6, lease = NULL
       WHERE request_id = ?1 AND state = 'leased' AND lease = ?2 AND lease_until > ?6
       RETURNING request_id`,
    )
    .bind(requestId, lease, result.outcome, result.proof_digest ?? null, result.proof_ms ?? null, now)
    .first();
  return row !== null;
}

/** Jobs whose last lease ran out with no attempts left are settled as unavailable. */
export async function expire(db: D1Database, now: number, limits: Limits): Promise<number> {
  const r = await db
    .prepare(
      `UPDATE jobs SET state = 'done', outcome = 'unavailable', done_at = ?1, lease = NULL
       WHERE state = 'leased' AND lease_until <= ?1 AND attempts >= ?2`,
    )
    .bind(now, limits.maxAttempts)
    .run();
  return r.meta.changes;
}
