// A stand-in for the H100 provers, run by the cron while MOCK_GPUS is set. It uses the same claim and complete
// calls a real GPU worker makes over HTTP, so swapping it for real machines changes nothing else.
// shortcut: no proof is generated and outcomes are sample data; replace with real workers on the /api/v1/prover routes.

import { claim, complete, type Limits, type Outcome } from "./jobs";
import { sha256 } from "./challenges";

export const PROOF_MS = 58_800; // one request per batch, F23

export async function mockGpus(db: D1Database, gpus: number, now: number, limits: Limits): Promise<void> {
  const { results: busy } = await db
    .prepare(`SELECT request_id, lease, leased_at FROM jobs WHERE state = 'leased' AND worker LIKE 'mock-h100-%'`)
    .all<{ request_id: string; lease: string; leased_at: number }>();

  let free = gpus - busy.length;
  for (const j of busy) {
    if (now - j.leased_at < PROOF_MS) continue;
    const digest = await sha256("mock proof " + j.request_id);
    // About one reply in ten is shown as a deviation, decided by the reply so a replay gives the same answer.
    const outcome: Outcome = parseInt(digest.slice(0, 2), 16) < 26 ? "deviation" : "conformant";
    if (await complete(db, j.request_id, j.lease, { outcome, proof_digest: digest, proof_ms: PROOF_MS }, now)) free++;
  }
  for (let i = 0; free > 0; i++, free--) if (!(await claim(db, `mock-h100-${i}`, now, limits))) break;
}
