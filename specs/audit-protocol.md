# Audit Protocol

## Overview

Challenge and proof verification system ensuring that receipted replies match the committed model from specification section 10.

## Challenge Flow

```
Client → AU: Submit challenge (t, x, y)
   ↓
AU → LG: Verify receipt exists for t
   ↓
AU → PV: Request conformance proof
   ↓
PV generates proof (~58.8 s at 1 per batch, F23)
   ↓
AU verifies proof (~21 s single thread, F26)
   ↓
AU → Client: Verdict (conform / deviate / unavailable)
```

## Challenge Submission

Client submits to `POST /audit/v1/challenges`:

```json
{
  "transcript_commitment": "<32-byte hex>",
  "prompt_token_ids": [200000, ...],
  "reply_token_ids": [...]
}
```

The auditor:

1. Fetches receipt from log matching `transcript_commitment`
2. Verifies receipt's `promise_sig` against log public key
3. Recomputes transcript commitment from receipt fields and token IDs
4. Confirms `t` matches
5. Checks beacon round: if within escrow + 72 hours, accepts challenge; otherwise rejects as expired

Returns `challenge_id` (UUID) and `status: "pending"`.

## Proof Types

### Conformance Proof

ZK proof that the reply matches the integer model's greedy output at temperature 0:

**Public inputs:**
- Commitment ID `C`
- Prompt token IDs `x`
- Reply token IDs `y`

**Proven statement:** "There exists an integer model with commitment ID `C` such that greedy decoding of prompt `x` produces reply `y`, with no range failure and no forced token."

Verification confirms exact model output (F30).

### Deviation Proof

Proves that a claimed reply deviates from the model:

**Public inputs:**
- Commitment ID `C`
- Prompt token IDs `x`
- Claimed reply token IDs `y`
- Deviation position `d` (0-based)
- Correct token at position `d`: `y_correct`

**Proven statement:** "There exists an integer model with commitment ID `C` such that greedy decoding of `x` produces `y_correct` at position `d`, and `y_correct ≠ y[d]`."

This proves deviation even when some range condition fails at an unevaluated position (F31).

## Verification Procedure

The auditor runs FlashProve's `cp_verify` binary (F26):

```bash
cp_verify \
  --proof <proof_file> \
  --public-inputs <json_file> \
  --commitment-id c7982f8a... \
  --output verdict.json
```

Returns:
- **Exit 0**: Proof valid, verdict is `conform` or `deviate` (from proof type)
- **Exit 1**: Proof invalid (malformed, wrong public inputs, or soundness violation)
- **Exit 2**: Verification error (bad input format, missing files)

Performance (F26):
- Single thread: about 21 s, up to 3.53 GB memory
- Shared VM (2-4 core): 36.2 to 44.0 s

## Verdict Publication

After verification, the auditor signs and publishes:

```json
{
  "challenge_id": "<uuid>",
  "transcript_commitment": "<32-byte hex>",
  "verdict": "conform",
  "proof_type": "conformance",
  "verified_at": "2026-11-20T12:00:00.000Z",
  "auditor_signature": "<Ed25519 signature>"
}
```

Or for deviation:

```json
{
  "verdict": "deviate",
  "proof_type": "deviation",
  "deviation_position": 42,
  "claimed_token": 200042,
  "correct_token": 200099
}
```

Or for unavailable (prover down, proof generation timeout, beacon unavailable):

```json
{
  "verdict": "unavailable",
  "reason": "prover_timeout"
}
```

Signature over:
```
"AuditVerdict" || challenge_id || transcript_commitment || verdict || verified_at as RFC3339 bytes
```

## Auditor Public API

### `POST /audit/v1/challenges`

Submit challenge. Returns `challenge_id`.

### `GET /audit/v1/challenges/{challenge_id}`

Returns challenge status:
- `pending`: Proof generation in progress
- `verifying`: Proof received, verification running
- `completed`: Verdict available

And when completed, the verdict object.

### `GET /audit/v1/verdicts?commitment={t}`

Returns all verdicts for transcript commitment `t`.

### `GET /audit/v1/verdicts/recent?hours={h}`

Returns verdicts from last `h` hours (up to 168).

### `GET /audit/v1/stats`

Returns:
```json
{
  "total_challenges": 123456,
  "conform": 123400,
  "deviate": 5,
  "unavailable": 51,
  "pending": 12,
  "last_updated": "2026-11-20T12:00:00.000Z"
}
```

## Automated Auditor Mode

The auditor runs continuous background challenges:

1. Fetch latest STH every 60 seconds
2. For each new receipt where beacon round is past escrow + 10 minutes:
   - Fetch beacon signature
   - Compute `k mod N`
   - If selected, submit challenge automatically
3. Track proof generation queue depth
4. Emit alerts if:
   - Deviation verdict found
   - `unavailable` rate exceeds 1%
   - Queue depth exceeds threshold
   - Proof generation time exceeds 120 seconds
   - Verification time exceeds 60 seconds

## Soundness and Completeness

From F32-F33:

- **Soundness**: Attacker making `q` hash queries has probability at most `q/2^124 + 2^-101` of forging a proof (Lean-verified bound)
- **Completeness**: Honest prover always produces valid conformance proof when reply matches model and no range failure occurred

When range failure occurs, the honest prover produces a deviation proof at the failure position, proving that the engine's reply is unprovable (not that it deviates).

## Challenge Limits

Per holder key:
- 10 challenges per hour
- 3 challenges per transcript per day

Prevents DoS against the prover.

## Related Specifications

- `sampling.md`: Selection rule and escrow timeline
- `receipt-log.md`: Receipt verification and log queries
- `verifier-kit.md`: Client-side verification procedure
- `facts-register.md`: F23, F26, F30-F33 (performance and soundness)
