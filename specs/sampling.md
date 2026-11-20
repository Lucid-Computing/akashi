# Sampling Protocol

## Overview

Unpredictable, tamper-proof selection of requests for ZK proof generation using drand public randomness beacon from specification section 8.

## Randomness Beacon

**Source**: drand quicknet mainnet (production chain)

| Parameter | Value | Source |
|---|---|---|
| Chain hash | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` | F36 |
| Genesis time | 1692803367 (Unix timestamp) | F36 |
| Period | 3 s | F36 |
| Beacon URL | `https://api.drand.sh/52db9ba7.../public/{round}` | Parameters |

Round number `r = round_at(<timestamp>)` is publicly computable and independent of any action by gateway, log or client (F7).

The request is receipted at `served_at` after the reply is validated, and that timestamp determines `beacon_round` (F11).

## Selection Rule

Given:
- `t` = transcript commitment (32 bytes)
- `r` = beacon round number (8-byte big-endian)
- `s` = the authenticated 48-byte quicknet signature for round `r`

Compute:
```
h = SHA-256(t || r || s)
k = first 4 bytes of h as big-endian uint32
selected = (k mod N) == 0
```

The signed mode determines the active divisor (20 for live, 1 for soak). The shadow divisor 1000 uses the same selection word over the same logged requests. Under an ideal uniform word, the exact probability is `ceil(2^32/N)/2^32`. [RFC-0005](../docs/rfcs/RFC-0005-beacon-escrow.md#proposed-design)

## Escrow timeline

1. Before the log append, stage the private transcript under the recomputed public leaf hash. Bind its transcript commitment, signed sampling mode, assigned round and original `served_at`.
2. Read that leaf from authenticated log history and recompute its hash. Check the assignment against the original timestamp. Verify the pinned quicknet signature for the fixed round before using the selection word.
3. Erase unselected escrow as soon as selection resolves. For a selected leaf, use its hash as the durable handoff identity. The auditor inbox accepts that identity once even when the sender retries after losing an acknowledgment. The sender releases its outbox copy after the inbox durably acknowledges the same leaf. If the deadline passes first, a gap records the missing confirmation. The auditor may already hold a job whose acknowledgment was lost.
4. At `served_at + W_escrow`, discard any undelivered private material and retain a redacted coverage gap. One expiry worker supervises each database. A role-private FIFO wakes it when any local process stages an earlier deadline. Startup and access checks also enforce the deadline. The v1 cap is five minutes. [Service parameters](parameters.md#service-parameters)

## Properties Achieved

From spec §3 security properties:

- **S2 (Unpredictable selection)**: Attacker cannot predict selection before transcript is bound (commitment ID published, transcript receipted, beacon round determined)
- **S3 (Non-omission)**: Every selected request enters the log and is challenged; log transparency allows public verification
- **S4 (Soundness)**: ZK proof verifies exact model output; Lean-verified soundness bound q/2^124 + 2^-101 (F32)

## Implementation

Run `make test-escrow` to exercise private custody, timed expiry, handoff replay and redacted gap records. Configure an operator-owned wrapping key and a separate auditor recipient key. Each service owns its database and key files. The sampler's `resolve_logged_leaf` accepts a verified public-log reader, the canonical receipt hasher and the quicknet round functions. Treat all three as trusted deployment dependencies.

Start `ExpiryWorker.run()` for each staging database and call `stop()` during shutdown. Disk erasure requires a running host. After downtime, the store purges overdue material when it opens. Protect the host clock and keep transient databases out of long-lived snapshots. The auditor's own retention starts from its separate job lifecycle.

## Related Specifications

- `receipt-log.md`: Receipt format with beacon_round field
- `audit-protocol.md`: Challenge protocol using selection rule
- `parameters.md`: Sampling rates N
- `facts-register.md`: F7-F13 (beacon parameters and escrow timeline)
