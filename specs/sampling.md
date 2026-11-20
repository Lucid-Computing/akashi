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
- `s` = public randomness (48 bytes SHA-512 signature from beacon round `r`)

Compute:
```
h = SHA-256(t || r || s)
k = first 4 bytes of h as big-endian uint32
selected = (k mod N) == 0
```

Where `N` is the sampling rate:
- Live requests: N = 20 (5% selected)
- Shadow requests: N = 1000 (0.1% selected)

A transcript is selected for proof with probability exactly 1/N (F9).

## Shadow Requests

The gateway seeds a public random stream of unpredictable shadow requests, each counted toward the threat models but not served to clients, to defeat selective compliance where the attacker checks whether `k mod N == 0` before deciding whether to deviate (F10).

Shadow requests use `N = 1000`. Selected shadows are proved by the auditor.

## Escrow Timeline

For beacon round `r`:

1. **Request receipted**: At `served_at`, gateway commits transcript commitment `t` and assigns `beacon_round = r`
2. **Round opens**: At genesis + r × period, round `r` is published by drand
3. **Escrow interval**: At genesis + r × period + 10 minutes (120 beacon rounds), audit protocol locks challenge set for round `r` (F12)
4. **Challenge delivery**: Within escrow + 72 hours, auditor delivers conformance or deviation proofs (F13)

```
served_at
    ↓
    Receipt with beacon_round=r
    ↓
[0-3s] ← beacon round r opens
    ↓
[10 min] ← escrow: selection is final
    ↓
[72 hours] ← proofs delivered or audit fails
```

## Properties Achieved

From spec §3 security properties:

- **S2 (Unpredictable selection)**: Attacker cannot predict selection before transcript is bound (commitment ID published, transcript receipted, beacon round determined)
- **S3 (Non-omission)**: Every selected request enters the log and is challenged; log transparency allows public verification
- **S4 (Soundness)**: ZK proof verifies exact model output; Lean-verified soundness bound q/2^124 + 2^-101 (F32)

## Implementation

### Gateway Side

```python
def compute_beacon_round(served_at: datetime) -> int:
    genesis = 1692803367  # Unix timestamp
    period = 3
    elapsed = served_at.timestamp() - genesis
    return int(elapsed / period)

def is_selected(transcript_commitment: bytes, beacon_round: int, beacon_sig: bytes, rate: int) -> bool:
    r_bytes = beacon_round.to_bytes(8, 'big')
    h = sha256(transcript_commitment + r_bytes + beacon_sig)
    k = int.from_bytes(h[:4], 'big')
    return (k % rate) == 0
```

### Auditor Side

1. Fetch all receipts from log for rounds `r_min` to `r_max`
2. For each round `r`, fetch beacon signature: `GET https://api.drand.sh/52db9ba7.../public/{r}`
3. Compute `k mod N` for each receipt
4. Challenge every selected request
5. Verify proofs or publish deviation verdict

## Fallback

If drand is unavailable at proof checking time (network partition, service degradation), the auditor:
1. Waits up to 24 hours for beacon availability
2. If still unavailable, logs an incident and skips that round's proofs
3. Resumes from next available round

This does not weaken security: the beacon round was determined at `served_at` and cannot change; unavailability only delays verification.

## Related Specifications

- `receipt-log.md`: Receipt format with beacon_round field
- `audit-protocol.md`: Challenge protocol using selection rule
- `parameters.md`: Sampling rates N
- `facts-register.md`: F7-F13 (beacon parameters and escrow timeline)
