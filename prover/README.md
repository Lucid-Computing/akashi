# Prover

FlashProve ZK proof generation for conformance and deviation proofs.

## Purpose

The prover generates zero-knowledge proofs that bind model outputs to the committed integer model, without revealing weights.

## Specifications

- `specs/audit-protocol.md`: Proof generation protocol
- `specs/capacity.md`: Performance targets
- `specs/facts-register.md`: F23, F25, F32 (performance and soundness)

## Performance

From F23:

| Configuration | Time per Request |
|---|---|
| 1 per batch | 58.8 s |
| 24 per batch | 9.2 s |

Cost: 71.4 to 93.0× stock vLLM prefill GPU time (F23)

Proof size: 18.78 MB average (F25)

## Key Invariants

From spec § 10:

1. **V1 configuration**: 1 request per batch (F28 advises this under published seed)
2. **Soundness**: q/2^124 + 2^-101 after q hash queries (F32, Lean-verified)

## Testing

```bash
cd prover/
pytest tests/ -v
```

## Related Specifications

- `specs/open-questions.md`: OQ6 (batched proving safety)
