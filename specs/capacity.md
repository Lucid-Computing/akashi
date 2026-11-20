# Capacity and Cost Model

From specification section 14.

## Performance Measurements

All measurements from FlashProve benchmarks (facts register):

| Metric | Value | Source |
|---|---|---|
| Decode speed | 0.60 to 0.62 s per token | F22 |
| Start-up time | 22 to 25 minutes with tensor verification | F22 |
| Host memory | ≥ 238 GB free | F22 |
| GPU memory peak | 36 GB | F22 |
| Prover (1 per batch) | 58.8 s per request | F23 |
| Prover (24 per batch) | 9.2 s per request | F23 |
| Prover cost | 71.4 to 93.0× stock vLLM prefill GPU time | F23 |
| Verification (single thread) | About 21 s | F26 |
| Verification (shared VM) | 36.2 to 44.0 s | F26 |
| Proof size | 18.78 MB average | F25 |

## Notes (non-normative)

Derived throughput calculation for P=256, R=256:
- Decode: ~156 s per request (256 × 0.61 s)
- Upper bound: ~553 replies/day (ignoring prefill)
- Actual throughput depends on unmeasured prefill time (OQ1)

V1 configuration: 1 request per batch (F28 advises this under published seed).

## Related Specifications

- `facts-register.md`: F22-F27 (all performance measurements)
- `open-questions.md`: OQ1 (prefill time), OQ6 (batched proving)
- `parameters.md`: T=1024, max_tokens_cap=256
