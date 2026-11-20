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

## Exact-match request bytes

`prover.request.build_statement(prompt, reply)` returns the verifier request
for one whole reply. Both inputs contain token IDs. For prompt length P and reply length R, the verifier
checks the next-token prediction at each position in [P−1, P+R−1).
`build_spool_request(prompt, reply)` appends a fresh 32-byte nonce for the
private spool. Keep submitted bytes private. Both encoders use the 1,024-token
window and zero padding specified by F7 and F8. [Proof runtime contract](../docs/rfcs/RFC-0006-proof-runtime.md#proposed-design)

Run `make test-proof-request` from the repository root to check the
encoding against pinned FlashProve vectors.

## Related Specifications

- `specs/open-questions.md`: OQ6 (batched proving safety)

## CPU proof-worker fixture

Use the adapter in `prover.mock` to exercise M1 proof-worker outcomes with the
nonce-free statement bytes from the request encoder. Its success result
identifies fixture evidence. Rejection and timeout give callers distinct
failure paths. Run `make test-mock-prover` at the repository root.
[Testing strategy](../docs/spec/07-testing-strategy.md#validation-layers)
