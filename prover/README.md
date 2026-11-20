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

## Private proof worker

Provision a private, local spool for the F4 commitment and a separate private state directory on the same filesystem. Initialize the spool with the pinned front end's commitment-specific `mark.txt`. The worker refuses a generic commitment mark. Give `SubmissionStore.submit` the durable job ID, nonce-free bytes from `build_statement` and the absolute deadline in Unix nanoseconds. `resume(job_id)` finishes a reserved submission after restart. A retry uses the original nonce and deadline.

Configure `ProverProcess.start` with the serving binary, a trusted operator build manifest, the secret-key directory, the published seed, a private home and temporary directory, spool and GPU index. The manifest binds schema version 1, `flashprove_revision`, `commitment_id` and `cp_prove_sha256` to the measured build. The runtime validates those inputs before starting with `-batch 1 -in-step 1`. Use its `stop` method to request shutdown at a batch boundary. If the wait times out, the stop request stays active. An abnormal exit places the spool on hold.

Use `ProofWorker.poll(job_id)` or `wait(job_id, poll_seconds=...)` with an operator-configured proof size limit. A pending job has no terminal result. The spool failure marker establishes only unavailability. The worker snapshots the first authenticated result in the private job ledger and requires the spool to be clear of holds on subsequent reads. Send a candidate's exact statement, four-byte token output and proof to the independent CPU verifier before issuing a verdict or disclosing proof bytes to a holder. Treat snapshots, statements, job bindings and raw spool files as private audit material under the [retention policy](../specs/retention.md).

Run `make test-proof-worker` for crash recovery, single-batch launch, shutdown, deadlines and collection. The [proof runtime RFC](../docs/rfcs/RFC-0006-proof-runtime.md#proposed-design) defines the protocol.

On x86-64 Linux with SHA extensions and G++ 13, set `FLASH_PROVE_DIR` to a local FlashProve checkout and run `make test-proof-spool-native`. It compiles the pinned CPU spool implementation, submits a real request, and collects both a tagged fixture payload and a failure marker. This checks file exchange and crash-safe replay.

## Scoring a receipted reply

On the isolated scorer host, call `ReferenceScorer.load(model_dir, manifest, rebuild_report=report)` from `prover.reference`. Supply the successful F4 commitment report and a separately protected operator manifest, both outside the model directory. The manifest declares `schema_version: 1`, `commitment_id`, `flashprove_revision` and a `sha256` object with entries for `integer_model.json`, `policy.txt`, `KL.bin`, `wsums.txt` and `fold.txt`. Take the fitted files from the compared rebuild and hash the operator's GGUF loader configuration. The pinned integer-model package checks the digests and tensor sums on load. The serving environment and its credentials are unnecessary for scoring.

Pass the authenticated prompt, original reply and signed token budget to `prover.scoring.assess`. The scorer feeds the pinned integer model the original 1,024-token input, including zero padding. Choice at position `P-1+d` predicts reply token `d`. On the first mismatch the new statement preserves the prompt and all preceding served tokens, ends with the expected token and zero-pads the remaining window. The verifier must reconstruct these bytes from the original receipt and verify a proof before reporting deviation. A match also needs a verified proof to establish conformance. [Proof runtime](../docs/rfcs/RFC-0006-proof-runtime.md#proposed-design)

An anonymous spool failure alone is unavailable. A privately reproduced range fault can excuse that failure only after all served predictions matched and the fault lies beyond the last evaluated position. This includes the final delivered token as an input, since the engine returned it without computing its successor. The scorer retains the position, condition and original statement digest for private audit. Run `make test-reference-scorer` to check prefix reconstruction, completion and range classification. [Model guarantee](../specs/guarantee.md)

To include the pinned package's real CPU vectors, set `VIG_FLASHPROVE_SOURCE` to its checkout at the configured revision and run `make test-reference-scorer REFERENCE_PYTHON=/path/to/reference/bin/python`. Install its integer-model 0.16.0 package, PyTorch 2.13.0 and NumPy 2.4.6 in a Python 3.13 reference environment. The vectors exercise the recorded greedy choices, a tie and a range exception on the small upstream model.
