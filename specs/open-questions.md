# Open Technical Questions

## Overview

From specification section 21. These are unresolved technical questions to be closed during the build milestones.

## Questions (OQ1-OQ9)

### OQ1: Engine Prefill Time

**Question**: Prefill time of the plug-in for prompts of 200 to 768 tokens

**How to close**: Measure at M0

**Context**: Engine decode time is measured (0.60-0.62 s/token per F22), but prefill time for the integer-model plug-in is not. Need this to calculate accurate throughput.

**Measured on 2026-11-20.** The following prefill times are the vLLM counter deltas for one isolated request at each rendered prompt length on the primary H100. [M0 hardware report](../engine/evidence/maverick-m0.json)

| Prompt tokens | Prefill seconds |
| ---: | ---: |
| 200 | 4.003 |
| 256 | 4.135 |
| 320 | 4.290 |
| 384 | 4.493 |
| 448 | 3.964 |
| 512 | 4.351 |
| 640 | 4.695 |
| 768 | 5.410 |

### OQ2: Streaming Token IDs

**Question**: Does vLLM 0.29.0 return token IDs in streamed chunks with `return_token_ids`?

**How to close**: Test at M0

**Context**: If not, gateway must stream from a non-streaming engine call.

**Measured on 2026-11-20.** vLLM 0.29.0 returned incremental token IDs for the fixed `science-rain` request. Its 2 native SSE frames carried all 3 reply IDs in the same order as the independently proved non-streaming response. [M0 hardware report](../engine/evidence/maverick-m0.json)

### OQ3: Router Header Forwarding

**Question**: Does the router forward the `verification` field or `x-akashi-*` headers to clients?

**How to close**: Test at M4

**Context**: Sealed pickup covers both answers (headers forwarded or not).

**Status**: Open, to be tested at M4.

### OQ4: Router Message Rewriting

**Question**: Does the router rewrite `messages` (prompt compression or truncation), or send sampling defaults the client did not set?

**How to close**: Test at M4

**Context**: Rewriting breaks pickup lookup and holder's render check. Reject non-neutral values regardless.

**Status**: Open, to be tested at M4.

### OQ5: Whole-Reply Proof Time

**Question**: Exact-match whole-reply proof time at one per batch on real replies

**How to close**: Measure at M0

**Context**: FlashProve reports 58.8 s for next-token proofs (F23). Whole-reply exact match assumed similar but not measured.

**Measured on 2026-11-20.** The persistent H100 prover processed 16 exact whole replies, one request per batch. Dispatch to proof publication took 21.29 to 22.73 seconds with a median of 21.94 seconds. Launch to the first request took 82.13 seconds. Independent x86-64 CPU verification passed all 16 and took 20.81 to 25.25 seconds per proof. [M0 hardware report](../engine/evidence/maverick-m0.json)

### OQ6: Batch Privacy Under Published Seed

**Question**: Is batching other clients' requests safe under a published seed? If yes, 24 per batch cuts proving cost about 6 times.

**How to close**: Ask FlashProve maintainers

**Context**: At 1 per batch: 58.8 s per proof (F23). At 24 per batch: 9.2 s per proof (F23). Batching would reduce cost 6.4×, but requires proving requests under a published seed is safe for batch privacy.

**Status**: Open, requires upstream guidance.

### OQ7: Commitment Remake

**Question**: Remaking the published commitment needs the calibration set, built from WikiText-2 and the Llama 2 and Llama 4 tokenizers; do the ungated copies with matching SHA-256 suffice by hash?

**Status**: Resolved by the M0 hardware rebuild.

**Context**: The published commitment (C = `c7982f8a...1f46`) was made under a published seed (F4), so anyone with the weight files and calibration set can remake it and verify the ID matches.

**Calibration result**: Confirmed with the unmodified F4 FlashProve generator,
Python 3.13.15, NumPy 2.3.5, PyArrow 23.0.1 and tokenizers 0.22.2.
The generator accepted all three SHA-256 pins and exited 0.
The 128 draws hashed to `8cd63f617d474124a50ee052eae2fd0be603ea45f191ec8ccb4f443f676fb58c`.
An independent SHA-256 read of the 131,200-byte calibration file returned
`a2ce04bd55b1b6fa2b9148744e087f5a2a484c1b3d525ea9fb2fc1ab8c6c2c02`, the published digest.
[Pinned generator and reference digests](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/scales/make_calibration_set.py#L80-L122)

**Hardware result.** The 2026-11-20 H100 rebuild used that calibration digest
and all five checksummed GGUF shards. Its generated commitment matched the full
F4 identifier. The verification key and first verification leaf also matched the
pinned digests. [Rebuild report](../engine/evidence/maverick-commitment.json)

**Inputs used**, in generator argument order:

1. [WikiText-2 raw training split](https://huggingface.co/datasets/Salesforce/wikitext/blob/b08601e04326c79dfdd32d625aee71d232d685c3/wikitext-2-raw-v1/train-00000-of-00001.parquet)
2. [Hugging Face Tokenizers' public Llama 2 test fixture](https://huggingface.co/datasets/hf-internal-testing/tokenizers-test-data/blob/e20ac5914f5ada06874e4f9d45e49b31a049904e/llama-2.json)
3. [F37 Llama 4 tokenizer](https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/blob/86c5ecb6f2fbddf604c60120125fb202e09f2556/tokenizer.json)

### OQ8: Range Failure Rate and Padding

**Question**: Range-failure rate on chat traffic, and whether a padding retry (`params_digest` v2) is needed

**How to close**: Soak data at M4

**Context**: The prover's behavior on a request at which a range condition fails is untested upstream (F35). V1 commits padding 0 in `params_digest`. If failures occur in padding, auditor may retry with padding token 200018 (model's pad token per F37), which needs `params_digest` v2.

**Status**: Open, measure during 72-hour soak at M4.

### OQ9: Prover-Engine Agreement

**Question**: Do the plug-in's greedy choices agree with the prover across driver and library versions?

**How to close**: Canary at every start-up; cross-host check at M0 if two hosts exist

**Context**: FlashProve conditions exactness on the float64 check (F20) and reports agreement from H100 runs only (F35). Need to verify that engine and prover always agree on greedy choices.

**Measured on 2026-11-20.** The primary NVIDIA H100 80GB HBM3 matched all three independently F4-verified golden replies. The separate NVIDIA H100 NVL refused startup twice. Its diagnostic replay disagreed with all three primary replies for the same prompts and budgets. The first canary also returned a different reply when repeated on the same healthy NVL process after its startup refusal. The cause remains unknown. The NVL configuration remains ineligible for serving or soak until a fresh startup passes its gates. The report records each host’s driver and runtime versions. These results cover the two measured configurations. [M0 hardware report](../engine/evidence/maverick-m0.json)

## Summary

All nine questions (OQ1-OQ9) are from specification section 21. They will be closed during the build milestones:

| Question | Closes At | Method |
|----------|-----------|--------|
| OQ1: Prefill time | M0 | Measured eight prompt lengths on the primary H100. |
| OQ2: Streaming token IDs | M0 | Native SSE IDs matched the proved reply. |
| OQ3: Router header forwarding | M4 | Test |
| OQ4: Router message rewriting | M4 | Test |
| OQ5: Whole-reply proof time | M0 | Timed and independently verified 16 singleton proofs. |
| OQ6: Batch privacy | Before M2 | Ask FlashProve maintainers |
| OQ7: Commitment remake | M0 | Resolved. Calibration and hardware rebuild match F4. |
| OQ8: Range failure rate | M4 | Soak data |
| OQ9: Prover-engine agreement | M0+ | The secondary refused startup twice, differed on all three primary cases and changed on its own first-case replay. Recheck at each startup. |

## Related Documentation

- `build-plan.md`: M0-M4 milestones that close these questions
- `facts-register.md`: Verified facts F1-F40
- `capacity.md`: Performance measurements
- `parameters.md`: System parameters
