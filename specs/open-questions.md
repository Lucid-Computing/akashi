# Open Technical Questions

## Overview

From specification section 21. These are unresolved technical questions to be closed during the build milestones.

## Questions (OQ1-OQ9)

### OQ1: Engine Prefill Time

**Question**: Prefill time of the plug-in for prompts of 200 to 768 tokens

**How to close**: Measure at M0

**Context**: Engine decode time is measured (0.60-0.62 s/token per F22), but prefill time for the integer-model plug-in is not. Need this to calculate accurate throughput.

**Status**: Open, to be measured at M0.

### OQ2: Streaming Token IDs

**Question**: Does vLLM 0.29.0 return token IDs in streamed chunks with `return_token_ids`?

**How to close**: Test at M0

**Context**: If not, gateway must stream from a non-streaming engine call.

**Status**: Open, to be tested at M0.

### OQ3: Router Header Forwarding

**Question**: Does the router forward the `verification` field or `x-vig-*` headers to clients?

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

**Status**: Open, to be measured at M0.

### OQ6: Batch Privacy Under Published Seed

**Question**: Is batching other clients' requests safe under a published seed? If yes, 24 per batch cuts proving cost about 6 times.

**How to close**: Ask FlashProve maintainers

**Context**: At 1 per batch: 58.8 s per proof (F23). At 24 per batch: 9.2 s per proof (F23). Batching would reduce cost 6.4×, but requires proving requests under a published seed is safe for batch privacy.

**Status**: Open, requires upstream guidance.

### OQ7: Commitment Remake

**Question**: Remaking the published commitment needs the calibration set, built from WikiText-2 and the Llama 2 and Llama 4 tokenizers; do the ungated copies with matching SHA-256 suffice by hash?

**How to close**: Confirm at M0

**Context**: The published commitment (C = `c7982f8a...1f46`) was made under a published seed (F4), so anyone with the weight files and calibration set can remake it and verify the ID matches.

**Status**: Open, confirm at M0 that ungated dataset copies work.

### OQ8: Range Failure Rate and Padding

**Question**: Range-failure rate on chat traffic, and whether a padding retry (`params_digest` v2) is needed

**How to close**: Soak data at M4

**Context**: The prover's behavior on a request at which a range condition fails is untested upstream (F35). V1 commits padding 0 in `params_digest`. If failures occur in padding, auditor may retry with padding token 200018 (model's pad token per F37), which needs `params_digest` v2.

**Status**: Open, measure during 72-hour soak at M4.

### OQ9: Prover-Engine Agreement

**Question**: Do the plug-in's greedy choices agree with the prover across driver and library versions?

**How to close**: Canary at every start-up; cross-host check at M0 if two hosts exist

**Context**: FlashProve conditions exactness on the float64 check (F20) and reports agreement from H100 runs only (F35). Need to verify that engine and prover always agree on greedy choices.

**Status**: Open, verify with canary (three fixed prompts, golden token IDs) at engine start-up.

## Summary

All nine questions (OQ1-OQ9) are from specification section 21. They will be closed during the build milestones:

| Question | Closes At | Method |
|----------|-----------|--------|
| OQ1: Prefill time | M0 | Measure |
| OQ2: Streaming token IDs | M0 | Test |
| OQ3: Router header forwarding | M4 | Test |
| OQ4: Router message rewriting | M4 | Test |
| OQ5: Whole-reply proof time | M0 | Measure |
| OQ6: Batch privacy | Before M2 | Ask FlashProve maintainers |
| OQ7: Commitment remake | M0 | Confirm |
| OQ8: Range failure rate | M4 | Soak data |
| OQ9: Prover-engine agreement | M0+ | Canary at every start-up |

## Related Documentation

- `build-plan.md`: M0-M4 milestones that close these questions
- `facts-register.md`: Verified facts F1-F40
- `capacity.md`: Performance measurements
- `parameters.md`: System parameters
