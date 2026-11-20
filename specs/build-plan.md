# Build Plan and Milestones

## Overview

This document outlines the phased development plan from specification section 20. Each milestone has clear exit tests and effort estimates.

## Milestone Structure

- **M0**: Bring-up (2 weeks) - FlashProve build and basic proving
- **M1**: Gateway and log (2 weeks) - Service infrastructure with mocks
- **M2**: Auditor (2 weeks) - Real prover integration end-to-end
- **M3**: Red team (1 week) - Attack vectors R1-R19
- **M4**: Router path and soak (1-2 weeks) - Integration and stress testing

## M0: Bring-up

**Duration**: 2 weeks

**Goal**: Build FlashProve at the pin, serve and prove real-weight greedy replies.

### Content

1. Build FlashProve at commit `9e2bdd8ff5bf9c62f18263d7dac189b0400b260c`
2. Download Llama 4 Maverick GGUF weights (revision `41032e54`)
3. Run `examples/maverick/run.sh all`
4. Serve 16 greedy replies via integer-model plug-in
5. Prove all 16 at exact match
6. Verify all 16 with `cp_verify`
7. Engine start-up gates pass

### Exit Test

- [ ] `compare` prints "Your commitment is the published one"
- [ ] 16 greedy replies served by plug-in
- [ ] All 16 proved at exact match
- [ ] `cp_verify` YES on all 16
- [ ] Engine start-up gates pass (float64 check, tensor verification, canary)
- [ ] OQ1 measured: prefill time for prompts 200-768 tokens
- [ ] OQ5 measured: exact-match whole-reply proof time at 1 per batch

### Measurements

Record baselines:
- Engine prefill time (OQ1)
- Engine decode time per token
- Proof generation time at 1 per batch (OQ5)
- Verification time on development machine
- Start-up times (engine, prover)

### Not in Scope

- Gateway or log infrastructure
- Beacon sampling
- Multi-node deployment

## M1: Gateway and Log

**Duration**: 2 weeks (parallel to M0)

**Goal**: Build service infrastructure with mock engine and prover.

### Content

1. Gateway (GW): HTTP server, request validation, canonical rendering, tokenization
2. Renderer: 200 golden conversations against `transformers.apply_chat_template`
3. Receipt log (LG): Merkle tree with signed entry promises and STHs
4. Transcript escrow (ES): Hold transcripts until beacon
5. Sampler (SM): drand client, selection rule
6. Sealed pickup store (PK): Encrypted receipt recovery
7. Mock engine: Deterministic toy model (vocab 512)
8. Mock prover: Implements `Prover` interface

### Exit Test

- [ ] Unit tests green (spec section 19.1):
  - Render: 200 golden conversations match transformers
  - Commitment t, params_digest, pickup derivation: fixed vectors
  - Merkle log: RFC 9162 test vectors, inclusion and consistency
  - Selection: vectors with real quicknet rounds, nesting for N ∈ {1,20,1000}
  - Request file builder: byte-identical to `spool.py make-request`
- [ ] Service logic end-to-end with mock engine and mock prover
- [ ] Third party recomputes every selection from log and beacon

### Not in Scope

- Real prover integration
- Deviation proofs
- Red team testing

## M2: Auditor

**Duration**: 2 weeks

**Goal**: Real prover integration, challenge to verdict end-to-end.

### Content

1. Challenge service (CH): Intake, job state, deadlines
2. Prover worker (PW): Request files, spool, `cp_prove` at 1 per batch
3. Reference scorer (RX): Integer-model scoring for deviation path
4. Verification (VF): `cp_verify` plus section 11 checks
5. Verdict signer (VD): Sign and publish verdicts
6. Audit API (AU): Selections, verdicts, public files
7. Verifier kit (VK): CLI wrapping `cp_verify` with checks 1-7

### Exit Test

- [ ] Challenge a 3-day-old transcript end-to-end
- [ ] Verdict returns `CONFORMS`
- [ ] VK exit 0 on a separate machine (not the build machine)
- [ ] One deviation proof produced and checked:
  - Substitute model (e.g., Scout)
  - RX finds first divergence
  - Prove w* (expected token at divergence)
  - VD signs verdict `DEVIATES`
  - VK exit 21 (deviation proven)

### Not in Scope

- Router integration
- Stress testing
- Multi-prover nodes

## M3: Red Team

**Duration**: 1 week

**Goal**: Pass criterion on attack vectors R1-R19.

### Content

Red team harness (RT) implements attack vectors from spec section 19.2. Each attack: at least 20 trials, mixed with honest controls.

**Pass criterion**: 100% of attack trials end in stated result, 0 honest trials fail.

### Attack Vectors (R1-R19)

| ID | Attack | Expected Result |
|---|---|---|
| R1 | Engine serves stock vLLM Maverick FP8 | DEVIATES |
| R2 | Engine serves stock vLLM BF16 | DEVIATES |
| R3 | Engine serves llama.cpp on same GGUF | DEVIATES |
| R4 | Engine serves Llama 4 Scout | DEVIATES |
| R5 | Integer model with one perturbed weight tensor | DEVIATES |
| R6 | Engine forces token mid-reply (logit bias) | DEVIATES |
| R7 | Engine truncates with early end token | DEVIATES |
| R8 | Engine truncates without end token below max_tokens | INCOMPLETE |
| R9 | Gateway tampers: one reply token changed | DEVIATES |
| R10 | System prompt injected into x | VK exit 11, CH INVALID_BUNDLE |
| R11 | Chat template swapped | VK exit 11 |
| R12 | Reply text altered in transit | VK exit 12 |
| R13 | Forged or altered receipt | VK exit 10 |
| R14 | Proof replayed for another transcript | VK exit 20 |
| R15 | Proof under another commitment ID | VK exit 20 or 30 |
| R16 | Promised leaf left out of log | Monitor alert, omission evidence |
| R17 | Promise backdated past 30s tolerance | VK warning, monitor alert |
| R18 | Provider deviates only on long prompts | DEVIATES on every selected long prompt |
| R19 | Challenge flood | 429 after rate limits, queue bounded |

### Exit Test

- [ ] Pass criterion met: 100% of attacks caught, 0 false positives
- [ ] All 19 attack vectors tested
- [ ] Test results documented

### Not in Scope

- External penetration testing
- Sustained load testing

## M4: Router Path and Soak

**Duration**: 1-2 weeks

**Goal**: Router integration (Mode R) and 72-hour soak test at N=1.

### Content

1. **Mode R feed**: `GET /router/models` with quantization, context length, supported parameters
2. **Sealed pickup**: Recovery path when router drops `verification` field
3. **Streaming**: SSE with keep-alive comments, `verification` in last data event
4. **Soak test**: 72 hours at N=1 (prove everything) on synthetic chat traffic

### Exit Test

- [ ] Request through a generic router to verified endpoint
- [ ] Receipt recovered via sealed pickup by someone who did not build the system
- [ ] Challenged and verified by third party
- [ ] Soak test green:
  - Zero unexplained ERROR verdicts
  - Measured EXCUSED_RANGE rate
  - Measured unwarranted rate
  - Memory stable on all nodes (engine, prover, gateway, auditor)
  - No resource leaks over 72 hours

### Soak Test Traffic

Synthetic chat:
- Mixed prompt lengths (50 to 768 tokens)
- Mixed reply lengths (10 to 256 tokens)
- Distributed roles (system, user, assistant)
- Edge cases: empty system message, very long single message, multi-turn

### Not in Scope

- Specific router partner integration
- Production deployment
- High-availability configuration

## Dependencies and Risks

### External Dependencies

- **FlashProve**: Stable release at pinned commit
- **vLLM 0.29.0**: Deterministic version
- **drand quicknet**: Reliable beacon access
- **Model weights**: Public Maverick 4-bit GGUF files
- **Calibration set**: For commitment remake (WikiText-2, tokenizers)

### Known Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| FlashProve memory requirements exceed available | Medium | M0 measures actual requirements; 540 GB host memory budgeted |
| Commitment cannot be remade (OQ7) | Low | Published seed makes it reproducible; verify at M0 |
| Range failures common on chat traffic (OQ8) | Medium | Soak at M4 measures rate; padding retry if needed |
| Prover and engine disagree (OQ9) | Low | Canary at every start-up; cross-host check if available |

### Contingency Plans

- **M0 fails hardware requirements**: Source larger machine or split to 2 GPUs
- **Determinism issues**: Narrow to provably deterministic subset
- **Proof performance worse than expected**: Accept higher latency or reduce sampling rate
- **Beacon unavailable during soak**: Queue transcripts, measure recovery

## Dependencies and Blockers

### External Dependencies

- **FlashProve**: Requires stable FlashProve release
- **vLLM**: Requires deterministic vLLM version
- **drand**: Requires reliable drand beacon access
- **Model Weights**: Requires public model weights

### Known Risks

1. **FlashProve Integration**: May require modifications to FlashProve or vLLM
2. **Determinism**: Achieving perfect determinism may be challenging
3. **Proof Performance**: Proof generation may be slower than expected
4. **Sampling Fairness**: Beacon availability issues could bias sampling

### Contingency Plans

- **FlashProve Issues**: Consider alternative ZK proof systems
- **Determinism Issues**: Narrow scope to provably deterministic subset
- **Performance Issues**: Reduce sampling rate or optimize critical paths
- **Beacon Issues**: Implement fallback randomness sources with documented trust assumptions

## Success Metrics

### M0 Success

- Gateway serves requests correctly
- Receipts are cryptographically sound
- System is deterministic

### M1 Success

- Conformance proofs verify correctly
- Proof generation works end-to-end
- Verifier is standalone and correct

### M2 Success

- Sampling is unbiased and verifiable
- Deviation proofs work correctly
- Challenge mechanism functions

### M3 Success

- Red team suite passes
- System is production-ready
- Performance meets targets

### M4 Success

- Integration patterns documented
- Cost model validated
- Production deployment feasible

## Timeline Considerations

This is an exploration project. No calendar deadlines are specified.

### Milestone Ordering

- M0 and M1 are sequential (M1 requires M0)
- M2 requires M1
- M3 can partially overlap with M2
- M4 requires M3

### Parallel Work

Some tasks can proceed in parallel:
- Documentation can be written ahead of implementation
- Tests can be written before features
- Integration design can start before M3 completion

## Open Questions

See `open-questions.md` for unresolved design questions that may affect the build plan.

### M0 Questions

- What is the appropriate receipt signature scheme?
- How should the Merkle log handle concurrent appends?

### M1 Questions

- What FlashProve configuration achieves best proof performance?
- What execution traces are required for proof generation?

### M2 Questions

- What is the optimal sampling rate?
- How should the system handle beacon unavailability?

### M3 Questions

- What retention policy balances cost and auditability?
- What are acceptable performance targets?

### M4 Questions

- What integration patterns are most common?
- How should costs be allocated in router integrations?

## Related Specifications

- `guarantee.md`: Security properties to implement
- `architecture.md`: System design
- `redteam-suite.md`: Security testing requirements
- `capacity.md`: Performance and cost analysis
- `router-integration.md`: Integration patterns
