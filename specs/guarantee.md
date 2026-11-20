# Security Guarantee and Threat Model

## Overview

The verified inference gateway provides a cryptographic guarantee that served LLM replies are exactly what the committed integer model would produce under greedy decoding, or explicitly identifies where they deviate.

## The Core Guarantee

Every reply that carries a receipt is bound, at the moment it is delivered, into a public append-only log. A public rule over that log and a public randomness beacon, fixed after delivery, selects a fraction r of replies for audit. For each selected reply, and for any reply whose holder challenges it within the retention window, the auditor produces either:

- **Conformance proof**: The reply's tokens are, at every position, the committed integer model's greedy choice given the prompt's tokens
- **Deviation proof**: At a stated position the committed model chooses a different token from the one served

Both are checkable on a CPU, without the weights, by anyone who holds the transcript.

## The Proof Statement

Fix the commitment ID C (32 bytes), the window T = 1,024, the end-token set E and a padding token z. For a prompt of token IDs x = (x_0 … x_{P-1}) and a reply y = (y_0 … y_{R-1}) with P + R ≤ T, let w = x ‖ y ‖ z^(T-P-R). The conformance statement is:

```
for every position t in [P-1, P+R-2]:  w_{t+1} = argmax_lowest-id( M_C(w_0 … w_t) )
```

where M_C is the integer model defined by FlashProve's `docs/model.md` at the weights that C binds. The proof also needs every range condition of M_C to hold at all T positions of w, padding included.

### Additional Checks

Statements the system adds around the proof, checked by the verifier kit, not by `cp_verify`:

| Check | Why the proof does not cover it |
|---|---|
| x is the canonical rendering of the delivered `messages` under the pinned render profile | the prover and `cp_verify` know no tokenizer or chat template |
| decode(y) equals the delivered text | nothing in the proof relates token IDs to text |
| the reply is complete: y_{R-1} ∈ E and no earlier y_i ∈ E, or R = max_tokens | `cp_verify` knows no end tokens; a reply cut short verifies as a shorter reply |
| the transcript is the one logged at delivery | the proof binds tokens to C, not to a time, an endpoint or a customer |

## What Is Proven

### Soundness and Strength

| Property | Strength | Basis |
|---|---|---|
| Conformance proof for false statement accepted | Lean verifier: at most about q/2^124 + 2^-101 after q hash queries, random-oracle model, exact match, full size, one proof (N proofs: N times the error). `cp_verify`, the program users run, is tested against it, not proved | Facts register F12, F13 |
| C binds one set of weights | Protocol-level binding proved for a Lean model of the committer, not for `cp_commit` itself | Fact F12 |
| C is the model advertised | The published Maverick commitment can be remade by anyone with the weight files and calibration set; equal IDs show the commitment repeats on that kind of machine, not that it is right | Facts F4, F5, F6 |
| Unaudited replies are honest | Statistical only: deterrence from post-hoc sampling and the open challenge channel | Design property |

## Residuals and Limitations

Residuals the system does not close, stated in every published verdict:

1. **Integer model, not the 16-bit model**: Its top token differs from the 16-bit model's at 6.81% of positions (F33). The claim is about the integer model on one third-party 4-bit conversion (F3), not about Meta's FP8 or BF16 release.

2. **Which machine served the reply** is not covered. The proof is about the function computed, not the hardware.

3. **Data handling** (retention, leakage, training use) by any party is not covered.

4. **A `cp_verify` bug** could turn a rejection into an acceptance (F12). Mitigation: second verifier using Lean-verified verifier on sampled verdicts.

### Explicitly Out of Scope

- **Sampled decoding**: Temperature above 0 not supported
- **Batching**: One sequence at a time only
- **Context above 1,024 tokens**: Prompt plus reply limited to window size
- **Tool calls, images, structured output**: Text-only chat and raw token completions
- **`stop` strings, `logit_bias`, logprobs**: Not supported by proof system
- **Other models**: V1 scoped to single model
- **High availability**: No SLA guarantees in prototype

## Roles and Trust

### Roles

| Role | Runs | Holds | Production owner |
|---|---|---|---|
| **Provider** | the engine (vLLM + integer-model plug-in) | model files | the inference provider |
| **Gateway operator** | gateway, receipt log, escrow, sampler, pickup store | log and receipt signing keys; transcripts for at most W_escrow | the router |
| **Auditor** | prover node, challenge service, verdict signer, audit API | auditor signing key; selected transcripts and proofs | the router or a neutral party |
| **Holder** | verifier kit | own transcripts and receipts | the end user, or anyone the user gives them to |

The provider runs only the engine. It receives token IDs and returns token IDs. It never sees `messages`, never renders, never decodes text for the client and never signs anything. This removes the provider's ability to inject a system prompt or rewrite text.

## Threat Model

### Adversaries

| Adversary | Capabilities | Goal |
|---|---|---|
| **A1 Provider** | Full control of the engine host: any model, any code, per-request choice of what to serve; knows the sampling rule; does not know a future beacon value | Serve a cheaper or different model on some or all requests without a failed audit |
| **A2 Gateway operator** | Controls the log and receipts | Hide a provider's failure (drop or reorder entries, backdate, equivocate), or frame a provider |
| **A3 Auditor** | Controls the prover and verdicts | Pass a deviating reply, or fail an honest one |
| **A4 Client or third party** | Arbitrary requests, arbitrary challenges | Forge receipts, exhaust capacity, learn other users' transcripts, frame a provider |
| **A5 Network** | On-path between router, gateway and engine | Tamper with requests or replies |

### Trust Assumptions

The system requires trust in:

1. **Cryptographic Primitives**: SHA-256, Merkle trees, ZK proof systems are secure
2. **FlashProve Soundness**: The ZK proof system is sound and does not have critical bugs
3. **drand Beacon**: The randomness beacon is live and unbiased
4. **Client Verification**: Clients actually check receipts and proofs
5. **Specification Adherence**: Implementation matches specifications

The system does **not** require trust in:
- The inference serving operator
- The gateway operator
- Model quality or training
- Network intermediaries

## Detection Probability

### Sampling Arithmetic

For a sampling rate of 1/N:
- **Single trial detection**: 1/N
- **k trials detection**: 1 - (1 - 1/N)^k
- **Sustained deviation**: Detected with high probability within 1000N requests

### Example Detection Rates

For N = 1000 (default sampling rate):

| Deviation Frequency | Detection in 100 Trials | Detection in 1000 Trials |
|---------------------|--------------------------|---------------------------|
| 1% (1/100) | >63% | >99.99% |
| 10% (1/10) | >99.99% | >100% (certain) |
| 100% (all) | >100% (certain) | >100% (certain) |

**Interpretation**: Even rare deviations are caught quickly. Systematic deviations are detected with near certainty.

### Challenge Mechanism

In addition to random sampling:
- Any receipt holder can challenge a specific reply
- Challenges trigger immediate proof generation
- Challenge proofs have the same properties as sampled proofs

This provides deterministic detection for suspicious replies without waiting for sampling.

## Security Properties

### Soundness

**Property**: A valid conformance proof MUST only verify when the reply is correct.

**Rationale**: Soundness is the foundational security property. If an adversary can create valid proofs for incorrect outputs, the system provides no security.

**Verification**: Red team suite must attempt to generate false proofs.

### Completeness

**Property**: Correct executions MUST produce valid proofs.

**Rationale**: If correct executions cannot be proven, legitimate operators cannot participate.

**Verification**: All test cases for correct inference must produce valid proofs.

### Tamper Evidence

**Property**: Any modification to receipts or the Merkle log MUST be detectable.

**Rationale**: Historical receipts must remain trustworthy for auditing.

**Verification**: Red team suite must attempt to modify receipts and logs undetectably.

### Determinism

**Property**: Identical inputs MUST produce identical outputs and proofs.

**Rationale**: Non-determinism breaks verifiability.

**Verification**: Repeated executions must produce identical results.

### Sampling Fairness

**Property**: Audit selection MUST be unbiasable.

**Rationale**: If the prover can avoid audits, deviations go undetected.

**Verification**: Beacon randomness must be public and verifiable before use.

## Compliance with Standards

- **RFC 2119**: Keyword usage for requirements
- **NIST Standards**: Cryptographic primitives follow NIST recommendations
- **Academic Standards**: Threat model follows standard definitions from the ZK proof literature

## Assumptions Register

| Assumption | Type | Impact if Violated |
|------------|------|---------------------|
| SHA-256 collision resistance | Cryptographic | Receipt binding breaks |
| Merkle tree soundness | Cryptographic | Log integrity breaks |
| FlashProve soundness | Cryptographic | Proof system breaks |
| drand beacon fairness | Distributed systems | Sampling bias possible |
| IEEE 754 determinism | Hardware | Reproducibility breaks |
| Model weight integrity | Operational | Wrong model proven correctly |
| Greedy decoding determinism | ML systems | Proof verification fails |

## Future Considerations

Potential future extensions (not currently in scope):

1. **Sampling-Based Decoding**: Proving correctness of stochastic outputs
2. **Batched Inference**: Proving batch integrity
3. **Multi-Model Support**: Extending to multiple models
4. **Privacy-Preserving Proofs**: Zero-knowledge proofs that hide prompts
5. **Continuous Auditing**: Real-time proof streaming

These require significant research and are documented in `open-questions.md`.

### Security Properties (Targets)

- **S1 Binding at delivery**: A receipt commits to (C, render profile, params, x, y, endpoint, time) before any selection randomness exists.

- **S2 Unpredictable selection**: At serving time no party can predict whether a reply will be selected with advantage beyond r.

- **S3 Non-omission**: A receipted entry missing from the log, or a log that shows different histories to different parties, is detectable from receipts and signed tree heads.

- **S4 Conformance soundness**: A deviating reply gets no accepted conformance proof (bounded by F12).

- **S5 Accountable failure**: A provider is marked failed only on evidence a third party can check: a deviation proof, a receipted transcript that fails the completeness check, or (rarely) a range failure inside the served positions that anyone can reproduce on the public weights.

- **S6 Transcript confidentiality**: The public log and audit API reveal no prompt or reply content; transcripts reach only the gateway (briefly), the auditor (if selected or challenged) and the holder.

- **S7 Availability**: Out of scope beyond rate limits and queue bounds.

### Explicit Non-Properties

A colluding gateway operator and provider (A1 + A2) can serve and log consistently and suppress audits; S3 makes this detectable only to holders who check their receipts and to log monitors. A colluding auditor (A3) can withhold verdicts; S5 and published proofs make false verdicts detectable, not impossible.

## Related Specifications

- `architecture.md`: System design implementing these guarantees
- `sampling.md`: Sampling protocol details
- `audit-protocol.md`: Proof generation and verification
- `redteam-suite.md`: Testing security properties
- `facts-register.md`: Verified facts supporting these claims
