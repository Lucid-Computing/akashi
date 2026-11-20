# Overview

## Release scope

The holder receives a receipt for a completed greedy reply, then checks evidence with public verifier inputs. Operators get detection and accountable failure for audited results under the assumptions in [security](06-security.md#trust-and-evidence). Receipt delivery alone asserts a log promise. Audit coverage comes from the [sampling rule](../../specs/sampling.md#selection-rule) and holder challenges. Report loss of coverage and proof availability explicitly.

Ship M0–M4 as a prototype according to [release gates](07-testing-strategy.md#release-gates). Support one integer model, text chat or raw IDs, one sequence, direct and router delivery, and one request per proof batch. Stochastic decoding, model multiplexing, cross-holder proof batches, tools, multimodal input and availability guarantees remain future scope. An alternate model runtime or config requires its own evidence and compatibility review.

## Evidence boundary

Engine integrity gates protect honest operation. Independent verification ties the signed record to exact token IDs, rendering, completeness and the committed function. Measurements describe the recorded environment. Treat real-chat padding failures, runtime portability and transparent router behavior as risks and collect evidence through the [open questions](../../specs/open-questions.md#summary).
