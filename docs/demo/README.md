# One chat, one proof

On 23 November 2026, a holder sent a single greedy chat through an opaque forwarding router to the gateway. The gateway used the [published FlashProve Maverick commitment](../../specs/facts-register.md#facts-register). Inference and proving occupied two Lucid H100s. The holder ran on a separate Linux x86-64 host under the same administration.

> A basket holds seven apples. I add five more. How many apples are in the basket? Answer with just the number.

The exact reply was `12<|eot|>`. The suffix is the decoded end-of-turn token. The holder saved its original input and a trusted signed checkpoint, recovered the sealed receipt after the router stripped the verification field, checked the signed log history, and challenged the reply. The auditor checked the proof and signed its verdict. The holder matched the downloaded proof to the signed evidence and reconstructed the public statement from its original input and the delivered reply. [Holder verification contract](../../docs/rfcs/RFC-0008-holder-verification.md) · [Sealed pickup contract](../../docs/rfcs/RFC-0010-router-pickup.md)

## The offline check

The working directory paths below are relative to the captured replay. Both invocations used the installed `vig-verify` wheel (the verifier's name before the project became Akashi; it now ships as `akashi-verify`), the same descriptor and checkpoint, and the same public statement. The verification processes saw loopback only, with no GPU or model weights. The only change to the second bundle was one bit of the decoded proof.

```sh
.venv/bin/vig verify bundle/holder.json --descriptor bundle/descriptor.json \
  --checkpoint bundle/checkpoint.json --assets assets --runtime bundle/runtime.json \
  --observed-at 2026-11-23T10:19:53.699044+00:00
```

```json
{"exit_code": 0, "outcome": "CONFORMS", "schema_version": 1, "warnings": []}
```

Repeating the command with `bundle/control.json` returned exit 20.

```json
{"exit_code": 20, "outcome": "PROOF_REJECTED", "schema_version": 1, "warnings": []}
```

[Recorded command and stdout data](evidence.json) · [Install and run the verifier against your own evidence](../../verifier/README.md)

## Measurements

| Boundary | Elapsed |
| --- | ---: |
| Chat POST to complete reply | 3.865 s |
| Chat POST to first full proof response | 52.634 s |
| Offline CLI, original proof | 24.123 s |
| Offline CLI, changed proof | 16.614 s |
| Chat POST to original offline CLI exit | 157.886 s |

The proof contained **18,771,124 bytes**. The HTTP proof response body contained **25,036,424 bytes**, including the enclosing JSON. The CLI intervals include process startup and local file reading. The elapsed times in this table came from the holder host’s monotonic clock.

Eight source-holder checks returned `NO_VERDICT` because the staged copy omitted its hardware-check module. The operator restored the pinned module and its package initializer. The holder made nine read-only proof fetches against the same challenge, then completed its source-level check before running the two installed CLI processes. The 157.886 seconds includes that recovery. The provider produced one signed leaf and one native proof. Treat all timings as observations of this single take. [Measurement record](../../specs/facts-register.md#recorded-gateway-demo) · [Machine-readable evidence](evidence.json)

## Reproduce what you can inspect

- Run [the CPU router quickstart](../../README.md#try-it) to exercise signed receipts and sealed pickup with a synthetic engine.
- Run [the package check](../../CONTRIBUTING.md#build-and-check-the-verifier-wheel) to install the development wheel and check the signed fixture. The native verifier’s separate clean-install report includes a real whole-reply proof and a changed-proof control. [Native clean-install report](../../distribution/verifier/evidence/native-clean-install.json)
- Follow [the real engine and prover setup](../../engine/README.md) for another live deployment. Run-specific holder inputs and original proof bytes remain in private custody. [Exact provider source](https://github.com/Lucid-Computing/akashi/commit/6b490814375a59ca8d8f0c46d5b460aae8b8df54) · [Exact holder source](https://github.com/Lucid-Computing/akashi/commit/64f2fcb95818bdcbac014bc90f6f39aeb36e3547)
- Use [the release gate](../../release/README.md) to qualify a candidate. The longer historical challenge and continuous soak have their own requirements.

A separate clean offline install replayed the same archived proof and reproduced both exits. The proof establishes greedy token conformance for this transcript and the committed model. [Security guarantee](../../specs/guarantee.md) · [Release testing strategy](../spec/07-testing-strategy.md#release-gates)
