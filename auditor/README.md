# Auditor

Challenge orchestration and proof verification service.

## Purpose

The auditor accepts challenges from clients, runs automated sampling using drand beacon, requests proofs from the prover, verifies them with `cp_verify`, and publishes signed verdicts.

## Specifications

- `specs/audit-protocol.md`: Complete challenge and proof protocol
- `specs/sampling.md`: Beacon selection and escrow timeline

## Key Invariants

From spec § 10:

1. **Receipt verification first**: Verify log signature and recompute commitment before requesting proof
2. **Holder challenge window**: Accept independently verified holder evidence within 30 days of delivery
3. **Rate limits**: 10/hour per holder key, 3/day per transcript
4. **Verdict signature**: Ed25519 over `"vig/verdict/1" || JCS(verdict)`, as specified in [RFC-0007](../docs/rfcs/RFC-0007-challenge-lifecycle.md#proposed-design)

## Holder challenge intake

Send `POST /audit/v1/challenges` with an authenticated holder bearer key and JSON containing `bundle` and its unsigned integer `leaf_index`. The bundle carries the caller's original input, resolved budget and displayed text, the gateway's private verification object, the signed log head and its inclusion response. Keep the returned challenge ID and private capability together. Separate submissions have separate capabilities even when their proof work is shared. [Holder bundle](../docs/spec/03-data-model.md#wire-types) · [Challenge API](../docs/spec/02-public-api.md#interfaces)

The auditor independently verifies the signed delivery and original transcript before accepting a challenge. A three-day-old receipt remains eligible when the holder supplies this evidence. The 30-day window starts at delivery. Each rolling hour allows ten challenges per authenticated holder. Each rolling day allows three per transcript across holders. A limited response includes Retry-After. The intake transaction commits the encrypted work item, hashed capability and both quota charges together. An otherwise verified incomplete reply is classified for the auditor without requesting a proof. [Parameters](../specs/parameters.md#rate-limits) · [Lifecycle](../docs/rfcs/RFC-0007-challenge-lifecycle.md#proposed-design)

Construct `ChallengeIntake` with an owner-only SQLite directory, trusted descriptor, F37 asset directory, the auditor's encryption public key and a private key for holder tags. Pass its `submit` method, an authenticated holder lookup and the deployment body limit to `ChallengeApp`. Run `make test-challenge-intake` for HTTP, independent receipt validation, quota races, restart and encrypted persistence.

## Automated Sampling

The receipt fixes the first quicknet round strictly after delivery time plus
MMD and the beacon margin. Verify the round's signature with the pinned
quicknet key before computing the selection word from the transcript
commitment, the round number and the raw signature. Live and shadow rates use
that same word. [Beacon and escrow contract](../docs/rfcs/RFC-0005-beacon-escrow.md#proposed-design)

Run `make test-beacon` from the repository root. The tests include an authentic
historical quicknet round and can run offline once the locked dependencies are
installed. [Pinned quicknet chain information](https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info)

## Related Specifications

- `specs/verifier-kit.md`: Exit codes and verification procedure
- `specs/facts-register.md`: F23, F26, F30-F33 (performance and soundness)
