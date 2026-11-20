# RFC-0007: Authenticate challenges and publish verdict evidence

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M2

## Summary

The auditor binds validated challenges and sampled jobs to signed, redacted evidence.

## Motivation

Auditors can run out of capacity or withhold files; callers need distinguishable outcomes and secure recovery. See [canonical specification](../spec/04-error-model.md#failure-contract).

## Goals

- Enforce challenge windows and rate limits before GPU admission.

## Non-Goals

- Use public proof downloads or publish unverifiable deviation as established.

## Proposed Design

`submit(holder: HolderKey, bundle: HolderBundle, leaf_index: int) -> ChallengeHandle`; `job(id, capability) -> ChallengeState`. Bind challenge identity and capabilities separately. Verify receipt, inclusion, original input, resolved budget, decoded text and completeness before dispatch. Incomplete otherwise-valid bundles can receive INCOMPLETE with signed evidence and no proof attempt. Holder challenges are accepted within W_challenge; sampled deadlines use D_sampled and on-demand timing uses the D_demand target. Enforce per-holder and per-transcript limits atomically, deduplicate work by transcript and proof statement while authorizing each reader independently, and persist pending → verifying → completed transitions. Compare generated proof before signing. Sign `"vig/verdict/1" || JCS(verdict)` with Ed25519. The signed object contains version, challenge UUID, transcript commitment, outcome, bounded reason, UTC verification time, auditor key ID and optional SHA-256 proof and statement digests; public responses add the signature and omit transcript content, tokens and capabilities. Serve private artifacts only after authorization and expire together.

## Alternatives Considered

Return a synchronous proof in the intake call. This ties GPU work to network lifetime and makes retries and recovery ambiguous.

## Drawbacks

Job persistence and private artifact retention increase operator burden.

## Migration / Rollout

Publish schema vig-verdict/1 with status vocabulary from the data model; use audited test fixtures before real jobs.

## Testing Strategy

Verify expired and three-day challenges, both rate limits, capability separation, reruns after crash and distinction between rejection, deviation and missing proof.

## Open Questions

Auditor owner records deployment-specific admission sizing at M2 before exposing challenge intake.

## References

- [Canonical specification](../spec/04-error-model.md#failure-contract)
- [Source contract](../../specs/audit-protocol.md#challenge-submission)
- [RFC index](README.md#accepted-decisions)
