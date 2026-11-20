# RFC-0008: Verify holder evidence independently

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M2

## Summary

A standalone verifier reconstructs evidence on a holder-controlled machine.

## Motivation

Proof bytes alone do not establish rendering, historical inclusion or completeness. See [canonical specification](../spec/04-error-model.md#verification-errors).

## Goals

- Validate full conformance and deviation without model weights or serving credentials.

## Non-Goals

- Claim conformance from receipt-only debugging.

## Proposed Design

`verify(bundle: HolderBundle, descriptor: TrustedDescriptor, checkpoint: SignedTreeHead | None) -> VerificationResult`. Resolve trusted identities and profile assets, verify signature and recomputed leaf and transcript hashes, validate inclusion and any consistency checkpoint, independently render original input, compare text and enforce completion. Check beacon round assignment and deadline warnings. Locally reconstruct statement bytes and use the pinned verifier on the supplied proof; map outcome to documented exits. For deviation also compare the replacement against the served token. A secondary verifier consumes the same reconstructed statement and records discrepancies without replacing an error with success. Fixed data and inputs yield repeatable outcomes; proof bytes need not be identical.

## Alternatives Considered

Trust the auditor's signed verdict instead of checking evidence. That yields authentication but removes independent validation.

## Drawbacks

Clients retain transcript information and need authenticated public verification inputs.

## Migration / Rollout

Ship CLI and structured output with offline support for evidence bundled with signed checkpoints.

## Testing Strategy

Test original input mismatch, altered text, invalid proof, missing proof, wrong commitment and healthy remote-host CPU verification.

## Open Questions

Verifier owner records exact packaged runtime and supported platforms at M2.

## References

- [Canonical specification](../spec/04-error-model.md#verification-errors)
- [Source contract](../../specs/verifier-kit.md#exit-codes)
- [RFC index](README.md#accepted-decisions)
