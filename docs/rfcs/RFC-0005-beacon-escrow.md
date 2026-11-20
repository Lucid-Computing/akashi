# RFC-0005: Fix future sampling and expire escrow

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M1

## Summary

Each promise fixes a future round that monitors can verify independently.

## Motivation

Choosing the current round or changing rounds on retry invalidates the selection assumption. See [canonical specification](../spec/06-security.md#trust-and-evidence).

## Goals

- Reproduce every published selection and record loss of coverage.

## Non-Goals

- Replace unavailable beacon values with a local generator.

## Proposed Design

`round_for(served_at) -> uint64` returns the first round strictly after served_at + MMD + beacon margin, using time(r)=genesis+(r−1)×period. Stamp before promise and exclude a delivery whose round has opened by terminal release. Verify the pinned chain identity, public key and round signature before hashing raw signature bytes. Preserve the specified first-u32 modulo rule and nested selections; the exact ideal-uniform modulo probability is ceil(2^32/N)/2^32. Treat N=1000 as a shadow computation over the same logged corpus and promote N=1 for soak under an advertised config epoch. Transfer selected private material before escrow expiry, erase unselected material immediately, erase all remaining private escrow at the hard cap and publish a gap. Persist checkpoints and transfer jobs idempotently by leaf. Never replace the fixed round.

## Alternatives Considered

Wait indefinitely for beacon data. It preserves the selected round but violates the escrow bound.

## Drawbacks

A beacon outage can permanently remove sampled transcript evidence.

## Migration / Rollout

Start with fixed and real round fixtures; enable live audit only after independent recomputation.

## Testing Strategy

Test clock boundaries, invalid signatures, restart after transfer, N nesting, duplicate delivery and outage crossing expiry.

## Open Questions

Sampler owner verifies pinned chain key and signature encoding in M1 fixtures.

## References

- [Canonical specification](../spec/06-security.md#trust-and-evidence)
- [Source contract](../../specs/sampling.md#selection-rule)
- [RFC index](README.md#accepted-decisions)
