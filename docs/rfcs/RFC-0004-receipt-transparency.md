# RFC-0004: Bind delivery to durable signed log history

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M1

## Summary

A framed commitment binds the transcript, while a public log binds its delivery metadata.

## Motivation

The legacy concatenation leaves token boundaries and delivery fields ambiguous. See [canonical specification](../spec/03-data-model.md#binding-invariants).

## Goals

- Make proof and append behavior interoperable across concurrent writers and readers.

## Non-Goals

- Publish transcripts or establish log consistency without independent observation.

## Proposed Design

`append(preimage: PublicLeafPreimage) -> Promise`; `head() -> SignedTreeHead`; `path(index: int, size: int) -> tuple[Digest, ...]`. Use the canonical preimages and legacy signature domains. Atomically persist immutable leaf index, request identity and associated signed head before returning the promise. Repeated identical appends return the original promise; a reused identity with different bytes fails. Sign head checkpoints both after append and at the configured cadence. Preserve the explicit sizes with each path; readers compare heads by identity, size, signature and root. Use the domain-separated binary Merkle construction in the source. Monitor missing promises past MMD and conflicting or inconsistent heads with retained signed evidence.

## Alternatives Considered

Sign transcript hashes without a Merkle history. This reduces storage but removes independent consistency and omission checks.

## Drawbacks

Durable commits add fast-path latency; operators must retain public leaf and head history.

## Migration / Rollout

Publish /log/v1 at the initial release, with fresh keys identified in the descriptor and archival key lookup.

## Testing Strategy

Test fixed preimages, tree reference vectors, concurrent retry, crash after commit, bad proof size and monitor evidence for omitted promises.

## Open Questions

None.

## References

- [Canonical specification](../spec/03-data-model.md#binding-invariants)
- [Source contract](../../specs/receipt-log.md#merkle-tree)
- [RFC index](README.md#accepted-decisions)
