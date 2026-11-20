# RFC-0002: Freeze rendering and token boundaries

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M1

## Summary

One pinned rendering implementation drives gateway, auditor and holder checks.

## Motivation

Intact token proofs cannot detect a discrepancy between the viewed transcript and the original chat by themselves. See [canonical specification](../spec/02-public-api.md#request-invariants).

## Goals

- Produce the same IDs and display text from the same profile and input.

## Non-Goals

- Add prompt rewriting, normalization or additional modalities.

## Proposed Design

`render(messages: tuple[Message, ...], profile: RenderProfile) -> tuple[Token, ...]`; `decode(tokens: tuple[Token, ...], profile: RenderProfile) -> str`. Verify full digests of both files from the pinned revision, run the packaged template with generation prompt, fixed date and absent tools, and encode without added special tokens. The template emits BOS; do not prepend a second one. Hash UTF-8 profile name followed by both raw digests; the raw-ID profile hashes its name alone. Preserve whitespace and Unicode code points and decode with special tokens retained and cleanup disabled. Resolve a profile once per request; immutable assets can be cached. Unsupported digest or unreadable asset fails closed. In raw mode compare arrays directly and require null display text in verification.

## Alternatives Considered

Render independently with each client's runtime. That gives clients flexibility at the cost of uncertifiable token drift.

## Drawbacks

Pinning requires publishing and preserving historical assets.

## Migration / Rollout

Lock the production renderer after comparison to the pinned reference; publish a new digest for behavior changes.

## Testing Strategy

Check 200 chat goldens including single BOS, empty user text, whitespace, multipart rejection and composed/decomposed Unicode, plus raw-ID boundaries.

## Open Questions

Renderer owner records full file digests and exact library pins before the M1 golden gate.

## References

- [Canonical specification](../spec/02-public-api.md#request-invariants)
- [Source contract](../../specs/canonical-rendering.md#encoding-procedure)
- [RFC index](README.md#accepted-decisions)
