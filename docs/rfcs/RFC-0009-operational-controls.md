# RFC-0009: Enforce privacy and observe lifecycle failures

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M1

## Summary

Operations exposes health and accountability while keeping private artifacts out of public services.

## Motivation

A proof is sensitive, and monitoring alone can accidentally expose the data being protected. See [canonical specification](../spec/05-observability.md#telemetry-contract).

## Goals

- Verify redaction, retention, checkpoint monitoring and private network isolation.

## Non-Goals

- Make legal compliance promises or introduce availability guarantees.

## Proposed Design

`emit(event: Event) -> None`; `sweep(now: Instant) -> RetentionReport`. Validate telemetry against the allowlist in the observability contract. Separate one-shot expiry from read-time access checks so a delayed sweeper does not extend access. Keep authenticated roles and distinct keys; publish verification key IDs and archive retired public keys. Persist public leaves, heads and verdicts. Use configured TTLs for private state, delete key slots with record expiry, and keep proof downloads scoped to holders. Reject diagnostics that include transcript material. Expose readiness only when configured dependencies can satisfy the serving gates; monitor independent signed-history continuity.

## Alternatives Considered

Centralize all log and proof objects in unrestricted observability storage. This eases debugging while widening access to private content.

## Drawbacks

Redaction makes production debugging dependent on controlled fixtures and bounded metadata.

## Migration / Rollout

Land common operational contracts with mocks and verify them on real nodes before soak.

## Testing Strategy

Use recognizable canary values in private inputs and prove their absence from telemetry and public endpoints. Exercise clock-boundary expiration, rotation and shutdown.

## Open Questions

Operations owner records deployment-specific pickup and audit API limits before Mode R promotion.

## References

- [Canonical specification](../spec/05-observability.md#telemetry-contract)
- [Source contract](../../specs/hardening.md#secrets-management)
- [RFC index](README.md#accepted-decisions)
