# RFC-0003: Enforce greedy policy and terminal delivery

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M1

## Summary

The gateway admits only inputs whose token executions can be warranted.

## Motivation

Unvalidated flags and terminal success before a log promise undermine the delivery claim. See [canonical specification](../spec/02-public-api.md#interfaces).

## Goals

- Require a verified durable log promise for every warranted completion.

## Non-Goals

- Add transparent model substitution or allow best-effort receipts.

## Proposed Design

`validate(body: object, mode: Mode) -> InferenceRequest`; `complete(request: InferenceRequest) -> Completion | ServiceError`. Model names and resolved budget agree with the descriptor. Validate vocabulary, body limit and field allowlists, use bounded FIFO admission, and release the slot after every result. The engine receives only token IDs and the allowlisted neutral controls. Validate final tokens and completeness before writing private delivery artifacts and committing the log promise. Implement direct receipt delivery, discovery and raw completions; defer router compatibility and streaming promotion to M4. Concurrent deadlines and cancellation cannot turn an unresolved promise into a successful completion.

## Alternatives Considered

Accept broad compatibility fields and ignore unsupported controls. That can promise behavior the proof cannot certify.

## Drawbacks

Strict compatibility rejects some SDK defaults.

## Migration / Rollout

Ship with mocks and keep admission unavailable when the real engine is unready.

## Testing Strategy

Check every accepted neutral value and invalid counterpart, alias equality, queue saturation, timeout cancellation, and invalid promise with no completion.

## Open Questions

None.

## References

- [Canonical specification](../spec/02-public-api.md#interfaces)
- [Source contract](../../specs/gateway-api.md#request-policy)
- [RFC index](README.md#accepted-decisions)
