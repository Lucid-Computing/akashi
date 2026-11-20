# RFC-0001: Gate the integer engine on reproducible execution

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M0

## Summary

The provider gets a serialized token interface with a reproducible startup gate.

## Motivation

The gateway must distinguish an honest plugin integrity fault from a completion eligible for a receipt. See [canonical specification](../spec/01-architecture.md#service-boundaries).

## Goals

- Recreate the commitment and match golden canary tokens before serving.

## Non-Goals

- Generalize across GPU families or relax integer exactness.

## Proposed Design

`Engine.generate(prompt: tuple[Token, ...], max_tokens: int) -> EngineResult` returns ordered tokens and a closed integrity window; a failed or unobservable window yields unavailable evidence. Follow the pinned launch, weight verification and three-canary contract. Run the float64 check on the serving GPU after relevant runtime changes. Device and dtype settings are part of the measured build; disable implicit precision fallback. Hold the execution lock from dispatch through last token and a log checkpoint covering the request. Close the slot on cancellation and quarantine the engine until the window can be reconciled. Report gate results without content. Release real deployment only behind the private route allowlist and mutual authentication.

## Alternatives Considered

Rely only on readiness probes to reduce startup time. Those probes cannot establish the pinned tensor and numerical invariants.

## Drawbacks

Launch consumes time and requires a dedicated host configuration.

## Migration / Rollout

Enable mock adapters for CPU tests; real routing requires measured promotion.

## Testing Strategy

Inject an adapter reporting each failed gate, a missing log checkpoint and cancellation; observe no receipt. Run commitment comparison and the 16-reply proof gate.

## Open Questions

Engine owner resolves OQ1, OQ2, OQ7 and the initial OQ9 cross-host comparison at M0. Repeat OQ9 on every serving startup; record unavailable second-host evidence.

## References

- [Canonical specification](../spec/01-architecture.md#service-boundaries)
- [Source contract](../../specs/engine.md#start-up-gates)
- [RFC index](README.md#accepted-decisions)
