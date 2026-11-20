# RFC-0011: Make prototype release evidence reproducible

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M3

## Summary

A release is promoted by reproducible milestone artifacts and compatibility checks.

## Motivation

Without explicit evidence, green CPU tests could be mistaken for real model verification. See [canonical specification](../spec/07-testing-strategy.md#release-gates).

## Goals

- Require every milestone gate and an installable verifier artifact.

## Non-Goals

- Set unsupported release calendars or benchmark service-level promises.

## Proposed Design

`GateResult = {milestone, source_revision, environment, fixture_digest, checks, artifacts, passed}`. Keep CPU checks, defensive contract regressions and real hardware evidence separate. Parameterize R1–R19 expected outcomes and honest controls with isolated fixtures, retaining redacted evidence. Track all selections in a soak ledger and compare against signed log history; classify every missing and excused outcome. Validate lock, SBOM or equivalent dependency inventory, licenses, checksums, documentation links, type checks and clean-package installation before release. Promote only when evidence for prior gates is present and reviewable.

## Alternatives Considered

Bundle all verification into one hardware test job. That obscures coverage and makes ordinary contributor changes depend on expensive devices.

## Drawbacks

Some gates require controlled infrastructure and an external holder.

## Migration / Rollout

Land build and CPU checks early, then add environment-specific gates and signed or checksum-verified release artifacts.

## Testing Strategy

Fail promotion for missing earlier evidence, failed controls, stale artifact digests, incompatible CLI or broken specification links.

## Open Questions

Release owner records the private security reporting route and exact CI tool pins before distribution.

## References

- [Canonical specification](../spec/07-testing-strategy.md#release-gates)
- [Source contract](../../specs/build-plan.md#milestone-structure)
- [RFC index](README.md#accepted-decisions)
