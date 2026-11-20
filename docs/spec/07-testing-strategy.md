# Testing strategy

## Release gates

| Milestone | Required evidence |
|---|---|
| M0 | Recreated commitment, 16 exact replies proved and verified, startup gates and platform measurements |
| M1 | 200 renderer goldens, receipt and pickup vectors, tree inclusion and consistency vectors, real beacon vectors and nesting, byte-identical request files, end-to-end mocks and independent public recomputation |
| M2 | Three-day-old holder challenge, verified conformance on a separate machine, diagnosed and independently checked deviation |
| M3 | R1–R19 defensive contract regressions with the trial and honest-control requirements in the build plan |
| M4 | Third-party router pickup, challenge and verification plus 72-hour synthetic all-audit soak, stable resource measurements and zero unexplained errors |

Map gates to artifacts with environment, pinned inputs, expected outcomes and observed outcomes. Preserve [build plan criteria](../../specs/build-plan.md#milestone-structure) over summary bullets elsewhere. M0 real bring-up and M1 mock development can proceed in parallel. M2 promotion requires both.

## Validation layers

Unit-test policy edges, byte layouts, deadline equalities, status maps and lifecycle transitions. Property-test logged tree growth across shapes and executable restart/retry invariants. Integrate mock engine and prover on CPU with isolated temporary state. Run real hardware gates separately with explicit setup and published redacted results. Pin fixtures and separate smoke or canary cases from representative timing and soak datasets. Track R1–R19 by outcome using controlled fixtures and assert honest controls. Gate releases on packaging, static typing, docs links and source, dependency and artifact provenance.
