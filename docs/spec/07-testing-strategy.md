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


## Running the M1 CPU gate

Run `make setup gate-m1` from a repository checkout. The gate fetches the two immutable public renderer files and checks their digests. For a provisioned or offline runner, set `VIG_RENDER_ASSETS` to the directory containing both files. Every vector suite must run with zero skips. The gate exercises one isolated Mode D service, a separate public selection reader and the CPU proof fixture. Its fixed workload covers selected, unselected and expired custody alongside two engine failure controls.

The command writes `build/gates/m1.json` with the commit, working-tree status, runtime versions, public vector digests, test counts, and expected and observed fixture outcomes. A failed gate replaces any earlier result and exits nonzero. CPU CI uploads this file as `m1-cpu-evidence`. M2 promotion additionally requires the real M0 evidence described in the [build plan](../../specs/build-plan.md#m0-bring-up).
