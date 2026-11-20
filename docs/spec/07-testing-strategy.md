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

## Run the M2 proof gate

Run `make gate-m2` on the independent x86-64 CPU verification host. Set `VIG_M2_CONFIG` to the private flow configuration and `VIG_M2_WORK` to its role-owned work directory. The gate reads the passed `build/gates/m0.json` and `build/gates/m1.json` reports. To supply archived reports, pass their paths with `M2_ARGS='--m0 /path/to/m0.json --m1 /path/to/m1.json'`. It writes the redacted result to `build/gates/m2.json`.

The private JSON configuration uses `schema_version` 1 and the following inputs. Protect it with mode 0600 and the work directory with mode 0700.

| Field | Input |
| --- | --- |
| `capture`, `proofs` | The eligible M0 capture directory and singleton proof directory for the matching workload. |
| `assets`, `rx_trace` | The pinned F37 runtime assets and the independent reference role's private trace file. |
| `proof_source_host`, `rx_source_host` | Role host fingerprints from `tools.m2_reference.host_id()`. When proof and reference share a host, the reference defaults to the prover's fingerprint. |
| `service`, `endpoint_id` | The isolated gateway's discovery settings and endpoint identity. The fixture generates its own signing keys and retains them in the private work directory. [Discovery configuration](../../gateway/discovery.py) |
| `native_runtime` | The host-owned native verifier's `binary`, `manifest`, `config_dir`, `public_key_dir`, `timeout_seconds`, `memory_bytes` and `max_proof_bytes`. [CPU proof verification](../../verifier/README.md#cpu-proof-verification) |

The M2 reference role runs `python -m tools.m2_reference --help` for the private configuration and output arguments. The scorer loads the verified F4 model, scores the controlled substitute reply, then binds the first divergent choice to the corrected proof statement. The CPU host checks the receipt, signed auditor verdict, statement and proof for the original and the substitute through the holder CLI. The verifier expects exits 0 and 21 respectively. [M2 exit test](../../specs/build-plan.md#m2-auditor)

The result records how the challenge age was measured. Use `python -m tools.m2_flow --prepare-only --config CONFIG --work WORK --output RESULT` to issue and retain the private receipts. The default replay advances the isolated audit clock by three days. After three days have elapsed since issuance, rerun with `M2_ARGS=--elapsed` to require a naturally aged receipt. Keep the same private work directory. Publish only the redacted report. The proof, statement, rendered tokens, full reference trace and private custody state stay with their roles. OQ6 remains open and the prover uses one request per batch. [Batch privacy](../../specs/open-questions.md#oq6-batch-privacy-under-published-seed) · [Private retention](../../specs/retention.md#retention-policy)

## Running the M3 regression gate

Run `make setup gate-m3`. It runs R1–R19 with isolated synthetic fixtures on the CPU, including the independent holder, monitor and challenge admission paths. Set `VIG_RENDER_ASSETS` for offline use, as for M1. The real-model conformance and historical challenge measurements are recorded by M0 and M2.

The aggregate at `build/gates/m3.json` records the source revision, working-tree status, environment, combined fixture digest and SHA-256 of each component report. It checks the specified outcome and every honest control for each scenario. R18 also reports selected long prompts and short controls. R19 reports both quota boundaries and the durable work checks. A failed rerun replaces earlier passing evidence. CPU CI archives all four reports. [Scenario outcomes](../../specs/redteam-suite.md) · [Release evidence requirements](../rfcs/RFC-0011-release-gates.md#proposed-design)
