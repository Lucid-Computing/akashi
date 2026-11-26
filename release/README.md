# Qualify a local release candidate

`make release-check` produces a reviewable archive for an exact Git commit. The current candidate is `akashi-verify` 0.0.0, a local proof of concept using the opaque mock router and a separately running holder. The command writes files under `build/release/`. Registry publication and a v1 release are separate maintainer decisions. [Release policy](../docs/spec/09-release-and-versioning.md) · [Changelog](../CHANGELOG.md)

## Collect the five reports

Preserve the original JSON bytes emitted by each milestone. Review their source revisions, public input digests, checks and environment. The four earlier reports supplied to M4 must be the same files you supply to the release gate.

| File | Evidence to review |
|---|---|
| `m0.json` | The physically eligible primary engine startup, the fixed real-model workload and the independently checked whole-reply proof evidence. |
| `m1.json` | The clean CPU gateway, log, pickup and sampling checks with pinned renderer inputs and explicit mock outcomes. |
| `m2.json` | The same M0 and M1 report digests. The signed holder challenge must have aged at least three actual wall-clock days and the independent verifier must return conformance 0 and deviation 21 for the designated cases. |
| `m3.json` | The clean, fixed R1–R19 regression corpus and honest controls, including the toolchain, corpus digest and counts. |
| `m4.json` | The same M0–M3 report digests, the original eligible primary and the live soak's fresh startup. At least 72 elapsed hours of all-audit traffic, signed history and verdict reconciliation, measured role resources and at least one independent local holder native verification. |

M0 bring-up and M1's CPU checks can run in parallel. M2 binds those two reports. Its age is measured from the signed delivery. M4 measures its own continuous 72-hour interval from the ready deployment's journal. A controlled future clock, a short rehearsal or an older run's startup record cannot stand in for either elapsed-time condition. Preserve the distinction between a local holder process and an independently operated external service when describing the result. [Milestone criteria](../docs/spec/07-testing-strategy.md#release-gates) · [Release evidence RFC](../docs/rfcs/RFC-0011-release-gates.md)

## Pin the reviewed evidence

Place the five files and `manifest.json` in a local directory outside the checkout. The manifest is a JSON object with these fields.

| Field | Required value |
|---|---|
| `schema_version` | Integer `1`. |
| `candidate_revision` | Full 40-character lowercase Git commit of the clean checkout being qualified. |
| `milestones` | Object keyed by `M0`, `M1`, `M2`, `M3` and `M4`. Each entry contains exactly `sha256` and `source_revision`. |
| `milestones.<gate>.sha256` | Lowercase SHA-256 of that gate's original file bytes, including the final newline if present. |
| `milestones.<gate>.source_revision` | The originating 40-character lowercase commit in the report. M1 records it under `source.commit`. The other reports use `source_revision`. |

Keep the three component reports `m3-model.json`, `m3-evidence.json` and `m3-admission.json` beside the five milestone files. Their digests and originating source revision must match the M3 aggregate.

Pin the SHA-256 of the final reviewed `manifest.json` through a trusted channel separate from the files. A candidate may integrate several earlier milestone commits. This is why the manifest records each source separately. The candidate checkout must contain the milestone validators and package builder, and reproduce the archived CPU fixture results. Its wheel and lock must match the pinned native clean-install qualification. [Evidence validation](evidence.py) · [Candidate builder](check.py)

## Run and inspect

From a clean candidate checkout, install the pinned development environment. Set `AKASHI_RELEASE_EVIDENCE` to the evidence directory and `AKASHI_RELEASE_MANIFEST_SHA256` to the independently reviewed digest. For an offline renderer run, set `AKASHI_RENDER_ASSETS` to the directory holding the two F37 files.

```sh
make setup
export AKASHI_RELEASE_EVIDENCE=/absolute/path/to/reviewed-evidence
export AKASHI_RELEASE_MANIFEST_SHA256="$REVIEWED_MANIFEST_SHA256"
make release-check
cat build/release/status.json
```

The command re-runs documentation, lint and typing, the private-operations drill, the M1 and M3 CPU gates and the clean wheel installation. It verifies the linkage to archived hardware evidence from the qualifying source revisions. A failed run exits nonzero, marks the status `incomplete` and removes any stale candidate from the output directory. Inspect `failed_stage` and any reported `missing_milestones` before retrying. Keep the source reports in their original form. [Qualification command](check.py)

On success, `status.json` records the SHA-256 of `candidate.zip`. The archive contains the verifier wheel, hash-locked requirements, public raw-ID fixture, native build and proof qualification, dependency and license inventory, security contact, changelog and provenance. The provenance records the milestone hashes, original source revisions, eligible startup and signed log root. `SHA256SUMS` covers the other archive members. Compare the outer archive digest with the reviewed status, then check the contents in a new directory before installation.

```sh
mkdir -m 700 release-inspection
unzip -q build/release/candidate.zip -d release-inspection
(cd release-inspection && sha256sum --check SHA256SUMS)
```

Archive the reviewed milestone reports and their independently pinned manifest with the release record. The installation fixture exercises receipt verification. Full proof verification requires a compatible x86-64 Linux CPU and the holder's private original evidence. [Verifier instructions](../verifier/README.md) · [Private security reporting](../SECURITY.md#security-reporting)
