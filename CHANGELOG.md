# Changelog

## Unreleased

- Rename the project to Akashi. The repository moved to `Lucid-Computing/akashi`. The CLI is now `akashi`, the wheel `akashi-verify`, the environment prefix `AKASHI_`, and the service units and paths `akashi*`. Protocol domains, the `x-akashi-receipt` header, `/.well-known/akashi.json` and the `akashi-pickup/1` envelope replace their `vig` forms. Receipts, pickups and verdicts made under the old domains no longer verify, and the reference vectors were regenerated. [Data model](docs/spec/03-data-model.md)
- Document the recorded Maverick request and both offline CLI verdicts with exact measurement boundaries and machine-readable evidence. [Recorded demo](docs/demo/README.md)
- Give contributors a CPU quickstart and issue forms that direct vulnerability reports to the private security channel. [Quickstart](README.md#try-it) · [Security reporting](SECURITY.md)
- The independent log monitor treats a public log response nested too deeply to decode as malformed. It keeps running and raises the coverage alert for overdue promises instead of stopping without one. [Independent monitor](log/README.md#independent-monitor)

## 0.0.0 development candidate

The development candidate supports signed inference receipts, an append-only receipt log, opt-in sealed pickup and offline holder verification for the pinned Maverick commitment. The holder can reconstruct its original request and verify the signed history. Native conformance and proven divergence have distinct CLI outcomes. [Holder verification](verifier/README.md) · [Public API](docs/spec/02-public-api.md)

The `akashi-verify` candidate bundles the Linux x86-64 CPU verifier and its measured public F4 verification inputs. The package gate checks the installed CLI with a signed raw-ID fixture. Release qualification also binds the wheel and lock to an independent Linux run on a genuine whole-reply proof and a one-bit altered control. Chat verification uses externally provisioned, digest-checked F37 tokenizer files. [Verifier kit](specs/verifier-kit.md) · [Native facts F4 and F9–F12](specs/facts-register.md)

The local router exercise uses opaque forwarding, sealed pickup, a separate holder process and real signed log history. The full M4 gate additionally requires a continuous 72-hour all-audit run on the eligible primary. The historical M2 challenge has its own three-day wall-clock requirement. [Router demo](router/README.md) · [Milestone criteria](docs/spec/07-testing-strategy.md#release-gates)

`make release-check` ties a clean candidate commit to reviewed M0–M4 reports, dependency and license inventory, checksums and native qualification. A v1 promotion requires passing evidence for every milestone. [Candidate qualification](release/README.md) · [Release policy](docs/spec/09-release-and-versioning.md) · [Security reporting](SECURITY.md)
