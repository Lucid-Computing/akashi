# Contributing to Akashi

## Getting Started

Install Git, Make and uv 0.13.6. From the root of a clean checkout, run the CPU checks.

```sh
make setup
make test-unit
make lint
make docs-check
```

uv selects the CPython patch in `.python-version` and installs the resolved
artifacts from `uv.lock` into `.venv`. The commands reject stale locks.
Declare runtime dependencies with exact versions in `pyproject.toml`, then
regenerate the lock with `uv lock`. CI checks both base and optional runtime
requirements and runs Ruff and strict mypy over the checkout.

For a serving or proving host, run the separate `make check-hardware` preflight.
The hardware requirements and upstream runtime pins are in
[the facts register](specs/facts-register.md#hardware-requirements) and
[parameters](specs/parameters.md#version-pinning). Milestone evidence requires
the real-model runs specified in the [build plan](specs/build-plan.md).

For the CPU milestone integration run, use `make gate-m1`. It fetches and checks the pinned public rendering assets or uses `AKASHI_RENDER_ASSETS` for an offline run. The report is written to `build/gates/m1.json`. Use `make demo-router` to exercise the holder through the local mock router. [Milestone evidence](docs/spec/07-testing-strategy.md#release-gates) · [Router demo](router/README.md)

## Build and check the verifier wheel

From the repository root, use the pinned uv and the development environment installed by `make setup`.

```sh
make setup
make test-package
```

The gate builds the Linux x86-64 `akashi-verify` 0.0.0 development wheel and checks its explicit file list, package metadata, native inputs and wheel RECORD. It installs the locked dependencies and the wheel in a fresh environment, then invokes the installed `akashi` command on the signed raw-ID fixture and a changed-signature control. A cross-installed Linux wheel on macOS can run those receipt checks. Native proof qualification runs on a compatible Linux CPU. [Platform and build provenance](distribution/verifier/README.md#native-executable)

The gate writes the wheel, hash-locked `requirements.txt` and `verifier-install-v1.json` to `build/package/`. Its report at `build/gates/package.json` records their SHA-256 values, the source revision, the installed dependency and license inventory, and the receipt outcomes. Pair that report with the Linux clean-install proof run for the same wheel digest. Preserve the exact candidate hashes when preparing release evidence. [Holder installation and fixture](verifier/README.md#install-the-development-wheel) · [Release policy](docs/spec/09-release-and-versioning.md#distribution)

When changing the native bundle, compare a clean build of the pinned FlashProve executable with its measured SHA-256 and reconcile every fitted input with the F4 provenance. Review the wheel's file mappings and license list together. Keep F37 tokenizer assets external and hash-pinned. [Measured public input inventory](distribution/verifier/README.md#public-verification-inputs) · [Wheel build metadata](distribution/verifier/pyproject.toml)

## Compatibility

| Change | Evidence to include |
| --- | --- |
| Shared Python code | Run the locked CPU commands above. The package declares Python 3.10 or newer. The default contributor interpreter is CPython 3.13.18. |
| Public response or CLI | Test the supported version and structured outcome. Preserve historical signed evidence and the interpretation of existing fields. |
| Request or signed encoding | Check old and new inputs against the published vectors. A breaking interpretation needs a new protocol or artifact version. |
| Real engine or prover | Run the role's hardware checks on x86-64 Linux with SHA extensions and an H100. F31 specifies CUDA 13.2 Update 2, GCC/G++ 13 and Python 3.13. |
| Native proof verifier | Exercise the pinned verifier on x86-64 Linux with SHA extensions and the public verification inputs. The verifier runs on CPU. |

Tests with host-owned dependencies report skips when those dependencies are absent. Record the skipped cases with the command and environment. Cite the relevant gate artifact before making a release claim. [Release compatibility policy](docs/spec/09-release-and-versioning.md#release-policy) · [Hardware sources F22, F24, F26 and F31](specs/facts-register.md#hardware-requirements)


## Open a change

For a small fix, send a focused pull request. For a new protocol, a change to a signed
format, or a change to the trust model, start with an issue and link the relevant
[contract](SPEC.md) or [RFC](docs/rfcs/README.md). That gives reviewers a chance to
settle the compatibility question before reviewing code.

In the pull request, include the behavior you changed, how you checked it, and any
checks that require another host. For a measured run, name the exact revision, model
commitment, environment and measurement boundary. Label mock and real-model results
clearly. For user-facing changes, update [the changelog](CHANGELOG.md) and the affected
guide or specification.

Keep signed vectors for existing versions. Add regression coverage at the affected
boundary when you change request admission, transcript binding, proof verification or
private-data handling. Use synthetic inputs and isolated state. Keep weights,
transcripts, proof material, credentials and signing keys out of Git, issues and CI
artifacts. [Private data handling](docs/operations/private-data.md)

## Get help

Search or open a [GitHub issue](https://github.com/Lucid-Computing/akashi/issues)
for reproducible bugs, documentation gaps or project questions. Send vulnerability
reports through the [private security channel](SECURITY.md#security-reporting).

Project contributions use the [Apache License 2.0](LICENSE).
