# Contributing to Verified Inference Gateway

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

For the CPU milestone integration run, use `make gate-m1`. It fetches and checks the pinned public rendering assets or uses `VIG_RENDER_ASSETS` for an offline run. The report is written to `build/gates/m1.json`. Use `make demo-router` to exercise the holder through the local mock router. [Milestone evidence](docs/spec/07-testing-strategy.md#release-gates) · [Router demo](router/README.md)

## Build and check the verifier wheel

From the repository root, use the pinned uv and the development environment installed by `make setup`.

```sh
make setup
make test-package
```

The gate builds the Linux x86-64 `vig-verify` 0.0.0 development wheel and checks its explicit file list, package metadata, native inputs and wheel RECORD. It installs the locked dependencies and the wheel in a fresh environment, then invokes the installed `vig` command on the signed raw-ID fixture and a changed-signature control. A cross-installed Linux wheel on macOS can run those receipt checks. Native proof qualification runs on a compatible Linux CPU. [Platform and build provenance](distribution/verifier/README.md#native-executable)

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

## Contribution Process

### Before You Start

1. Check existing issues to avoid duplicate work
2. For major changes, open an issue first to discuss the approach
3. Read `AGENTS.md` for architectural guidelines
4. Review relevant specifications in `specs/`

### Making Changes

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes following coding standards (see below)
3. Add or update tests for your changes
4. Update specifications if behavior changes
5. Update documentation as needed
6. Run the full test suite

### Coding Standards

See `AGENTS.md` for detailed coding standards. Key points:

- Use type hints in Python code
- Follow PEP 8 style for Python
- Follow Rust conventions for Rust code
- Write clear, self-documenting code
- Keep functions small and focused
- Validate inputs and handle errors explicitly

### Testing Requirements

All contributions must include appropriate tests:

- **Unit tests**: For individual functions and modules
- **Integration tests**: For component interactions
- **Red team tests**: For security-critical changes
- **Property-based tests**: For cryptographic operations

### Commit Messages

Write clear, descriptive commit messages:

```
Short summary (50 chars or less)

Longer explanation if needed. Wrap at 72 characters.
Explain what changed and why, not how.

Reference issues: Fixes #123
```

### Submitting a Pull Request

1. Push your branch to GitHub:
```bash
git push origin feature/your-feature-name
```

2. Open a pull request with:
   - Clear description of changes
   - Link to related issue
   - List of breaking changes (if any)
   - Testing performed

3. Address review feedback
4. Ensure CI passes before merging

## Code Review Process

All contributions go through code review:

- **Soundness**: Security properties preserved
- **Determinism**: Behavior is predictable
- **Testing**: Adequate test coverage
- **Documentation**: Specs and docs updated
- **Style**: Follows coding standards

Reviews may take several days. Be patient and responsive to feedback.

## Security Guidelines

### Reporting Security Issues

Send reports privately to the maintainer using the [security policy](SECURITY.md#security-reporting).

### Secure Development Practices

- Never commit secrets, keys, or credentials
- Use environment variables for configuration
- Validate and sanitize all inputs
- Use established cryptographic libraries
- Document security assumptions

### Model Weights

Model weights must never be committed to version control:

- Add weight directories to `.gitignore`
- Document weight download and verification procedures
- Use checksums to verify weight integrity
- Pin weights to specific versions

## Documentation

Run `make docs-check` before submitting documentation. CI checks local file links, heading anchors and the accepted RFC section structure.

- Update `README.md` for user-facing changes
- Update `AGENTS.md` for architectural changes
- Add ADRs in `docs/decisions/` for design decisions
- Update specifications in `specs/` for behavior changes
- Include inline comments for complex logic

## Architecture Decision Records

For significant design decisions, create an ADR:

1. Copy `docs/decisions/000-template.md`
2. Name it `NNN-descriptive-title.md` (next number in sequence)
3. Fill in: Context, Decision, Consequences, Alternatives
4. Link to relevant spec sections
5. Include in your PR

## Testing

### Writing Tests

- Test one thing per test function
- Use descriptive test names
- Include edge cases and error conditions
- Mock external dependencies
- Keep tests fast and deterministic

### Red Team Tests

Security testing is critical. Red team tests should:

- Attempt to break security properties
- Document the attack vector
- Verify defenses work correctly
- Be maintained as the system evolves

## Performance Considerations

- Profile before optimizing
- Document performance requirements
- Add benchmarks for critical paths
- Consider proof generation cost
- Verify scalability claims with tests

## Questions and Support

- Open an issue for questions
- Check `specs/open-questions.md` for known unknowns
- Review `docs/decisions/` for design rationale
- Read `AGENTS.md` for development guidelines

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Recognition

Contributors will be recognized in release notes and project documentation.

Thank you for contributing to verifiable inference!
