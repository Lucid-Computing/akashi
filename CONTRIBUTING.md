# Contributing to Verified Inference Gateway

Thank you for your interest in contributing to this project. This document outlines the process and standards for contributions.

## Getting Started

Install Git, Make and uv 0.13.6. From a clean checkout, run the CPU profile:

```sh
make setup
make test-unit
make lint
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

**Do not open public issues for security vulnerabilities.**

Email security reports to: [security contact to be added]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fixes (if any)

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

Good documentation is essential:

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
