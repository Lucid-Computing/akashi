# Verifier

Standalone proof verification tools for independent validation of receipts and ZK proofs.

## Purpose

The verifier kit enables clients to independently verify receipts through 6 steps: receipt signature, transcript commitment, tree inclusion, tree consistency, render correctness, and optionally model conformance.

## Specifications

- `specs/verifier-kit.md`: Complete verification procedure and exit codes
- `specs/facts-register.md`: F9 (cp_verify codes), F23, F25, F26 (performance)

## Exit Codes

From spec § 11.3:

| Code | Meaning |
|---|---|
| 0 | conforms: every check passed |
| 10 | receipt invalid (signature, `t`, inclusion) |
| 11 | rendering mismatch |
| 12 | text mismatch |
| 13 | reply incomplete |
| 20 | proof rejected (`cp_verify` exit 1) |
| 21 | deviation proven |
| 30 | no verdict (`cp_verify` 2-5, 14, 15; missing files) |
| 64 | usage |

## Source checkout

Run `make setup test-receipts test-merkle-log` from the repository root for the signed-receipt and log evidence checks. Native proof verification requires the pinned binary and F4 public inputs on a compatible x86-64 Linux CPU. [Contributor setup](../CONTRIBUTING.md#getting-started) · [Distribution policy](../docs/spec/09-release-and-versioning.md#distribution)

## Related Specifications

- `specs/receipt-log.md`: Receipt format
- `specs/audit-protocol.md`: Challenge submission
- `specs/canonical-rendering.md`: Tokenizer and rendering
