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

## Distribution

Python package with pinned, reproducibly built `cp_verify` binary per platform (x86-64 Linux with SHA extensions).

```bash
pip install vig-verify
```

## Testing

```bash
cd verifier/
pytest tests/ -v
```

## Related Specifications

- `specs/receipt-log.md`: Receipt format
- `specs/audit-protocol.md`: Challenge submission
- `specs/canonical-rendering.md`: Tokenizer and rendering
