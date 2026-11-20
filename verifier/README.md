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

## Related Specifications

- `specs/receipt-log.md`: Receipt format
- `specs/audit-protocol.md`: Challenge submission
- `specs/canonical-rendering.md`: Tokenizer and rendering

## Verify a holder bundle offline

From a source checkout, use the locked environment. Supply the descriptor obtained through a trusted channel and the private bundle assembled from your original input, resolved completion budget and displayed response. The command operates on local files.

```sh
make setup
uv run --locked ./vig verify holder.json --descriptor trusted-vig.json \
  --assets /path/to/pinned-tokenizer --checkpoint previous-sth.json \
  --runtime verifier-runtime.json
```

The bundle uses `verification` from the warranted response or opened pickup envelope, `max_tokens` from the caller, `input` containing the original messages or raw IDs, and `text` containing the displayed chat text or JSON null for raw mode. Supply the signed head as `history.sth` and the log's inclusion response as `history.inclusion`. If you have an older trusted head, pass it separately with `--checkpoint` and include the log's response in `history.consistency`. The descriptor can include retired log verification keys. Chat uses both F37 assets from `--assets` or `VIG_RENDER_ASSETS`.

The optional `proof` object carries `kind`, the original 4,104-byte `statement` in lowercase hex, and `proof` in standard padded Base64. Deviation evidence includes the zero-based reply `index` and corrected token `expected`. Both kinds use a four-byte zero public output and accept an explicit `y` of `00000000`. Provide trusted native verifier paths in `--runtime` using `binary`, `manifest`, `config_dir` and `public_key_dir`. Configure `timeout_seconds`, `memory_bytes` and `max_proof_bytes` according to the verifier host. Optional `lean` settings use `checkout`, `lake`, `temp` and `timeout_seconds`. See the [proof runtime](../docs/rfcs/RFC-0006-proof-runtime.md) and [holder contract](../docs/rfcs/RFC-0008-holder-verification.md).

Every verification result is a schema-versioned JSON object with `exit_code`, `outcome` and `warnings`. Use `--receipt-only` to verify the original input, text, binding, signed history and completeness without a proof runtime. Success in this mode reports `RECEIPT_VERIFIED` and exits 30. An absent inclusion path reports whether the merge deadline elapsed. An expired holder challenge window can coexist with a valid historical proof. `make test-holder-verifier` runs the holder and proof-decoding controls. [Verification errors](../docs/spec/04-error-model.md#verification-errors)
