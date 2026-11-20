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

## CPU proof verification

`verifier.proof.verify_reply` independently reconstructs the original whole-reply statement or its first divergent prefix. Give it the holder's prompt, served reply, signed budget and private candidate. A missing proof, a mismatched statement and a native rejection have distinct structured outcomes. A configured secondary checker receives the identical reconstructed bytes. A disagreement preserves both outcomes and prevents a successful verdict. [Proof runtime contract](../docs/rfcs/RFC-0006-proof-runtime.md#proposed-design)

Configure `NativeVerifier` with the trusted local binary, manifest, configuration directory, public key directory, wall-clock timeout, address-space limit in bytes and maximum proof size in bytes. On x86-64 Linux with SHA extensions, it checks pinned files, writes the reconstructed request and locally determined token file in a private directory, then runs the positional F9 command under `prlimit`. No weights or GPU are required. The F4 configuration uses the upstream proof-of-work accounting. The verifier checks the terminal verdict, statement coverage, exact-match policy and commitment record before accepting. [F4, F8–F12 and F26](../specs/facts-register.md)

Provision the manifest independently of holder evidence. It contains `schema_version: 1`, `flashprove_revision`, `commitment_id` and a `sha256` object with lowercase SHA-256 digests for `cp_verify`, `config/policy.txt` and `config/layout.txt`. Hash the measured build and the exact fitted files from the compared F4 rebuild. The package supplies the published digests for `config/KL.bin`, `ivk/key.bin` and `ivk/leaf/0.bin`. The native verifier authenticates subsequent leaf files against the pinned key. [F4 expected values](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/expected.txt)

For independent checking, pass `LeanVerifier(inputs, LeanConfig(checkout, lake, temp), timeout_seconds)` as the secondary checker. Provision the pinned FlashProve tree and its compiled `lean/.lake` cache following the upstream instructions, a trusted Lake executable, and a private scratch directory owned by the verifier account. The wrapper validates the pinned sources, serializes use of the compiled cache and checks the official script's exit and full verdict line. [Upstream Lean verifier](https://github.com/anthropics/FlashProve/tree/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/tools/lean-verify)

Run `make test-proof-verification` for reconstruction, native outcome mapping and secondary disagreement. To exercise a real CPU, use a verified Maverick fixture directory containing `config/`, `ivk/`, `example.req`, `example.y` and `example.proof` from the public Maverick example. Run `python -m tests.native_verification --help` for its paths and host limits. The command independently regenerates the public next-token request, checks its proof, and exercises changed-input and missing-key controls. Whole-reply evidence uses a different range and is measured in M0 and M2.

## Related Specifications

- `specs/receipt-log.md`: Receipt format
- `specs/audit-protocol.md`: Challenge submission
- `specs/canonical-rendering.md`: Tokenizer and rendering
