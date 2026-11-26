# Verify a reply offline

The `akashi verify` command checks the holder’s original input and displayed reply
against a signed receipt and log history. With a proof and the public verifier
inputs, it also checks the reply against the committed integer model. Native
verification requires a compatible Linux CPU. It reads local files and needs
no model weights. [Verification contract](../specs/verifier-kit.md) ·
[Recorded CLI session](../docs/demo/README.md#the-offline-check)

| Exit | Meaning |
| --- | --- |
| 0 | `CONFORMS`. The proof and holder checks passed. |
| 10 | Receipt or signed history failed validation. |
| 11 | Input rendering mismatch. |
| 12 | Displayed text mismatch. |
| 13 | Incomplete reply. |
| 20 | `PROOF_REJECTED`. The proof failed verification. |
| 21 | A deviation was proven. |
| 30 | The holder obtained no model verdict. Read the JSON outcome to distinguish `RECEIPT_VERIFIED` from unavailable evidence or runtime. |
| 64 | CLI usage error. |

[Complete error contract](../docs/spec/04-error-model.md#verification-errors)

## Install the development wheel

`akashi-verify` 0.0.0 is a local development candidate. On x86-64 Linux with Python 3.10 or newer, obtain the wheel, `requirements.txt` and `verifier-install-v1.json` from the candidate build. Use a separately trusted copy of its package report to check the wheel, lock and fixture SHA-256 values before installation. The qualified native host runs Ubuntu 24.04 with SHA extensions, glibc 2.39 and the documented C++ runtime. [Candidate build instructions](../CONTRIBUTING.md#build-and-check-the-verifier-wheel) · [ELF requirements and input digests](../distribution/verifier/README.md#native-executable)

Run these commands in the directory containing those three candidate files. Set `AKASHI_PACKAGE_REPORT` to the trusted report path. Choose a fresh, user-owned directory for the environment.

```sh
set -e
python3 - "$AKASHI_PACKAGE_REPORT" <<'PYVERIFY'
import hashlib, json, pathlib, sys

report = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
if (report["schema_version"], report["gate"], report["status"]) != (1, "package", "passed"):
    raise SystemExit("expected a passing package report")
for filename, field in [
    ("akashi_verify-0.0.0-py3-none-linux_x86_64.whl", "wheel_sha256"),
    ("requirements.txt", "lock_sha256"),
    ("verifier-install-v1.json", "fixture_sha256"),
]:
    if hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest() != report[field]:
        raise SystemExit("candidate digest mismatch: " + filename)
PYVERIFY
uv venv --no-project --python python3 .venv
uv pip install --python .venv/bin/python --require-hashes --only-binary :all: -r requirements.txt
uv pip install --python .venv/bin/python --no-deps ./akashi_verify-0.0.0-py3-none-linux_x86_64.whl
uv pip check --python .venv/bin/python
.venv/bin/akashi verify --help
```

For an offline installation, stage the matching dependency wheels for your Python and platform, and add `--no-index --find-links /path/to/wheelhouse` to the requirements installation command. Verification itself reads local files.

### Check the public installation fixture

The synthetic raw-ID fixture contains a signed receipt, its public descriptor and a trusted checkpoint. It tests the installed CLI's input binding and signed history. It needs neither a tokenizer nor a proof. The successful receipt-only outcome is `RECEIPT_VERIFIED` with exit 30. The package gate also checks that an altered signature yields exit 10. [Public fixture](../tests/fixtures/verifier-install-v1.json)

```sh
.venv/bin/python - <<'PYFIXTURE'
import json, pathlib, subprocess

sample = json.loads(pathlib.Path("verifier-install-v1.json").read_bytes())
for field in ("bundle", "descriptor", "checkpoint"):
    pathlib.Path("fixture-" + field + ".json").write_text(json.dumps(sample[field]))
result = subprocess.run([
    ".venv/bin/akashi", "verify", "fixture-bundle.json", "--descriptor", "fixture-descriptor.json",
    "--checkpoint", "fixture-checkpoint.json", "--observed-at", sample["observed_at"], "--receipt-only",
], capture_output=True, text=True)
print(result.stdout, end="")
if result.returncode != 30 or json.loads(result.stdout)["outcome"] != "RECEIPT_VERIFIED":
    raise SystemExit("receipt fixture failed")
PYFIXTURE
```

### Verify a private chat reply with the installed native checker

Obtain the descriptor through a trusted channel, use the original holder input and provide the saved signed checkpoint when available. Stage the two F37 files from revision `86c5ecb6f2fbddf604c60120125fb202e09f2556` of `unsloth/Llama-4-Maverick-17B-128E-Instruct` in the same local directory. The renderer verifies each file before use. [Pinned tokenizer files](https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/tree/86c5ecb6f2fbddf604c60120125fb202e09f2556) · [Canonical rendering](../specs/canonical-rendering.md)

| File | SHA-256 |
|---|---|
| `tokenizer.json` | `172c9eb4beafc72601690da3ccfcede5c2e6806a8d5ec1fca33e22acea8023a4` |
| `tokenizer_config.json` | `2c56f1b600f928762c235c1b7a9349dc50c3574031f396a35ab25d3ad3ca425d` |

With the wheel installed, a trusted `--runtime` JSON object containing only the positive `timeout_seconds`, `memory_bytes` and `max_proof_bytes` selects its bundled native checker and F4 files. For example, the CPU qualification uses the following host limits.

```json
{"timeout_seconds":180,"memory_bytes":8589934592,"max_proof_bytes":33554432}
```

```sh
.venv/bin/akashi verify holder.json --descriptor trusted-akashi.json \
  --checkpoint previous-sth.json --assets /path/to/f37 --runtime verifier-runtime.json
```

A verified whole-reply conformance proof returns `CONFORMS` and exit 0. The CLI reports `PROOF_REJECTED` with exit 20 for a rejected proof and `DEVIATES` with exit 21 for a verified divergence. Use the receipt-only example above to check installation without private proof material. [Proof contract](../docs/rfcs/RFC-0006-proof-runtime.md) · [Holder outcomes](../docs/rfcs/RFC-0008-holder-verification.md)

## Source checkout

Run `make setup test-receipts test-merkle-log` from the repository root for the signed-receipt and log evidence checks. Native proof verification requires the pinned binary and F4 public inputs on a compatible x86-64 Linux CPU. [Contributor setup](../CONTRIBUTING.md#getting-started) · [Distribution policy](../docs/spec/09-release-and-versioning.md#distribution)

## CPU proof verification

`verifier.proof.verify_reply` independently reconstructs the original whole-reply statement or its first divergent prefix. Give it the holder's prompt, served reply, signed budget and private candidate. A missing proof, a mismatched statement and a native rejection have distinct structured outcomes. A configured secondary checker receives the identical reconstructed bytes. A disagreement preserves both outcomes and prevents a successful verdict. [Proof runtime contract](../docs/rfcs/RFC-0006-proof-runtime.md#proposed-design)

Configure `NativeVerifier` with the trusted local binary, manifest, configuration directory, public key directory, wall-clock timeout, address-space limit in bytes and maximum proof size in bytes. On x86-64 Linux with SHA extensions, it checks pinned files, writes the reconstructed request and locally determined token file in a private directory, then runs the positional F9 command under `prlimit`. No weights or GPU are required. The F4 configuration uses the upstream proof-of-work accounting. The verifier checks the terminal verdict, statement coverage, exact-match policy and commitment record before accepting. [F4, F8–F12 and F26](../specs/facts-register.md)

Provision the manifest independently of holder evidence. It contains `schema_version: 1`, `flashprove_revision`, `commitment_id` and a `sha256` object with lowercase SHA-256 digests for `cp_verify`, `config/policy.txt` and `config/layout.txt`. Hash the measured build and the exact fitted files from the compared F4 rebuild. The package supplies the published digests for `config/KL.bin`, `ivk/key.bin` and `ivk/leaf/0.bin`. The native verifier authenticates subsequent leaf files against the pinned key. [F4 expected values](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/expected.txt)

For independent checking, pass `LeanVerifier(inputs, LeanConfig(checkout, lake, temp), timeout_seconds)` as the secondary checker. Provision the pinned FlashProve tree and its compiled `lean/.lake` cache following the upstream instructions, a trusted Lake executable, and a private scratch directory owned by the verifier account. The wrapper validates the pinned sources, serializes use of the compiled cache and checks the official script's exit and full verdict line. [Upstream Lean verifier](https://github.com/anthropics/FlashProve/tree/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/tools/lean-verify)

Run `make test-proof-verification` for reconstruction, native outcome mapping and secondary disagreement. To exercise a real CPU, use a verified Maverick fixture directory containing `config/`, `ivk/`, `example.req`, `example.y` and `example.proof` from the public Maverick example. Run `python -m tests.native_verification --help` for its paths and host limits. The command independently regenerates the public next-token request, checks its proof, and exercises changed-input and missing-key controls. Whole-reply evidence uses a different range and is measured in M0 and M2.

## Verify a holder bundle offline

From a source checkout, use the locked environment. Supply the descriptor obtained through a trusted channel and the private bundle assembled from your original input, resolved completion budget and displayed response. The command operates on local files.

```sh
make setup
uv run --locked ./akashi verify holder.json --descriptor trusted-akashi.json \
  --assets /path/to/pinned-tokenizer --checkpoint previous-sth.json \
  --runtime verifier-runtime.json
```

The bundle uses `verification` from the warranted response or opened pickup envelope, `max_tokens` from the caller, `input` containing the original messages or raw IDs, and `text` containing the displayed chat text or JSON null for raw mode. Supply the signed head as `history.sth` and the log's inclusion response as `history.inclusion`. If you have an older trusted head, pass it separately with `--checkpoint` and include the log's response in `history.consistency`. The descriptor can include retired log verification keys. Chat uses both F37 assets from `--assets` or `AKASHI_RENDER_ASSETS`.

The optional `proof` object carries `kind`, the original 4,104-byte `statement` in lowercase hex, and `proof` in standard padded Base64. Deviation evidence includes the zero-based reply `index` and corrected token `expected`. Both kinds use a four-byte zero public output and accept an explicit `y` of `00000000`. Provide trusted native verifier paths in `--runtime` using `binary`, `manifest`, `config_dir` and `public_key_dir`. Configure `timeout_seconds`, `memory_bytes` and `max_proof_bytes` according to the verifier host. Optional `lean` settings use `checkout`, `lake`, `temp` and `timeout_seconds`. See the [proof runtime](../docs/rfcs/RFC-0006-proof-runtime.md) and [holder contract](../docs/rfcs/RFC-0008-holder-verification.md).

Every verification result is a schema-versioned JSON object with `exit_code`, `outcome` and `warnings`. Use `--receipt-only` to verify the original input, text, binding, signed history and completeness without a proof runtime. Success in this mode reports `RECEIPT_VERIFIED` and exits 30. An absent inclusion path reports whether the merge deadline elapsed. An expired holder challenge window can coexist with a valid historical proof. `make test-holder-verifier` runs the holder and proof-decoding controls. [Verification errors](../docs/spec/04-error-model.md#verification-errors)
