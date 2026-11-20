# Engine

vLLM 0.29.0 serving FlashProve integer model with strict integrity gates.

## Purpose

The engine executes LLM inference under constraints that make proofs possible: greedy decoding only, no forced tokens, with range condition monitoring.

## Specifications

- `specs/engine.md`: Complete integration specification (model files, launch config, integrity gates)
- `specs/facts-register.md`: F14-F22 (configuration and performance)

## Key Invariants

From spec § 7:

1. **Start-up gates**: Float64 check, tensor verification, canary test (all must pass before serving)
2. **Single sequence**: `--max-num-seqs 1` ensures integrity monitoring works
3. **Range failures logged**: Engine logs ERROR on range condition failure
4. **Forced tokens logged**: Engine logs WARNING when tokens are forced
5. **Gateway monitors log**: Any ERROR/WARNING during request window → 502 unwarranted

## Model Configuration

From F3-F4:

- Model: Llama 4 Maverick 17B-128E Instruct, UD-Q4_K_XL, ~232 GB
- Commitment ID: `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46`
- Start-up: 22 to 25 minutes with tensor verification (F22)
- Decode: 0.60 to 0.62 s per token (F22)

## Rebuild the Maverick commitment

Use an ordinary account on the F24/F31 host. Prepare a clean FlashProve checkout at
`9e2bdd8ff5bf9c62f18263d7dac189b0400b260c`. Install its hashed requirements in the
active Python 3.13 environment. Provision the five GGUF shards, the per-shard public
weight declarations, and `calibration_set.npy` outside both repositories. Generate
the calibration file using the pinned script in its default mode and the three
inputs in its inventory. [Upstream setup and access requirements](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/README.md#run-it)

| Material | Reference at the FlashProve pin |
|---|---|
| Five UD-Q4_K_XL shards at the F3 revision | [Shard names and SHA-256](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/weights.sha256) |
| WikiText-2, Llama 2 and Llama 4 tokenizers, calibration output | [Revisions, paths, sizes and SHA-256](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/scales/make_calibration_set.py#L80-L122) |
| Published 32-byte seed | [Seed file](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/public-seed.bin) |
| Tensor sums, fitted scales, public verification key, first leaf, commitment ID | [Published comparison values](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/expected.txt) |

Run from the gateway repository root. Set the variables to absolute paths. Choose a
fresh private work directory on a local disk with space for the build and commitment.

```sh
export FLASH_PROVE_DIR=/path/to/clean/FlashProve
export WEIGHTS_DIR=/path/to/prepared/weights
export COMMITMENT_WORK_DIR=/path/to/new/work
make verify-commitment
```

The command exits nonzero when a prerequisite or comparison fails. Keep work
files private, including the generated secret key. The expected ID comes from F4.
On 2026-11-20 the F31 preflight passed on an H100 and the driver completed
`needs`, `build`, `checksums`, `fit`, `commit` and `compare`. The five GGUF
shards passed the pinned checksums. The generated commitment ID, verification
key, first verification leaf, fitted bounds and weight sums matched the pinned
comparison file. The fit reused a weight sums file that matched its pinned
digest. A separate run of the freshly built `weight_sums --eres 10 --threads 24`
read the five original shards and reproduced that file byte for byte. The report
records its SHA-256 under `model/wsums.txt`.
[Hardware rebuild report](evidence/maverick-commitment.json)

## Related Specifications

- `specs/parameters.md`: T=1024, engine parameters
- `specs/hardening.md`: Security configuration (no --trust-remote-code, reverse proxy, mTLS)

## CPU mock

Use the deterministic token adapter in `engine.mock` for M1 integration tests.
The fixtures cover a completed integrity window, an engine integrity fault and
an unavailable engine. Select the fixture when constructing the adapter. The
mock requires no model files or accelerator. Run `make test-mock-engine` at
the repository root. [Engine boundary](../docs/rfcs/RFC-0001-engine-integrity.md#proposed-design)

## Real-model measurements

Run `make gate-m0` on the provisioned verifier host to reconstruct and check a 16-reply hardware capture. [Inputs and replay procedure](baseline.md)
