# Engine Integration

## Overview

vLLM 0.29.0 serving FlashProve's integer model with strict integrity gates from specification section 7.

## Model Files and Commitment

| Item | Value | Source |
|---|---|---|
| Weights | `unsloth/Llama-4-Maverick-17B-128E-Instruct-GGUF`, revision `41032e5471dd6ea5b349062d978626215d6c5bba`, folder `UD-Q4_K_XL`, five shards, ~232 GB | F3 |
| Tensor sums | `wsums.txt`, SHA-256 `689cd1d0...b519` | F4 |
| Scales | `KL.bin`, SHA-256 `df29bd82...ab1a` | F4 |
| Public key files | `ivk/key.bin` `178d8814...7c38`, `ivk/leaf/0.bin` `e9dea311...c8dd0` | F4 |
| Configuration | `policy.txt`, `KL.bin`, `layout.txt` (all enter commitment ID) | F6 |
| Commitment ID | `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46` (exact match, published seed) | F4 |

## Launch Configuration

Engine host, as dedicated non-root account, clean environment, model directory mounted read-only (F14):

```bash
CUDA_VISIBLE_DEVICES=0 \
VLLM_USE_V2_MODEL_RUNNER=1 \
VLLM_NO_USAGE_STATS=1 \
PYTHONSAFEPATH=1 \
GLOO_SOCKET_IFNAME=lo \
HOME=<own> \
TMPDIR=<own> \
vllm serve "$M" \
  --served-model-name maverick-int \
  --host 127.0.0.1 \
  --load-format integer_model \
  --max-num-seqs 1 \
  --max-model-len 1024 \
  --no-enable-prefix-caching \
  --enforce-eager \
  --generation-config vllm \
  --fingerprint-mode none \
  --max-logprobs 0 \
  --disable-uvicorn-access-log \
  --model-loader-extra-config '{"reference_directory": "<K>", "reference_files": 5}'
```

With `"verify_sums": true` in `integer_model.json`, so every weight tensor is checked against `wsums.txt` at load (F21). Variable `M` prepared by `integer_model_vllm.example vllm_files M 200001,200007,200008`.

### Prohibited Flags

The engine MUST NOT run with (F14):
- `--trust-remote-code`
- `VLLM_SERVER_DEV_MODE`
- `VLLM_MODEL_REDIRECT_PATH`
- `VLLM_LOGGING_LEVEL` (use default)
- `--middleware` (proof generation is auditor's job, not engine's)

## Start-up Gates

Each logged and exported as a metric; GW sends no traffic until all pass:

1. **Float64 exactness check**: FlashProve's "Check that float64 products are exact on your GPU" on the serving GPU, rerun after any change of GPU, driver, CUDA, PyTorch or environment (F20).

2. **Weight verification**: Two log lines "Verified: these files have the given SHA-256 digests" and "Verified: every weight tensor has the SHA-256 that wsums.txt lists for it" (F21).

3. **Canary test**: Three fixed prompts whose greedy replies are stored as golden token IDs (made once and proved at M0), compared exactly.

## Per-Request Integrity Window

The plug-in reacts to a range-condition failure by ending the reply with an end token the model did not choose and logging an ERROR line; it logs one warning per sequence when a token is forced (F15, F18). Such a reply has no conformance proof.

Because the engine serves one sequence at a time, GW:

1. Holds the engine lock from request send to last token received
2. Tails the engine's log stream (journald or a pipe; gateway host reads it over private link)
3. Marks the request `unwarranted` if any ERROR line or plug-in warning appears during the request window, or if "EngineCore encountered a fatal error" appears (F18)

An `unwarranted` request gets 502 and no receipt, and increments `vig_unwarranted_total{reason}`. This is a defense for the honest provider, not a security control: a malicious engine can suppress its log, and then the reply is receipted and fails audit, which is the intended outcome.

A correct reply can still be unprovable because a range condition fails at a position the engine never evaluated, padding included (F16). One count found no failure on 544 of 544 windows of a public model's 4-bit weights (F17). Audit protocol handles the case.

## Network Exposure

Engine listens on `127.0.0.1` only. A reverse proxy on the engine host terminates mTLS from the gateway's client certificate and allows exactly `POST /v1/completions` and `GET /health`. Routes closed at proxy (F19):

- `/metrics` (answers without API key)
- `/invocations` (answers without API key)
- `/generative_scoring` (answers without API key)
- All other admin endpoints

The proxy allows one connection.

## Hardware Requirements

From F22:
- 1 × H100 80 GB GPU
- ≥ 238 GB free host memory
- 36 GB GPU memory peak
- ≥ 300 GB local disk
- Start-up time: 22 to 25 minutes with tensor verification
- Decode speed: 0.60 to 0.62 s per token after 3-token prompt

## Related Specifications

- `facts-register.md`: F14-F22 (engine configuration and performance)
- `parameters.md`: Engine parameters
- `hardening.md`: Security configuration
- `gateway-api.md`: Request format from gateway
