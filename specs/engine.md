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

## Provider adapter

Supply a `LaunchConfig` with the real rebuild report and fitted work directory, the prepared model and independent loader reference directory, the pinned FlashProve checkout, the serving Python environment, private home and temporary directories, an operator-provisioned canary file and a shutdown grace period. Export only the public fit configuration and verification-key artifacts to the engine account. Bind the measured dtype to the same F4 commitment in the canary file. Record three distinct prompt vectors, their budgets and their M0-proved expected replies. Keep the model read-only and run under the provider service account.

On the provider, enter `engine.service.observe_engine(config, ...)` and read `evidence, canaries = observation.startup()`. Keep the context open while serving. The pinned vLLM launcher binds the loopback listener before loading the model. Only the new child's two loader messages satisfy this startup. Configure the startup deadline, health polling interval, log checkpoint timeout and maximum log-line size on the host.

The private control channel proposed by this adapter exposes the startup evidence, public canaries and log-window boundaries. In the provider context, start `engine.control.ControlServer` with the service socket path, authorized gateway UID and GID, control timeout, `evidence.instance`, `lambda: observation.startup()[0]`, the canaries, and the observation's `begin` and `finish` methods. Provision a provider-owned socket directory with mode `2750` and the gateway group. The gateway connects with `ControlClient` configured with the provider UID. Each side checks its peer's operating-system identity. This Unix socket supports co-located service accounts. A split-host deployment requires an authenticated private relay that preserves these identities and the request boundaries.

On the gateway, construct `EngineClient` with the private mTLS proxy host and port, model name, server CA, gateway certificate and key, request margin and response-size limit. Call `engine.service.attach_engine(client, control_client, ...)` to check health and run the three canaries. The gateway alone holds its TLS key. The client buffers the greedy reply and checks the echoed prompt token IDs before returning tokens.

The provider drains the current process's own stdout/stderr pipe at both request boundaries. This requires synchronous plugin logging to that pipe before token emission, as in the pinned model plugin. An asynchronous collector needs its own acknowledged post-request barrier. Preserve the one-sequence launch and the authenticated engine route. Missing coverage, cancellation or an invalid reply quarantines the adapter. A supervisor may reopen the slot only after a clean, complete window covering the interrupted work, or a fresh measured startup.

Run `make test-engine` for CPU gate, process and transport fixtures. Real startup and proof evidence belongs in the [M0 gate](build-plan.md#m0-bring-up). The [pinned completion schema](https://github.com/vllm-project/vllm/blob/v0.29.0/vllm/entrypoints/openai/completion/protocol.py) describes the token ID response fields.

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

On 2026-11-20, Lucid H100 allocation 7292 ran the production supervisor and gateway
attachment at engine revision `79247c9425e46ea5b1da1ee5e87e1af8930ff46a`.
The F4 rebuild supplied the reference files. All 51 GPU arithmetic cases passed
and the supervisor observed both verification messages from the launched child.
Three whole-reply goldens had already passed FlashProve's native verifier on a
separate CPU host. The gateway replayed all three through its mutually authenticated
proxy. From entry into the provider supervisor through completion of the third
canary, 1,294.165 seconds elapsed. The same process then closed integrity windows
for 16 greedy requests and a separate streamed completion. The stream's three
token IDs matched its nonstreaming reply. [Redacted readiness record](../engine/evidence/maverick-engine-ready.json)
