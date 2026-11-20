# Gateway API

## Overview

OpenAI-compatible HTTP API from specification section 5, restricted to greedy-only inference with cryptographic receipts.

## Endpoints

| Method and Path | Purpose |
|---|---|
| `POST /v1/chat/completions` | Chat, rendered by the gateway |
| `POST /v1/completions` | Raw token IDs in `prompt` (render profile `raw-ids/1`) |
| `GET /v1/models` | OpenAI model list |
| `GET /router/models` | Provider feed for Mode R (router integration) |
| `GET /.well-known/vig.json` | Service descriptor: commitment ID, render profile digest and files, E, T, max_tokens_cap, sampling rate, key IDs and public keys, log ID, beacon chain hash, URLs of LG, PK, CH, AU |

Every other path answers 404. TLS terminates at the gateway. Mode D clients authenticate with bearer API keys; Mode R uses one key per router.

## Request Policy

Accepted fields of `POST /v1/chat/completions`, with the only values accepted:

| Field | Accepted Values |
|---|---|
| `model` | The served model name |
| `messages` | 1 or more; roles `system` (first only), `user`, `assistant`; `content` a string, or a list of `{"type":"text","text":...}` parts that GW joins with no separator |
| `max_tokens`, `max_completion_tokens` | Integer 1 to `max_tokens_cap` (256); default 256; must satisfy `P + max_tokens ≤ T` |
| `temperature` | Absent or 0 |
| `top_p` | Absent or 1 |
| `top_k` | Absent, 0 or -1 |
| `frequency_penalty`, `presence_penalty` | Absent or 0 |
| `repetition_penalty` | Absent or 1 |
| `n` | Absent or 1 |
| `seed` | Any integer (ignored: decoding is greedy) |
| `stream`, `stream_options.include_usage` | Boolean |
| `user` | String, not logged |

Any other field, or any accepted field with another value, gets 400 with `error.code = "unsupported_parameter"` and the field name.

This is stricter than FlashProve's middleware, which serves such requests and marks them unprovable (F39): on this endpoint every reply that is served MUST be provable in principle.

The engine request that GW builds sets no field beyond `model`, `prompt` (token IDs), `max_tokens`, `temperature: 0`, `return_token_ids: true` and `stream`; in particular none of the fields that force tokens (`allowed_token_ids`, `bad_words`, `min_tokens`, structured outputs, `logit_bias`, beam search) (F18).

## Errors

| HTTP | `error.code` | When | Receipt |
|---|---|---|---|
| 400 | `unsupported_parameter`, `unsupported_content`, `context_too_long` | Policy violation | None |
| 429 | `queue_full` | More than `Q_max` waiting; `Retry-After` set | None |
| 502 | `unwarranted_reply` | Engine logged a range failure or a forced token for this request; or `y` violates the end rule | None |
| 503 | `engine_unavailable` | Engine down, starting (22 to 25 minutes per F22) or failed its float64 check | None |

A reply without a receipt is outside the guarantee. The gateway MUST NOT return a 200 completion without a receipt.

## Response Format

The completion is OpenAI-compatible. `choices[0].finish_reason` is `stop` when `y` ends in E and `length` when `R = max_tokens`. The gateway adds a top-level object, and also the header `x-vig-receipt: <base64url of the receipt>` (Mode D):

```json
{
  "id": "chatcmpl-123",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "maverick-int",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "Hello! How can I help you today?"
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 211,
    "completion_tokens": 87,
    "total_tokens": 298
  },
  "verification": {
    "version": "vig/1",
    "receipt": {
      "log_id": "<32-byte hex>",
      "endpoint_id": "maverick-int-c7982f8a",
      "request_id": "<uuid>",
      "served_at": "2026-11-20T10:15:03.412Z",
      "commitment_id": "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
      "render_profile": "<32-byte hex>",
      "params_digest": "<32-byte hex>",
      "salt": "<32-byte hex>",
      "transcript_commitment": "<t, 32-byte hex>",
      "leaf_hash": "<32-byte hex>",
      "beacon_round": 21734890,
      "promise_sig": "<Ed25519 signature by the log key>"
    },
    "prompt_token_ids": [200000, ...],
    "reply_token_ids": [...],
    "pickup_id": "<32-byte hex>"
  }
}
```

With `stream: true`, text deltas are decoded incrementally from `y`, SSE comment lines are sent as keep-alives while the engine works, and `verification` arrives in the last data event before `[DONE]`. If the reply turns out unwarranted after deltas were sent, the last event carries `verification: {"status": "unwarranted"}` and no receipt.

## Service Descriptor

`GET /.well-known/vig.json`:

```json
{
  "version": "vig/1",
  "commitment_id": "c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46",
  "model": "llama-4-maverick-int",
  "window": 1024,
  "end_tokens": [200001, 200007, 200008],
  "max_tokens_cap": 256,
  "sampling_rate": {"live": 20, "shadow": 1000},
  "render_profile": {
    "digest": "<32-byte hex>",
    "profile": "llama4-chat/1",
    "tokenizer_json_url": "https://...",
    "tokenizer_config_url": "https://...",
    "tokenizer_json_sha256": "172c9eb4...23a4",
    "tokenizer_config_sha256": "2c56f1b6...425d"
  },
  "log": {
    "log_id": "<32-byte hex>",
    "log_key_id": "log-key-1",
    "log_public_key": "<Ed25519 public key>",
    "url": "https://.../log/v1/"
  },
  "beacon": {
    "chain": "quicknet",
    "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "url": "https://api.drand.sh"
  },
  "pickup_url": "https://.../receipts/v1/pickup/",
  "challenge_url": "https://.../audit/v1/challenges",
  "audit_url": "https://.../audit/v1/",
  "auditor_key_id": "auditor-key-1",
  "auditor_public_key": "<Ed25519 public key>"
}
```

## Mode D (Direct Client)

Client sends request to gateway directly:
1. Authenticate with bearer API key
2. Receive reply with `verification` object in response
3. Receive `x-vig-receipt` header
4. Keep transcript and receipt for challenges

## Mode R (Router)

Router lists gateway as provider endpoint:

1. **Router feed**: `GET /router/models` returns:
```json
{
  "models": [{
    "id": "llama-4-maverick-int",
    "quantization": "int4",
    "max_context_length": 1024,
    "max_length": 256,
    "supported_parameters": ["max_tokens", "temperature", "stream", "seed"],
    "description": "Llama 4 Maverick 17B integer model. Greedy decoding only (temperature=0). Proofs on 1/20 requests. See [verification URL]"
  }]
}
```

2. **Receipt delivery**: `verification` field and header when forwarded by router; otherwise sealed pickup

3. **Rendering**: Gateway renders; router sends `messages`

4. **Timeouts**: Streaming with keep-alives; `max_tokens ≤ 256` keeps decoding under about 2.6 minutes

## Related Specifications

- `canonical-rendering.md`: Render profile and algorithm
- `receipt-log.md`: Receipt format and log API
- `parameters.md`: max_tokens_cap, Q_max, request policy values
- `router-integration.md`: Mode R details
