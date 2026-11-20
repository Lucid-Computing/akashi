# Gateway

OpenAI-compatible HTTP API with strict greedy-only policy and cryptographic receipts.

## Purpose

The gateway enforces the verified inference guarantee by accepting only greedy-decodable requests (temperature=0) and generating cryptographic receipts binding every warranted reply.

## Specifications

- `specs/gateway-api.md`: Complete API specification (endpoints, request policy, errors, response format)
- `specs/canonical-rendering.md`: Tokenization and chat templates
- `specs/engine.md`: Engine integration and integrity monitoring

## Key Invariants

From spec § 5:

1. **Greedy-only**: Reject any request with temperature ≠ 0, top_p ≠ 1, or sampling parameters
2. **No receipt = no 200**: MUST NOT return 200 completion without valid receipt
3. **Unwarranted detection**: Return 502 if engine logs ERROR or warning during request window
4. **Window constraint**: Enforce P + max_tokens ≤ T = 1024

## Configuration

From `specs/parameters.md` and `specs/engine.md`:

```bash
ENGINE_URL=http://127.0.0.1:8000
LOG_URL=https://log.example.com/log/v1/
COMMITMENT_ID=c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46
TOKENIZER_PATH=/path/to/tokenizer/
```

## Canonical rendering

Supply the two tokenizer files from the F37 revision to `ChatRenderer`. The
renderer verifies both SHA-256 digests before compiling the packaged template
and loading the tokenizer. It joins text parts without a separator. User and
assistant text retain their whitespace. The template trims the system message.
The chat gate requires exactly one BOS, so a literal marker that produces a
second BOS is rejected. Raw requests preserve the original IDs and have null
display text. [Canonical rendering contract](../docs/rfcs/RFC-0002-canonical-rendering.md#proposed-design)

Run `make test-renderer` at the repository root. The gate downloads the two
pinned public files into a temporary directory. For offline runs, set
`VIG_RENDER_ASSETS` to the directory containing `tokenizer.json` and
`tokenizer_config.json` before invoking Make.
[Pinned assets](https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/tree/86c5ecb6f2fbddf604c60120125fb202e09f2556)

## Related Specifications

- `specs/parameters.md`: T, max_tokens_cap, Q_max
- `specs/receipt-log.md`: Receipt format and promise protocol
- `specs/hardening.md`: Security configuration

## Request validation

Run `make test-request-policy` from the repository root. The gateway validates
bearer authentication and the configured body limit before rendering, checks the
greedy-only allowlist, and resolves both budget aliases to one token count.
Only the normalized engine fields proceed to dispatch.
[Request policy](../specs/gateway-api.md#request-policy) · [Failure contract](../docs/spec/04-error-model.md#failure-contract)

## Model discovery

Mount `gateway.discovery.DiscoveryApp(config)` in the gateway WSGI stack.
`GET /v1/models` returns the operator's model name, owner and creation time.
`GET /.well-known/vig.json` publishes the window, token cap, commitment,
render profiles, beacon chain, public verification identities and service
addresses. Use the same `ServiceConfig` for request admission so the served
model name and limit agree with the descriptor.

The descriptor retains the chat `render_profile` object. The proposed additive
`render_profiles` list also identifies `raw-ids/1` and its digest. Configure
public verification keys and service URLs at deployment. Check the discovery
routes with `make test-discovery`.
[Descriptor fields](../specs/gateway-api.md#service-descriptor) · [Raw profile](../specs/canonical-rendering.md#raw-ids1)
