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

## Warranted delivery

The gateway prepares one delivery attempt after validating the complete token reply. The attempt freezes its UUID, salt, original input, UTC serving timestamp and future beacon round. Internal append retries reuse this attempt. A new client submission starts a new inference. The escrow payload contains the salt, budget, token vectors, reply text and original chat messages where applicable. The public log receives only the bound leaf fields.

For opted-in chat, the pickup writer durably reserves the lookup ID, leaf hash and absolute expiry before append. After verifying the exact returned leaf and its Ed25519 promise, the gateway seals the signed verification and waits for durable publication. The writer must tolerate a repeated reservation or publication for the same leaf and expiry, preserve the first successfully stored envelope and reject conflicting bindings. The lookup expires seven days after the original serving timestamp. The caller checks cancellation, the request deadline and the unopened beacon round at terminal release. Crashes can leave a signed leaf without a delivered response. [Delivery order](../docs/spec/01-architecture.md#delivery-order) · [Sealed pickup](../docs/rfcs/RFC-0010-router-pickup.md#proposed-design)

## Direct buffered inference

Mount `gateway.http.ServingApp` behind the deployment's TLS ingress. Configure one `Serving` coordinator per engine with the discovery descriptor, pinned chat renderer, engine adapter, delivery committer and bearer-key validator. The same app serves discovery and both POST routes. It enforces the configured request deadline and advertises the operator's retry interval on a full queue. One request holds the slot through delivery assembly, with up to four waiting (see `Q_max` in `specs/parameters.md`). A server that detects a disconnect can supply a `RequestControl` in the WSGI environment under `vig.request_control` and call its `cancel()` method.

A successful direct response carries the signed receipt in both `verification.receipt` and the base64url `x-vig-receipt` header. Chat uses the pinned display decoder. Raw results expose token IDs with null display text. The proposed transport error codes `request_cancelled` and `commit_failed` identify a cancelled delivery and an unverified or unavailable append. Both responses omit the receipt.

Run `make test-serving` with `VIG_RENDER_ASSETS` pointing to the pinned tokenizer and configuration. The tests exercise actual loopback HTTP, encrypted escrow and signed log storage, FIFO admission, disconnects, invalid tokens and promise failures.

## Streaming delivery

Configure `stream_heartbeat_seconds` on `ServingApp` to accept `stream: true` on chat and raw completions. Set that interval to suit the idle timeout of the deployed HTTP path. Authentication, request policy and bounded FIFO admission complete before HTTP 200 and SSE headers. While the engine runs, the gateway sends keep-alive comments. It decodes the full checked reply once, which preserves text across split Unicode token boundaries. The first data event carries provisional chat text or raw IDs. Only the final data event carries verification, followed by `[DONE]`. Requested usage is included in the final data event. The direct JSON transport keeps its original receipt header. [Gateway contract](../specs/gateway-api.md)

A worker error or expired release window produces an unwarranted terminal event without a receipt. Closing a partially read stream cancels its control and keeps the single engine slot occupied until the in-flight worker exits. Use a WSGI host that closes response iterables on disconnect and configure intervening proxies to forward SSE promptly. For direct streaming, `gateway.stream_reader.terminal_evidence(response)` requires an intact terminal verification and DONE sequence before returning the holder's evidence for independent checks. Run `make test-streaming` to exercise the HTTP and cancellation boundaries.
