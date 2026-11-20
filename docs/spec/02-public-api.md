# Public API

## Interfaces

| Interface | Request → successful result |
|---|---|
| `POST /v1/chat/completions` | [Greedy chat object](../../specs/gateway-api.md#request-policy) → completion with `verification` or SSE |
| `POST /v1/completions` | Same greedy restrictions with integer `prompt` array instead of messages → raw-ID completion with verification |
| `GET /v1/models`, `GET /router/models` | No body → listed model and constraints |
| `GET /.well-known/vig.json` | No body → [versioned descriptor](../../specs/gateway-api.md#service-descriptor) |
| `/log/v1/` | [Promise and read operations](../../specs/receipt-log.md#log-api) → promise, signed head, public leaf metadata or tree proof |
| `/audit/v1/` | [Challenge, verdict and stats operations](../../specs/audit-protocol.md#auditor-public-api) → private job status or public redacted metadata |
| `GET /receipts/v1/pickup/{pickup_id}` | Opaque identifier → authenticated ciphertext |
| `vig verify BUNDLE --descriptor FILE [--receipt-only]` | Local holder bundle and pinned descriptor → [exit status](04-error-model.md#verification-errors) |

Apply bearer authentication to inference, authenticate append writers, and authenticate holder keys at challenge intake. Return the challenge capability only to the submitter. Require it on `GET /audit/v1/challenges/{challenge_id}` for job status and `GET /audit/v1/challenges/{challenge_id}/proof` for proof and statement. Public verdict lookup by commitment, recent verdicts, selections and stats expose metadata only. Serve public selections via `GET /audit/v1/selections` keyed by leaf index and round with a cursor; status is selected, unselected, pending or gap.

## Request invariants

Reject unknown fields and non-neutral controls. The two budget aliases may coexist when equal. JSON booleans are distinct from integers. Apply the configured body limit before parsing and validate IDs against the profile vocabulary. Use `1 <= P`, `1 <= max_tokens <= max_tokens_cap`, and `P + max_tokens <= T`. Use the model name in the descriptor for inference and both discovery feeds. Unknown routes return 404.

For chat, accept only a leading system message and at least one user or assistant message. Join text parts without a separator, rejecting invalid parts. Keep the resolved budget in the holder bundle. In Mode D deliver receipt in the response and receipt header when available. In SSE every delta is provisional until terminal verification. The gateway may buffer engine output and stream after validation if upstream token IDs or prefix-stable text are unavailable. In Mode R preserve the originating messages and resolved budget through the router. See [compatibility policy](09-release-and-versioning.md#release-policy).
