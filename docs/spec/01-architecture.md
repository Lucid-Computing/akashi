# Architecture

## Service boundaries

| Component | Input → output | Owner and durable state |
|---|---|---|
| Renderer | Message sequence → token IDs | Gateway and verifier share pinned profile artifacts |
| Gateway | Validated request → receipt-bearing completion or typed failure | Gateway operator owns admission, transcript assembly and delivery |
| Engine | Token IDs and budget → token IDs and integrity status | Provider owns weights, gates and serialized engine execution |
| Log | Validated receipt preimage → signed promise and indexed leaf | Gateway operator maintains durable append-only history |
| Sampler and escrow | Signed log history, verified beacon, transient transcript → selection or gap | Gateway operator stores encrypted escrow and tracks rounds |
| Auditor and prover | Challenge or selected job → signed verdict and capability-protected proof | Auditor owns job transitions and proof artifacts |
| Verifier | Holder bundle and trusted descriptor → receipt checks and proof verdict | Holder owns transcript and trusted checkpoints |
| Router and pickup | Forwarded chat and sealed envelope → recoverable receipt | Router owns forwarding, gateway owns ciphertext TTL |

## Delivery order

Validate and reserve admission before rendering or dispatch work. Within one engine execution slot, record the integrity window and validate the final tokens. Persist escrow before appending the public leaf. For an opted-in pickup, reserve its lookup ID against the same leaf and expiry before append. Verify the returned promise, then seal the complete verification object and durably publish its ciphertext under the reservation before releasing terminal verification. The envelope contains the log signature produced by the append. A failure after append can leave an auditable undelivered promise. Monitor and sample such entries normally. A repeated submission is a new inference request. Internal retries preserve the original commit identity. Engine, log and gateway failure paths live in [the error contract](04-error-model.md#failure-contract).

Audit observes signed history and verifies the fixed round before evaluating selection. The auditor validates holder material, dispatches the proof worker and persists the verdict and evidence before publication. The holder can independently repeat verification on a CPU. See the original [architecture flow](../../specs/architecture.md#data-flow).
