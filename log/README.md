# Receipt Log

Append-only RFC 6962 Merkle tree log of transcript commitments with Ed25519-signed tree heads.

## Purpose

The log provides tamper-evident storage of all receipted replies, enabling public verification of receipt inclusion and detection of omitted requests.

## Specifications

- `specs/receipt-log.md`: Complete log specification (receipt format, Merkle tree, STH, API)
- `specs/retention.md`: Data retention policies

## Key Invariants

From spec § 9:

1. **Append-only**: No deletion or modification of receipts
2. **Atomic appends**: Tree size increments by exactly 1 per promise
3. **STH publication**: Every 60 seconds and after every write (F29)
4. **Promise signature**: Ed25519 over `"PromiseReceipt" || log_id || leaf_hash`

## Receipt Format

From spec § 9.1, contains:
- Transcript commitment `t`
- Beacon round for selection
- Log promise signature
- Leaf hash (includes metadata)

## API Endpoints

From spec § 9.3:

- `GET /sth` - Latest signed tree head
- `POST /promise` - Append receipt (gateway-only)
- `GET /receipts/{leaf_index}` - Receipt at index
- `GET /proof/{leaf_index}` - Merkle audit path
- `GET /consistency?from={old}&to={new}` - Consistency proof

## Validate receipt bytes

Run `make test-receipts` from the repository root. The target installs the
locked Ed25519 implementation and checks fixed commitment, leaf and promise
vectors. The holder recomputes the framed transcript commitment with the
private salt. Public readers can reconstruct the leaf and check the promise
using their trusted log identity and verification key.
[Wire types and binding rules](../docs/spec/03-data-model.md#binding-invariants)

## Related Specifications

- `specs/sampling.md`: Beacon round determination
- `specs/audit-protocol.md`: Auditor log queries
- `specs/verifier-kit.md`: Client verification procedure

## Independent monitor

Run `log.monitor.LogMonitor` under the monitor's own account with a persistent database, a trusted log ID and the archived log verification keys. Pass `PublicKeyArchive.lookup` as `lookup_key`. Give `hold` a signed holder receipt. It verifies the promise and keeps only its public binding fields and signature. Configure a `log.reader.LogReader` from the trusted descriptor's HTTPS log URL with operator-selected read timeout and response-size limit. Pass that reader, a stop event, a polling interval and the operator's alert sink to `run`. Alerts are delivered at least once. A sink should deduplicate repeated evidence.

Each observation verifies the signed checkpoint, the consistency path from the previous checkpoint and the root reconstructed from the newly observed public leaves. The monitor persists the authenticated prefix transactionally. `verified_leaf(index)` and `checkpoint()` expose only that prefix. An independent observer can pass a second signed head to `observe` for comparison. A previously consistent older head leaves the trusted checkpoint in place.

After the ten-second merge deadline, an absent promise in a fully observed, post-deadline signed tree produces an omission alert with both log signatures. A stale or inaccessible checkpoint produces a coverage alert. An invalid unsigned consistency response is recorded as a failed check alongside the two signed heads. Independent reviewers can reproduce an observed absence from the retained leaf history. Isolated readers depend on exchanging checkpoints to discover split views. [Receipt transparency contract](../docs/rfcs/RFC-0004-receipt-transparency.md#proposed-design)

Run `make test-log-monitor` for signed-head and RFC 6962 vectors, restart persistence, clock boundaries and a TLS connection to the log server.
