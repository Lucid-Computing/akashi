# Receipt Log

## Overview

Append-only Merkle tree log of transcript commitments with cryptographically signed tree heads from specification section 9.

## Receipt Format

Every warranted reply carries a receipt binding the transcript into the public log:

```json
{
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
}
```

## Transcript Commitment

Computed by the gateway before serving the reply:

```
t = SHA-256(C || R || H_params || salt || x || y)
```

Where:
- `C` = commitment ID (32 bytes)
- `R` = render profile digest (32 bytes)
- `H_params` = SHA-256 of `max_tokens` as 4-byte little-endian (32 bytes)
- `salt` = 32 random bytes
- `x` = prompt token IDs (P × 4 bytes, little-endian)
- `y` = reply token IDs (R × 4 bytes, little-endian)

This binding includes the integer model state, render profile, request parameters, and actual tokens (F28).

## Leaf Hash

The Merkle tree leaf combines the transcript commitment with metadata:

```
leaf_hash = SHA-256(
  commitment_id || 
  render_profile || 
  params_digest || 
  salt || 
  transcript_commitment || 
  8-byte big-endian beacon_round || 
  served_at as RFC3339 bytes
)
```

## Promise Signature

Ed25519 signature by the log service's private key over:

```
"PromiseReceipt" || log_id || leaf_hash
```

The gateway verifies this signature before serving the reply. An invalid signature causes 500 with no receipt.

## Merkle Tree

RFC 6962 append-only binary Merkle tree with SHA-256:

```
MTH({})         = SHA-256("")
MTH({leaf₀})    = SHA-256(0x00 || leaf₀)
MTH({leaf₀...leafₙ}) = SHA-256(0x01 || MTH(left) || MTH(right))
```

Tree size `N` grows monotonically. Each leaf index is permanent.

## Signed Tree Head (STH)

Periodic commitment to the tree state, signed by the log key:

```json
{
  "version": "vig-log/1",
  "log_id": "<32-byte hex>",
  "tree_size": 123456,
  "timestamp": "2026-11-20T10:20:00.000Z",
  "root_hash": "<32-byte hex>",
  "signature": "<Ed25519 signature>"
}
```

Signature over:
```
"STH" || log_id || 8-byte big-endian tree_size || timestamp as RFC3339 bytes || root_hash
```

STH published every 60 seconds and after every write, so clients polling at 1 Hz see receipts within 2 seconds (F29).

## Log API

All endpoints under `/log/v1/`:

### `GET /sth`

Returns the latest signed tree head. The implementation also accepts the proposed `size` query parameter to retrieve the latest signed checkpoint at a historical size. Include `log_key_id` alongside `size` to retrieve a checkpoint signed by a specific historical writer. The response includes the signing key ID for archived-key verification.

### `POST /promise`

An authenticated gateway submits the canonical public leaf fields described in the [binding invariants](../docs/spec/03-data-model.md#binding-invariants). The log recomputes the leaf hash and rejects private fields. A successful append returns that public metadata, the permanent zero-based leaf index, the leaf hash and the Ed25519 promise signature. The gateway retains the private salt and verifies the promise before delivery.

Retrying the same bound request returns its original promise. Reusing the request ID with different metadata returns a conflict. The public leaf, tree nodes, promise and signed head commit in the same SQLite transaction. [RFC-0004](../docs/rfcs/RFC-0004-receipt-transparency.md#proposed-design)

### `GET /receipts/{leaf_index}`

Returns the public leaf at the zero-based index, or 404. The salt and holder promise signature stay outside public reads.

### `GET /receipts/range?start={s}&end={e}`

Returns receipts for leaf indices `[s, e)`, up to 10,000 per call.

### `GET /proof/{leaf_index}`

Returns the audit path to the current root. The optional proposed `size` query parameter selects a historical root. The response identifies the tree size used.

```json
{
  "leaf_index": 42,
  "tree_size": 123456,
  "audit_path": ["<32-byte hex>", ...]
}
```

Client verifies by recomputing MTH and checking against STH.

### `GET /consistency?from={old_size}&to={new_size}`

The response identifies both requested tree sizes and returns the RFC 6962 consistency path. The proposed JSON field names are `from`, `to` and `consistency_path`.

### Running the log

Construct `log.store.MerkleLog` with a dedicated database, operator-provisioned Ed25519 signing key, log identity, key ID, and the canonical `log.receipt.leaf_hash` function. Run one supervised `log.http.run_checkpoints(log, stop_event)` task for the log and mount `log.http.LogApp(log, gateway_identity=...)` behind the authenticating service front end. Configure that front end to set WSGI `REMOTE_USER` from its verified client principal. Keep the database and private signing material on operator-controlled storage.

Run `make test-merkle-log` from the repository root. The tests exercise proof vectors, concurrent appends, rollback, replay, authenticated writes and historical reads.

## Sealed Pickup (Mode R)

The pickup service returns a sealed envelope by its opaque `pickup_id`. The holder derives the digest from their secret and the original exchange, opens the envelope, and verifies the recovered receipt against the trusted log identity and key. The [sealed pickup byte contract](retention.md#sealed-pickup) specifies the inputs and encoding.

## Retention

From `retention.md`:

| Data | Retention | Purpose |
|---|---|---|---|
| Receipts in log | 5 years | Proof of inclusion, challenges |
| Leaf hashes in tree | Permanent | Tree integrity |
| Sealed pickup packages | 7 days (`W_pickup`) | Router receipt delivery |
| STH history | 5 years | Tree consistency verification |

## Security Properties

- **S1 (Binding)**: Transcript commitment cryptographically binds C, R, params, salt, x, y
- **S3 (Non-omission)**: Every receipted reply enters the log; transparency allows public verification
- **S5 (Accountable failure)**: If log is compromised, the provider can prove it with an inconsistent STH

## Related Specifications

- `gateway-api.md`: Receipt delivery in response
- `sampling.md`: beacon_round determination
- `audit-protocol.md`: Log queries for challenges
- `facts-register.md`: F28-F29 (commitment and STH timing)
