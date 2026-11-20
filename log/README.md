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

## Testing

```bash
cd log/
pytest tests/ -v
```

## Related Specifications

- `specs/sampling.md`: Beacon round determination
- `specs/audit-protocol.md`: Auditor log queries
- `specs/verifier-kit.md`: Client verification procedure
