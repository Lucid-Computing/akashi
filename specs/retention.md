# Data Retention and Privacy

## Retention Policy

From specification section 12:

| Data | Location | Retention Period | Visible To |
|------|----------|------------------|------------|
| `messages`, `x`, `y` (unselected) | ES (transcript escrow) | Until beacon round verified, max 5 minutes | Gateway operator |
| Selected transcripts | CH (challenge service) | 30 days after verdict | Auditor |
| Sealed receipts | PK (pickup store) | 7 days | Anyone holding the transcript |
| Log leaves, STHs | LG (receipt log) | Permanent | Public |
| Verdicts (no content) | AU (audit API) | Permanent | Public |
| Proofs, statements | CH | 30 days | The transcript's holder (with capability token) |
| Engine logs | Engine host | 7 days, no request content at INFO level | Provider |

## Privacy Properties

### Transcript Confidentiality (S6)

The public log and audit API reveal no prompt or reply content. Transcripts reach only:

1. **Gateway operator** (briefly, seconds to minutes during escrow)
2. **Auditor** (if selected or challenged, for 30 days)
3. **Holder** (indefinitely, they created it)

### Receipt Contents

Receipts contain:
- Transcript commitment `t` (SHA-256 hash with 32-byte salt)
- Metadata: endpoint, request ID, timestamp
- Beacon round number
- Log proof

Receipts do NOT contain:
- Prompt text or tokens
- Reply text or tokens  
- User identifiers (beyond request ID)

The salt in `t` makes it hiding: the public log does not let anyone test guesses at a prompt.

### Escrow Deletion

Unselected transcripts are deleted after beacon round verification:
- Overwrite the record
- Drop the key slot
- Maximum lifetime: `W_escrow` = 5 minutes hard cap

If beacon unavailable, transcripts wait; the hard cap ends in deletion and an `escrow_expired` log record, reported by audit API as a gap (never as a pass).

### Sealed Pickup

For holders who lose the receipt, sealed pickup provides recovery without revealing content to the gateway operator:

```
k = SHA-256("vig/pickup/v1" || JCS(messages) || u32le(max_tokens) || UTF-8(reply_text))
pickup_id = SHA-256("id" || k)
blob = XChaCha20-Poly1305(key=HKDF-SHA256(k, info="enc"), plaintext=JCS(verification))
```

The store holds `(pickup_id, blob)` with:
- No plaintext receipt
- Key derivable only from the transcript
- Blob encrypted with key derived from transcript

Fetch: `GET /receipts/v1/pickup/{pickup_id}` returns blob; holder decrypts with their own `k`.

## Proof Sensitivity

From fact F40:

> A proof file is as sensitive as its request.

A proof lets its holder test guesses at the whole request. Therefore:

- Proofs are released only to the holder of the transcript
- Challenge API returns proof only with capability token from submission
- Audit API publishes verdicts (no proof, no transcript)
- Proofs are NOT published to third parties

## Log Pruning

The Merkle log is append-only and permanent. Leaf data contains only:
- Endpoint ID
- Served timestamp
- Transcript commitment `t` (hashed)
- Beacon round

No pruning is performed. Storage grows linearly with request count (~100 bytes per request).

## Compliance Considerations

### Data Subject Rights

For requests about specific users:
- Gateway operator can identify receipts by endpoint/time but not by content
- Auditor can identify selected transcripts within 30-day window
- After retention periods, transcripts are deleted

### Legal Holds

If retention beyond 30 days is required:
- Holder keeps their own transcript
- Audit API keeps verdicts permanently
- Proofs can be regenerated if transcript is available (within commitment's validity)

### Cross-Border Data

Transcripts transit the gateway and (if selected) the auditor. Deploy components in appropriate jurisdictions for compliance.

## Monitoring

Retention compliance metrics:

- `vig_escrow_age_seconds`: Age of oldest transcript in escrow (alert if > 300s)
- `vig_challenge_age_days`: Age of oldest challenged transcript (alert if > 30d)
- `vig_pickup_age_days`: Age of oldest sealed receipt (alert if > 7d)
- `vig_escrow_expired_total`: Count of transcripts expired before beacon (should be 0)

## Related Specifications

- `guarantee.md`: S6 (transcript confidentiality)
- `receipt-log.md`: What is logged publicly
- `sampling.md`: Escrow operation
- `audit-protocol.md`: Challenge retention
