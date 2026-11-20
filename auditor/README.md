# Auditor

Challenge orchestration and proof verification service.

## Purpose

The auditor accepts challenges from clients, runs automated sampling using drand beacon, requests proofs from the prover, verifies them with `cp_verify`, and publishes signed verdicts.

## Specifications

- `specs/audit-protocol.md`: Complete challenge and proof protocol
- `specs/sampling.md`: Beacon selection and escrow timeline

## Key Invariants

From spec § 10:

1. **Receipt verification first**: Verify log signature and recompute commitment before requesting proof
2. **Escrow window**: Accept challenges if within escrow + 72 hours
3. **Rate limits**: 10/hour per holder key, 3/day per transcript
4. **Verdict signature**: Ed25519 over `"AuditVerdict" || challenge_id || t || verdict || verified_at`

## Challenge Flow

From spec § 10.1:

1. Client submits (t, x, y)
2. Auditor fetches receipt from log, verifies
3. Auditor recomputes commitment, confirms match
4. Auditor requests conformance or deviation proof
5. Prover generates proof (~58.8 s, F23)
6. Auditor verifies with `cp_verify` (~21 s, F26)
7. Auditor publishes signed verdict

## Automated Sampling

From spec § 10.5:

- Fetch STH every 60 seconds
- For each receipt past escrow + 10 minutes:
  - Fetch beacon signature
  - Compute selection (k mod N)
  - Submit challenge if selected

## Testing

```bash
cd auditor/
pytest tests/ -v
```

## Related Specifications

- `specs/verifier-kit.md`: Exit codes and verification procedure
- `specs/facts-register.md`: F23, F26, F30-F33 (performance and soundness)
