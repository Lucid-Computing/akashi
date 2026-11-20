# RFC-0006: Build and verify exact proof statements

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M2

## Summary

Byte-identical statements link stored replies to the pinned proof runtime.

## Motivation

A proof can only support a verdict for the statement the holder independently reconstructs. See [canonical specification](../spec/06-security.md#trust-and-evidence).

## Goals

- Verify exact statements with one holder's request per batch.

## Non-Goals

- Prove cross-holder batches or pretend job failures identify a cause.

## Proposed Design

`build_statement(transcript: Transcript, divergence: Divergence | None) -> Statement`. Write exactly T little-endian u32 tokens, then r and e using the pinned request format; for a submitted request append the 32-byte nonce. Use r=P−1 and e=P+len(y)−1; fill the rest with z. For a deviation, locate the first different argmax on the served prefix, replace the token at that position and prove the actual prefix through the replacement. Require comparison to the original receipted token and full reconstruction by the verifier. Submit atomically once per durable job and collect spool output with deadline and graceful stop. Verify positional invocation and exits from facts F8–F9 against the pinned key and commitment. Spool failure alone implies unavailable; independent range evidence outside served positions can classify EXCUSED_RANGE. Keep range evidence private and do not turn it into a deviation proof.

## Alternatives Considered

Use an engine-reported mismatch or proof success marker as evidence. Neither validates the statement at the trust boundary.

## Drawbacks

Scoring and independent verification add work; padding can prevent proof even for a complete reply.

## Migration / Rollout

Use the same request builder for the M0 measurements and M1 mock gate; promote the real worker by M2.

## Testing Strategy

Compare bytes against the pinned tool, then test wrong commitment, incomplete status, timeout, clean shutdown and independently checked first divergence.

## Open Questions

Proof owner measures OQ5 at M0. Privacy owner records OQ6 before M2 promotion; retain single-request batches for v1 regardless.

## References

- [Canonical specification](../spec/06-security.md#trust-and-evidence)
- [Source contract](../../specs/audit-protocol.md#proof-types)
- [RFC index](README.md#accepted-decisions)
