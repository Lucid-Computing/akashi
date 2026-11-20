# RFC-0010: Recover warranted replies through opaque routers

- Status: Accepted
- Authors: Specification contributors (maintainer review @AbdelStark)
- Created: 2026-11-20
- Target milestone: M4

## Summary

Mode R recovers holder evidence when response extensions are stripped.

## Motivation

The router can remove verification fields, add decoding defaults or rewrite the input the holder needs. See [canonical specification](../spec/02-public-api.md#interfaces).

## Goals

- Support recovery without treating a completion ID as a credential.

## Non-Goals

- Support rewriting routers or deploy a router-side proof trust service.

## Proposed Design

`seal(bundle, original_chat, budget, reply_text, holder_secret) -> (pickup_id, envelope)`; `open(envelope, holder_secret, original_chat, budget, reply_text) -> Verification`. Use the retention spec transcript-derived KDF with an explicit 32-byte holder secret mixed into k after the domain tag, followed by canonical chat JSON and the framed UTF-8 reply. Carry the secret as an opt-in namespaced value in the existing user string, forwarded unchanged; never echo or log it. Use a fresh random 24-byte nonce, include it in the envelope and authenticate the version and lookup digest as associated data. Return only ciphertext by pickup ID, expire after W_pickup and verify the recovered receipt independently. Keep router messages, budget and secret unchanged. SSE comments carry no evidence; a single terminal verification controls status before DONE. Buffer unless verified prefix-stable display deltas can be emitted.

## Alternatives Considered

Use a completion ID or transcript text alone as the lookup credential. Both are easier to integrate, but text can have low entropy and IDs may be routed or recorded.

## Drawbacks

Sealed recovery requires explicit holder opt-in and a forwarding-compatible router. Routers already see holder inputs.

## Migration / Rollout

Run direct and transparent flows first; advertise recovery only on tested routes.

## Testing Strategy

Strip response extensions in the integration fixture and recover with original holder inputs; wrong secret and expiry must fail. Record real forward behavior and the third-party soak.

## Open Questions

Router owner checks OQ3 and OQ4 during M4 integration; operations owner measures OQ8 during soak.

## References

- [Canonical specification](../spec/02-public-api.md#interfaces)
- [Source contract](../../specs/retention.md#sealed-pickup)
- [RFC index](README.md#accepted-decisions)
