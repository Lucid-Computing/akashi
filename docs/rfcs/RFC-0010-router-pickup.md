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

`seal(bundle, original_chat, budget, reply_text, holder_secret) -> (pickup_id, envelope)`; `open(envelope, holder_secret, original_chat, budget, reply_text) -> Verification`. Compute `k = SHA256("akashi/pickup/v1" || holder_secret || frame(JCS(messages)) || u32le(budget) || frame(UTF8(reply_text)))` and `pickup_id = SHA256("id" || k)`. Derive the encryption key as HKDF-SHA256 with absent salt, info `enc` and 32 output bytes. Carry the 32-byte secret in the existing user field as `akashi-pickup/1:<64 lowercase hex digits>`; forward unchanged without echoing or logging it. Encrypt canonical JSON verification with XChaCha20-Poly1305 and a fresh random 24-byte nonce. The response is `{version:"akashi-pickup/1", nonce:hex, ciphertext:hex}`, with the tag appended to ciphertext and associated data equal to UTF-8 version bytes followed by the raw lookup digest. Return only ciphertext by pickup ID, expire after W_pickup and verify the recovered receipt independently. Keep router messages, budget and secret unchanged. SSE comments carry no evidence; a single terminal verification controls status before DONE. Buffer unless verified prefix-stable display deltas can be emitted.

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
