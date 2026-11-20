# Sealed receipt pickup

Create a `PickupStore` in an owner-only directory and pass it as `pickup` to `gateway.commit_delivery.DeliveryCommitter`. The gateway reserves the opaque lookup ID before appending, then verifies the signed log promise and publishes the encrypted verification object. The reservation binds to the same delivery with a private retry tag. A retry keeps the original expiry and the first published ciphertext even if sealing generates a fresh nonce. [Delivery order](../docs/spec/01-architecture.md#delivery-order)

The gateway's `pickup_lifetime` defaults to the v1 seven-day `W_pickup` and can be shortened for a deployment. Pending and published records expire at the exact UTC deadline. `PickupStore.get` enforces expiry on every lookup. `sweep()` deletes expired reservations and ciphertexts and returns their count. Run it from the private retention job even when traffic is idle. The database retains a clock high-water mark across restarts so a wall-clock rollback cannot reopen an expired record. [Retention policy](../specs/retention.md#sealed-pickup)

## Read service

Mount `PickupApp(store, limiter=PerIPLimit(...))` at `GET /receipts/v1/pickup/{pickup_id}`. The response contains only the envelope version, nonce and authenticated ciphertext. Absent, pending, expired and malformed IDs share the missing response. All responses disable caching. The per-IP request count, interval and peer capacity are deployment settings. The rolling limiter is local to one service process and uses the socket peer address reported by the server. Size multi-process deployments at their shared ingress. A normal reverse proxy appears as a single peer, so configure per-client limiting at that edge when applicable. Keep full pickup paths and query strings out of access logs, tracing and error handling. The supplied `make_pickup_server` starts a quiet loopback-compatible WSGI host. [Operations contract](../docs/rfcs/RFC-0009-operational-controls.md)

The holder opens an envelope using its original messages, resolved budget, displayed reply and fresh holder secret. It verifies the signed receipt using the key ID in that receipt. New holder secrets derive different pickup IDs, and existing ciphertext remains retrievable under its original ID until expiry. [Wire encoding](../docs/rfcs/RFC-0010-router-pickup.md#proposed-design)

Run `make test-pickup` at the repository root to exercise the wire format, real HTTP lookup, encrypted delivery and retention boundaries. The tests use source-controlled fixtures and temporary role-owned databases.
