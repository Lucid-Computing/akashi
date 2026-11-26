# Router Integration

## Overview

Integration patterns for LLM router services from specification section 13, using generic Mode R (router-mediated) architecture.

## Architecture

```
Client → Router → Gateway → Engine
           ↓
        Pickup service (receipts)
```

Router discovers gateway via provider listing, routes requests based on model availability, cost, and policy, then forwards to gateway endpoint.

## Discovery and Registration

### Provider Feed

Router fetches available models:

```
GET /router/models
```

Returns:

```json
{
  "models": [{
    "id": "llama-4-maverick-int",
    "quantization": "int4",
    "max_context_length": 1024,
    "max_completion_tokens": 256,
    "supported_parameters": ["max_tokens", "temperature", "stream", "seed"],
    "constraints": {
      "temperature": [0],
      "top_p": [1],
      "n": [1]
    },
    "description": "Llama 4 Maverick 17B integer model with ZK proofs. Greedy decoding only. Verification receipts available. See https://.../.well-known/akashi.json"
  }]
}
```

Router should:
1. Parse constraints and reject requests that violate them before forwarding
2. Display constraints in model selection UI
3. Link to `.well-known/akashi.json` for verification details

### Service Descriptor

Router fetches once and caches:

```
GET /.well-known/akashi.json
```

Contains:
- Commitment ID (model identity)
- Window size T and max_tokens cap
- Sampling rates
- Log, auditor, and pickup URLs
- Public keys for signature verification

## Request Flow

### 1. Router Receives Request

Client sends OpenAI-compatible request to router's unified endpoint.

### 2. Model Selection

Router's model selector considers:
- Model name match
- Context length ≤ 1024
- `max_tokens` ≤ 256
- Temperature = 0 (or absent, router sets to 0)
- Other sampling parameters match constraints

If request violates constraints, router can:
- Reject with 400
- Or forward and let gateway reject (returns 400 with `unsupported_parameter`)

### 3. Request Forwarding

Router forwards to gateway with:
- Same `messages`, `model`, `max_tokens`, `stream`
- Ensures `temperature: 0` (or absent)
- Removes unsupported fields
- Adds router's API key for gateway authentication

### 4. Response Handling

Gateway returns completion with `verification` object.

**Option A: Transparent forwarding**

Router forwards entire response including `verification` and `x-akashi-receipt` header to client. Client can verify immediately.

**Option B: Opaque forwarding**

Router strips `verification` before forwarding to client. Client fetches receipt later via sealed pickup.

## Receipt Delivery Patterns

### Pattern 1: Inline (Transparent Router)

Client receives `verification` object in response body and `x-akashi-receipt` header.

Advantages:
- Immediate verification
- No additional round trip
- Client controls verification

Disadvantages:
- Router must forward extra fields
- Receipt visible to router

### Pattern 2: Sealed Pickup (Opaque Router)

The holder opts in by putting a fresh pickup secret in the request's `user` field. The router preserves the field, messages, resolved budget and displayed reply. After serving, the holder derives the opaque pickup ID, retrieves the encrypted envelope within `W_pickup` and independently verifies the recovered receipt. Forwarding compatibility is assessed per route. [Sealed pickup contract](retention.md#sealed-pickup)

### Pattern 3: Router Verification Service

Router fetches receipt, verifies basic checks (signature, commitment, inclusion), and adds a `router_verified: true` flag to the response.

Advantages:
- Simplified client integration
- Router can cache verification results
- No client-side crypto

Disadvantages:
- Client trusts router's verification
- Does not defend against router compromise
- Client should still verify independently for sensitive use cases

## Timeouts and Streaming

Gateway uses streaming with SSE keep-alive comments while engine works.

With `max_tokens ≤ 256`, decoding stays under about 2.6 minutes.

Router should:
- Use `stream: true` and forward SSE events to keep client connection alive
- Send keep-alive comments while gateway works

## Error Handling

Gateway errors forwarded by router:

| Gateway HTTP | Router Action | Client Experience |
|---|---|---|
| 400 `unsupported_parameter` | Forward to client | Client fixes request |
| 429 `queue_full` | Retry with backoff or route to alternate provider | Transparent retry |
| 502 `unwarranted_reply` | Log incident, route to alternate provider | Transparent failover |
| 503 `engine_unavailable` | Route to alternate provider | Transparent failover |

Router should:
- Log all 502 and 503 errors for investigation
- Emit metrics on unwarranted rate
- Remove gateway from rotation after sustained 503

## Cost and Billing

Gateway does not charge per-request. Pricing models:

1. **Flat rate**: Monthly fee for router access key
2. **Volume tiers**: Cost per million tokens with volume discounts
3. **Seat licensing**: Per end-user or per organization

Verification costs (proof generation and auditor) are included. No extra charge for receipts.

Router passes cost through to client or includes in aggregated pricing.

## Observability

Router should emit metrics:

- `router_gateway_requests_total{gateway, model, status}`
- `router_gateway_duration_seconds{gateway, model}`
- `router_gateway_tokens_total{gateway, model, type="prompt"|"completion"}`
- `router_gateway_errors_total{gateway, model, code}`
- `router_verification_fetched_total{gateway}`
- `router_verification_valid_total{gateway}`

And alerts:
- `unwarranted` rate > 0.1%
- 503 rate > 5% over 10 minutes
- Verification fetch failures > 1% over 1 hour

## Client Integration

### Discovery

Client using router should:

1. Fetch router's model list
2. Find models with "verification" or "proof" in description
3. Check model constraints
4. Read `.well-known/akashi.json` from verification URL

### Verification

For transparent routers:

```python
response = requests.post("https://router.example/v1/chat/completions", ...)
verification = response.json().get("verification")

if verification:
    receipt = verification["receipt"]
    # Verify as in verifier-kit.md
```

For opaque routers, the holder retains the secret generated before submission. Recovery uses the original chat, budget, displayed reply and trusted descriptor.

```python
from pickup.crypto import lookup_id, open as open_pickup

pickup_id = lookup_id(messages, budget, reply_text, holder_secret)
url = trusted_descriptor["pickup_url"].rstrip("/") + "/" + pickup_id
response = requests.get(url)
response.raise_for_status()
verification = open_pickup(response.json(), holder_secret, messages, budget, reply_text)
```

Pass the recovered verification and original inputs to the [holder verifier](verifier-kit.md).

## Provider Dashboard

Gateway operator provides router dashboard showing:
- Model availability and uptime
- Queue depth and request latency
- Unwarranted rate (should be ~0)
- Verification stats from auditor
- Recent deviations (if any)

Router queries:

```
GET /router/stats
```

Returns:

```json
{
  "model": "llama-4-maverick-int",
  "status": "available",
  "uptime_percent_7d": 99.9,
  "queue_depth": 3,
  "avg_latency_seconds": 45.2,
  "unwarranted_rate_7d": 0.0002,
  "total_requests_7d": 123456,
  "verification_rate": 0.05,
  "last_deviation": null
}
```

## Fallback and Redundancy

Router should:

1. Register multiple gateway instances (if available)
2. Health-check each gateway's `/health` endpoint
3. Route to healthy gateways only
4. Retry once on 503, then fail over to alternate provider
5. Do not retry on 400, 502 (errors are deterministic)

## Security Considerations

- Router sees all prompts and replies (not end-to-end encrypted)
- Router cannot forge receipts (log signature verification)
- Router cannot modify tokens without detection (commitment binding)
- Client should verify receipts independently, especially for sensitive use cases
- Router's verification service is a convenience, not a security control

## Related Specifications

- `gateway-api.md`: Endpoints and response format
- `receipt-log.md`: Sealed pickup protocol
- `verifier-kit.md`: Client verification procedure
- `hardening.md`: Rate limiting and authentication
