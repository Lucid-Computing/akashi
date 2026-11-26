# Verifier Kit

## Overview

Client-side verification tools and procedures from specification section 11, enabling users to independently verify receipts.

## What Clients Can Verify

Without running the prover:

1. **Receipt authenticity**: Log promise signature
2. **Tree inclusion**: Merkle audit path to signed tree head
3. **Tree consistency**: Evolution from old STH to new STH
4. **Transcript commitment binding**: Recompute `t` from receipt fields and token IDs
5. **Render correctness**: Recompute text from token IDs using published tokenizer

With the prover (requires GPU):

6. **Model conformance**: Generate and verify ZK proof locally

## Verification Procedure

### Step 1: Verify Receipt Signature

Given receipt with `promise_sig`, log public key from `.well-known/akashi.json`:

```python
def verify_receipt_signature(receipt, log_public_key):
    log_id = bytes.fromhex(receipt["log_id"])
    leaf_hash = bytes.fromhex(receipt["leaf_hash"])
    message = b"PromiseReceipt" + log_id + leaf_hash
    
    sig = bytes.fromhex(receipt["promise_sig"])
    verify_ed25519(log_public_key, message, sig)  # raises on failure
```

### Step 2: Verify Transcript Commitment

Recompute from receipt and token IDs:

```python
def verify_transcript_commitment(receipt, prompt_token_ids, reply_token_ids):
    C = bytes.fromhex(receipt["commitment_id"])
    R = bytes.fromhex(receipt["render_profile"])
    salt = bytes.fromhex(receipt["salt"])
    
    # params_digest from max_tokens
    max_tokens = len(reply_token_ids)  # or from original request
    H_params = sha256(max_tokens.to_bytes(4, 'little'))
    
    # Token IDs to bytes (little-endian)
    x = b''.join(tid.to_bytes(4, 'little') for tid in prompt_token_ids)
    y = b''.join(tid.to_bytes(4, 'little') for tid in reply_token_ids)
    
    recomputed_t = sha256(C + R + H_params + salt + x + y)
    
    expected_t = bytes.fromhex(receipt["transcript_commitment"])
    assert recomputed_t == expected_t
```

### Step 3: Verify Tree Inclusion

Fetch audit path from `GET /log/v1/proof/{leaf_index}`, verify RFC 6962 Merkle path to latest STH root.

### Step 4: Verify Tree Consistency

Fetch consistency proof from `GET /log/v1/consistency?from={old}&to={new}`, verify old tree is prefix of new tree.

### Step 5: Verify Render

Download tokenizer from `.well-known/akashi.json`, decode reply token IDs, compare to expected text.

### Step 6: Verify Model Conformance (Optional)

Run FlashProve prover and verifier:

```bash
cp_prove \
  --commitment-id c7982f8a... \
  --prompt-token-ids prompt.bin \
  --reply-token-ids reply.bin \
  --output proof.bin

cp_verify \
  --proof proof.bin \
  --public-inputs inputs.json \
  --commitment-id c7982f8a... \
  --output verdict.json
```

Performance (F23, F26):
- Proof generation: 58.8 s
- Verification: about 21 s single thread, 36.2 to 44.0 s shared VM
- Proof size: 18.78 MB average

## Exit Codes

From spec § 11.3:

| Code | Meaning |
|---|---|
| 0 | conforms: every check passed |
| 10 | receipt invalid (signature, `t`, inclusion) |
| 11 | rendering mismatch |
| 12 | text mismatch |
| 13 | reply incomplete |
| 20 | proof rejected (`cp_verify` exit 1) |
| 21 | deviation proven |
| 30 | no verdict (`cp_verify` 2-5, 14, 15; missing files) |
| 64 | usage |

### FlashProve `cp_verify` Exit Codes

From F9:

| Code | Meaning |
|---|---|
| 0 | YES: proof valid |
| 1 | NO: proof invalid (soundness violation) |
| 2-4 | Errors (bad input format, missing files) |
| 5 | Error |
| 14 | Error |
| 15 | Error |

## Second Verifier

Because proof verification is much faster than generation (21 s vs 58.8 s), clients can run a second independent verifier:

1. Submit challenge to auditor, get `challenge_id`
2. Poll `GET /audit/v1/challenges/{challenge_id}` until verdict available
3. Download auditor's proof from challenge result
4. Run local `cp_verify` on the same proof
5. Compare verdicts

This defends against:
- Compromised auditor (A3) issuing false verdicts
- Network attacker (A5) tampering with verdict responses

## Verifier Kit Distribution

Python package with a pinned, reproducibly built `cp_verify` binary per platform (x86-64 Linux with SHA extensions).

```bash
pip install akashi-verify
```

Includes:
- Receipt signature verification
- Transcript commitment computation
- Tree inclusion/consistency verification
- Render verification with tokenizers
- Pinned `cp_verify` binary for proof verification
- API client for log and auditor

## Client Integration Examples

### Mode D (Direct)

```python
from akashi_verify import Verifier

v = Verifier.from_well_known("https://.../")
response = requests.post("https://.../v1/chat/completions", ...)
receipt = response.json()["verification"]["receipt"]

# Verify immediately
v.verify_receipt_signature(receipt)
v.verify_transcript_commitment(
    receipt,
    response.json()["verification"]["prompt_token_ids"],
    response.json()["verification"]["reply_token_ids"]
)
v.verify_tree_inclusion(receipt)
print("✓ Verified")
```

### Mode R (Router)

```python
# After serving, fetch sealed pickup
pickup = requests.get(f"https://.../receipts/v1/pickup/{request_id}").json()
receipt = pickup["receipt"]

# Verify as above
v.verify_receipt_signature(receipt)
# ... etc
```

## Error Handling

All verification functions raise exceptions on failure:
- `SignatureError`: Log signature invalid
- `CommitmentError`: Transcript commitment mismatch
- `InclusionError`: Tree inclusion proof invalid
- `ConsistencyError`: Tree consistency proof invalid
- `RenderError`: Token IDs don't match text
- `ConformanceError`: Model deviation detected

Client code should:
1. Log the error with full receipt and token IDs
2. Alert user of verification failure
3. Optionally submit challenge to auditor for investigation

## Related Specifications

- `receipt-log.md`: Receipt format and log API
- `audit-protocol.md`: Challenge submission for full verification
- `canonical-rendering.md`: Tokenizer and render algorithm
- `facts-register.md`: F9 (cp_verify codes), F22-F26 (verification performance)
