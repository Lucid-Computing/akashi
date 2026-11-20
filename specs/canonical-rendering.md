# Canonical Rendering

## Overview

Deterministic token ID computation from specification section 6, ensuring byte-identical prompt and reply conversion across all parties (gateway, auditor, verifier, client).

## Purpose

Every proof statement binds token IDs `x` (prompt) and `y` (reply), not text. To verify that a reply matches what the user saw, clients must:

1. **Encode**: Convert request `messages` to token IDs using the render profile
2. **Decode**: Convert reply token IDs to text using the same profile
3. **Commit**: Compute transcript commitment from token IDs

If gateway, auditor, and client use different tokenizers or chat templates, they produce different token IDs, and verification fails.

## Render Profile

Published in `.well-known/vig.json`:

```json
{
  "render_profile": {
    "digest": "<32-byte hex>",
    "profile": "llama4-chat/1",
    "tokenizer_json_url": "https://...",
    "tokenizer_config_url": "https://...",
    "tokenizer_json_sha256": "172c9eb4...23a4",
    "tokenizer_config_sha256": "2c56f1b6...425d"
  }
}
```

### Digest Computation

```
digest = SHA-256(
  profile_name || 
  tokenizer_json_sha256 || 
  tokenizer_config_sha256
)
```

Where `profile_name` is `"llama4-chat/1"` as UTF-8 bytes.

This digest enters the transcript commitment (receipt-log.md), binding the exact tokenizer.

## Profile: llama4-chat/1

### Tokenizer Files

- **tokenizer.json**: HuggingFace Tokenizers format, `from_pretrained` output
- **tokenizer_config.json**: Additional config (BOS, EOS, chat template)

Both files frozen at model commit, SHA-256 published.

### Chat Template

From `tokenizer_config.json`, the Jinja2 template:

```jinja2
{% for message in messages %}
{% if message['role'] == 'system' %}
<|start_header_id|>system<|end_header_id|>

{{ message['content'] }}
{% elif message['role'] == 'user' %}
<|start_header_id|>user<|end_header_id|>

{{ message['content'] }}<|eot_id|>
{% elif message['role'] == 'assistant' %}
<|start_header_id|>assistant<|end_header_id|>

{{ message['content'] }}<|eot_id|>
{% endif %}
{% endfor %}
<|start_header_id|>assistant<|end_header_id|>


```

This matches Llama 4 official chat format.

### Special Tokens

| Token | ID | Purpose |
|---|---|---|
| `<\|begin_of_text\|>` | 200000 | BOS, prepended to every prompt |
| `<\|end_of_text\|>` | 200001 | EOS |
| `<\|start_header_id\|>` | 200006 | Message role marker start |
| `<\|end_header_id\|>` | 200007 | Message role marker end |
| `<\|eot_id\|>` | 200008 | End of turn |

The set E = {200001, 200007, 200008} marks valid end tokens (gateway accepts replies ending in any of these).

### Encoding Procedure

Given `messages`:

1. Load `tokenizer.json` and `tokenizer_config.json`, verify SHA-256
2. Instantiate tokenizer: `transformers.AutoTokenizer.from_pretrained(...)`
3. Apply chat template: `tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)`
4. Tokenize result: `tokenizer.encode(formatted_text, add_special_tokens=False)`
5. Prepend BOS token 200000
6. Result is prompt token IDs `x`

**Critical**: `add_generation_prompt=True` appends `<|start_header_id|>assistant<|end_header_id|>\n\n`, so the model generates the assistant reply immediately.

### Decoding Procedure

Given reply token IDs `y`:

1. Load same tokenizer
2. Decode: `tokenizer.decode(y, skip_special_tokens=False)`
3. Result is reply text

**Critical**: `skip_special_tokens=False` preserves end tokens in output (user sees `<|eot_id|>` if present, or raw text if reply ends in 200001 or 200007).

## Content Normalization

### Multi-part Messages

Gateway accepts `messages[i].content` as:
- String (most common)
- List of `{"type": "text", "text": "..."}` parts (OpenAI vision format, but only text parts accepted)

Normalization:

```python
def normalize_content(content):
    if isinstance(content, str):
        return content
    elif isinstance(content, list):
        parts = [p["text"] for p in content if p["type"] == "text"]
        return "".join(parts)  # No separator
    else:
        raise ValueError("Invalid content")
```

This runs before chat template application.

### Whitespace

No normalization: whitespace is preserved exactly as sent. Different whitespace produces different token IDs and different proofs.

### Unicode

UTF-8 encoding throughout. No normalization (NFC, NFD, etc.). Clients and gateway must use same Unicode representation.

## Render Profile Versioning

Profile name includes version: `llama4-chat/1`.

If chat template changes (e.g., updated Llama 4.1 format), a new profile is published:
- New digest computed
- New tokenizer files (or same files with different template)
- New `.well-known/vig.json` with updated profile

Old receipts remain valid (they bind the old digest). Auditor fetches the correct tokenizer for each receipt's profile.

## Render Verification

Client verification step 5 (verifier-kit.md):

```python
def verify_render(receipt, reply_token_ids, expected_text):
    # Fetch tokenizer files from receipt's render_profile
    profile_digest = receipt["render_profile"]
    well_known = fetch_well_known()
    
    if profile_digest != well_known["render_profile"]["digest"]:
        # Receipt from old profile, fetch archived tokenizer
        tokenizer = fetch_archived_tokenizer(profile_digest)
    else:
        tokenizer = fetch_current_tokenizer()
    
    # Verify SHA-256 of tokenizer files
    assert sha256(tokenizer_json) == tokenizer_json_sha256
    assert sha256(tokenizer_config_json) == tokenizer_config_sha256
    
    # Decode
    decoded_text = tokenizer.decode(reply_token_ids, skip_special_tokens=False)
    
    # Compare
    assert decoded_text == expected_text
```

## Alternative Profiles

### raw-ids/1

For `POST /v1/completions` with raw token IDs:

```json
{
  "model": "maverick-int",
  "prompt": [200000, 12345, 67890],
  "max_tokens": 50
}
```

No chat template, no tokenization. Gateway serves raw token IDs directly to engine, returns raw token IDs in reply.

Profile:
- `profile: "raw-ids/1"`
- `digest: SHA-256("raw-ids/1")`
- No tokenizer files (identity encoding)

Used for research and debugging.

## Implementation Notes

### Gateway

```python
from transformers import AutoTokenizer

class CanonicalRenderer:
    def __init__(self, profile_config):
        self.tokenizer = AutoTokenizer.from_pretrained(
            profile_config["tokenizer_path"],
            trust_remote_code=False
        )
        self.profile_digest = profile_config["digest"]
    
    def render_prompt(self, messages):
        formatted = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        token_ids = self.tokenizer.encode(
            formatted,
            add_special_tokens=False
        )
        return [200000] + token_ids  # Prepend BOS
    
    def decode_reply(self, token_ids):
        return self.tokenizer.decode(
            token_ids,
            skip_special_tokens=False
        )
```

### Auditor

Same code, must produce identical token IDs for same messages.

### Client Verifier

Same code, verifies that gateway's text matches decoded token IDs.

## Edge Cases

### Empty Messages

```json
{"messages": [{"role": "user", "content": ""}]}
```

Valid. Chat template produces token IDs for role markers and whitespace, but no content tokens.

### System Message Only

```json
{"messages": [{"role": "system", "content": "You are helpful."}]}
```

Invalid per gateway policy (at least one user or assistant message required after system).

### Multiple System Messages

```json
{"messages": [
  {"role": "system", "content": "Rule 1"},
  {"role": "system", "content": "Rule 2"}
]}
```

Invalid per OpenAI spec and Llama 4 chat format. Gateway rejects with 400.

### Long Messages

No length limit on individual message content. Total token count must satisfy `P + max_tokens ≤ T = 1024`.

If prompt exceeds limit, gateway returns 400 `context_too_long`.

## Testing

Canonical rendering test suite (`gateway/tests/test_rendering.py`):

1. **Determinism**: Same messages produce same token IDs across 100 runs
2. **Round-trip**: `decode(encode(text))` recovers text exactly
3. **Whitespace**: Different whitespace produces different token IDs
4. **Unicode**: Different Unicode normalization produces different token IDs (or same, depending on tokenizer)
5. **Multi-part**: Multi-part content produces same token IDs as joined string
6. **Template**: Chat template output matches Llama 4 official examples

All tests must pass before deployment.

## Related Specifications

- `gateway-api.md`: Message format and content validation
- `receipt-log.md`: Render profile digest in transcript commitment
- `verifier-kit.md`: Decode verification procedure
- `facts-register.md`: F2 (tokenizer configuration)
