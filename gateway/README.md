# Gateway

OpenAI-compatible HTTP API with strict greedy-only policy and cryptographic receipts.

## Purpose

The gateway enforces the verified inference guarantee by accepting only greedy-decodable requests (temperature=0) and generating cryptographic receipts binding every warranted reply.

## Specifications

- `specs/gateway-api.md`: Complete API specification (endpoints, request policy, errors, response format)
- `specs/canonical-rendering.md`: Tokenization and chat templates
- `specs/engine.md`: Engine integration and integrity monitoring

## Key Invariants

From spec § 5:

1. **Greedy-only**: Reject any request with temperature ≠ 0, top_p ≠ 1, or sampling parameters
2. **No receipt = no 200**: MUST NOT return 200 completion without valid receipt
3. **Unwarranted detection**: Return 502 if engine logs ERROR or warning during request window
4. **Window constraint**: Enforce P + max_tokens ≤ T = 1024

## Configuration

From `specs/parameters.md` and `specs/engine.md`:

```bash
ENGINE_URL=http://127.0.0.1:8000
LOG_URL=https://log.example.com/log/v1/
COMMITMENT_ID=c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46
TOKENIZER_PATH=/path/to/tokenizer/
```

## Testing

```bash
cd gateway/
pytest tests/ -v
```

## Related Specifications

- `specs/parameters.md`: T, max_tokens_cap, Q_max
- `specs/receipt-log.md`: Receipt format and promise protocol
- `specs/hardening.md`: Security configuration
