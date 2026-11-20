# Engine

vLLM 0.29.0 serving FlashProve integer model with strict integrity gates.

## Purpose

The engine executes LLM inference under constraints that make proofs possible: greedy decoding only, no forced tokens, with range condition monitoring.

## Specifications

- `specs/engine.md`: Complete integration specification (model files, launch config, integrity gates)
- `specs/facts-register.md`: F14-F22 (configuration and performance)

## Key Invariants

From spec § 7:

1. **Start-up gates**: Float64 check, tensor verification, canary test (all must pass before serving)
2. **Single sequence**: `--max-num-seqs 1` ensures integrity monitoring works
3. **Range failures logged**: Engine logs ERROR on range condition failure
4. **Forced tokens logged**: Engine logs WARNING when tokens are forced
5. **Gateway monitors log**: Any ERROR/WARNING during request window → 502 unwarranted

## Model Configuration

From F3-F4:

- Model: Llama 4 Maverick 17B-128E Instruct, UD-Q4_K_XL, ~232 GB
- Commitment ID: `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46`
- Start-up: 22 to 25 minutes with tensor verification (F22)
- Decode: 0.60 to 0.62 s per token (F22)

## Testing

```bash
cd engine/
pytest tests/test_startup_gates.py -v
pytest tests/test_canary.py -v
pytest tests/test_integrity.py -v
```

## Related Specifications

- `specs/parameters.md`: T=1024, engine parameters
- `specs/hardening.md`: Security configuration (no --trust-remote-code, reverse proxy, mTLS)
