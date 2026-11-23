# System Parameters

## Overview

This document defines all fixed and configurable parameters for the v1 prototype.

## Fixed Parameters

These are determined by the FlashProve commitment and cannot be changed without a new commitment:

| Parameter | Value | Description | Source |
|---|---|---|---|
| `T` | 1,024 | Window size (prompt + reply + padding) | F7 |
| `C` | `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46` | Commitment ID (exact match, published seed) | F4 |
| `E` | `[200001, 200007, 200008]` | End-token IDs | F37 |
| `z` | `0` | Padding token | F7 |

## Service Parameters

Configurable operational parameters:

| Parameter | v1 Value | Description |
|---|---|---|
| `max_tokens_cap` | 256 | Maximum reply length accepted by gateway (about 2.6 minutes of decoding) |
| `P_max` | `T - max_tokens` | Maximum prompt length for a request |
| `MMD` | 10 s | Maximum merge delay of the log |
| `δ_beacon` | 3 s | Margin after MMD before the beacon round |
| `W_escrow` | 5 minutes (hard cap) | Longest life of an unselected transcript |
| `W_pickup` | 7 days | Life of a sealed receipt in the pickup store |
| `W_challenge` | 30 days | Window for on-demand challenges from delivery |
| `D_sampled` | 24 hours | Deadline for a sampled verdict, measured from the signed receipt’s `served_at` |
| `D_demand` | 15 minutes (p95 target) | Target for an on-demand verdict, warm prover |
| `Q_max` | 4 | Maximum requests waiting at gateway (then 429) |

## Sampling Rates

| Parameter | Value | Usage |
|---|---|---|
| `r` | `1/N` where N ∈ {1, 20, 1,000} | Sampling rate |
| Live default | N = 20 | Active sampled audits |
| Shadow | N = 1,000 | Computed selections for economics |
| Soak test | N = 1 | Full audit mode (72-hour window) |

### Sampling Rate Selection

At ~550 requests/day (engine-limited):
- N = 20 selects ~27.5 per day
- N = 1,000 selects ~0.55 per day (one every ~2 days)
- N = 1 selects all 550 per day

Prover capacity at 1 per batch: ~1,470 proofs/day, so N=1 is feasible on prototype traffic.

## Model Parameters

| Parameter | Value | Description | Source |
|---|---|---|
| Model | Llama 4 Maverick 17B-128E Instruct | Integer model on 4-bit GGUF | F3 |
| Quantization | UD-Q4_K_XL | Third-party 4-bit conversion | F3 |
| Repository | `unsloth/Llama-4-Maverick-17B-128E-Instruct-GGUF` | HuggingFace repository | F3 |
| Revision | `41032e5471dd6ea5b349062d978626215d6c5bba` | Pinned revision | F3 |
| Weight files | 5 shards, ~232 GB | UD-Q4_K_XL folder | F3 |
| Vocabulary size | 202,048 | Token ID range | F37 |
| BOS token | 200000 | Begin-of-sequence | F37 |
| EOS tokens | 200001, 200007, 200008 | End-of-sequence | F37 |
| Pad token | 200018 | Padding (not used in v1 commitment) | F37 |

## Engine Parameters

From FlashProve OPERATING.md:

| Parameter | Value | Description | Source |
|---|---|---|
| vLLM version | 0.29.0 | Fixed version with integer model plug-in | F14 |
| `--max-num-seqs` | 1 | One sequence at a time | F14 |
| `--max-model-len` | 1024 | Window size | F14 |
| `--no-enable-prefix-caching` | Required | No prefix caching | F14 |
| `--enforce-eager` | Required | Eager mode (no CUDA graphs) | F14 |
| `--generation-config` | `vllm` | Configuration mode | F14 |
| `--fingerprint-mode` | `none` | No fingerprinting | F14 |
| `--max-logprobs` | 0 | No logprobs | F14 |
| Temperature | 0 | Greedy decoding only | Request policy |
| `return_token_ids` | `true` | Return token IDs | Rendering spec |

## Beacon Parameters

drand quicknet configuration:

| Parameter | Value | Description | Source |
|---|---|---|
| Chain | quicknet | drand chain name | F36 |
| Chain hash | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` | Chain identifier | F36 |
| Period | 3 s | Round frequency | F36 |
| Genesis | 1692803367 | Unix timestamp of round 1 | F36 |
| Scheme | `bls-unchained-g1-rfc9380` | Signature scheme | F36 |
| Endpoint | `https://api.drand.sh` | Public API | Design |

Round time calculation:
```
time(ρ) = genesis + (ρ - 1) × 3
```

## Render Profile Parameters

From specification section 6:

| Parameter | Value | Description | Source |
|---|---|---|
| Profile name | `llama4-chat/1` | Chat profile identifier | Spec §6.1 |
| Tokenizer | `tokenizer.json` SHA-256 `172c9eb4...23a4` | HuggingFace tokenizer | F37 |
| Config | `tokenizer_config.json` SHA-256 `2c56f1b6...425d` | Tokenizer configuration | F37 |
| Revision | `86c5ecb6f2fbddf604c60120125fb202e09f2556` | HuggingFace revision | Spec §6.1 |
| Template | From `tokenizer_config.json` | Chat template | F37 |
| `add_generation_prompt` | `true` | Add generation prompt | Spec §6.1 |
| `add_special_tokens` | `false` | Template emits BOS itself | Spec §6.1 |
| `date_string` | `"26 Jul 2024"` | Fixed date for determinism | Spec §6.1 |
| `tools` | `null` | No tool calls | Spec §6.1 |

Second profile (`raw-ids/1`): client supplies token IDs directly, no rendering.

## Cryptographic Parameters

| Parameter | Value | Description |
|---|---|---|
| Hash function | SHA-256 | All commitments and receipts |
| Signature scheme | Ed25519 | Log promises, STHs, verdicts |
| Key length | 32 bytes | Ed25519 standard |
| Merkle tree | Binary | 2-way fanout |
| Receipt salt | 32 bytes | Random per request |

## Rate Limits

| Endpoint | Limit | Description |
|---|---|---|
| `/v1/chat/completions` | Per API key | To be configured |
| `/v1/challenges` | 10 per holder key per hour | Challenge intake |
| `/v1/challenges` | 3 per transcript per day | Prevent duplicate challenges |
| Pickup store | Per IP | To be configured |
| Audit API | Per IP | To be configured |

## Resource Limits

| Resource | Limit | Reason |
|---|---|---|
| Request body | 256 KiB | Gateway limit |
| Merkle log | No limit (append-only) | Permanent |
| Escrow | W_escrow = 5 minutes per transcript | Memory bound |
| Pickup store | W_pickup = 7 days per sealed receipt | Storage bound |
| Audit queue | No hard cap | Bounded by deadlines |
| Prover queue | Deadlines apply | GPU capacity |

## Timeouts

| Operation | Timeout | Context |
|---|---|---|
| Engine request | `max_tokens × 0.62 s + margin` | Per-request |
| Receipt generation | <10 ms target | Fast path |
| Merkle append | <50 ms target | Fast path |
| Beacon fetch | 10 s with retries | Sampler |
| Proof generation (1/batch) | ~58.8 s + verification | Auditor |
| Verification | 21 to 44 s | Auditor and holders |

## Hardware Requirements

See `capacity.md` for detailed hardware specifications.

## Version Pinning

All dependencies MUST use exact pinned versions:

| Component | Version | Reason |
|---|---|---|
| vLLM | 0.29.0 | FlashProve integration tested version |
| FlashProve | Commit `9e2bdd8ff5bf9c62f18263d7dac189b0400b260c` | Version 0.16.0 |
| Python | 3.13 | FlashProve requirement |
| CUDA | 13.2 Update 2 | FlashProve requirement |
| gcc/g++ | 13 | FlashProve requirement |
| Tokenizers library | Pinned | Determinism |
| Jinja2 | Pinned | Determinism |

## Related Specifications

- `facts-register.md`: Source facts for all parameters
- `capacity.md`: Resource requirements and performance
- `engine.md`: Engine configuration details
- `sampling.md`: Beacon and selection parameters
- `canonical-rendering.md`: Render profile details
