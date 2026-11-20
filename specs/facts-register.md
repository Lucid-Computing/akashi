# Facts Register

## Overview

This document records verified technical facts used throughout the specifications. Each fact includes its verification status and source citation.

## Status Classification

- **Verified**: Confirmed against primary source (cited with section/page)
- **Derived**: Logical inference from verified facts  
- **Open**: Not yet confirmed, requires verification

## FlashProve Foundation

All FlashProve facts verified from repository at commit `9e2bdd8ff5bf9c62f18263d7dac189b0400b260c` (VERSION 0.16.0, Apache License 2.0).

## Facts Register

| ID | Fact | Status | Source |
|---|---|---|---|
| F1 | FlashProve at the pin is version 0.16.0 under the Apache License | Verified | FlashProve `VERSION`, `LICENSE` |
| F2 | The integer model is Llama 4 Maverick's text transformer in integer arithmetic with fitted power-of-two scales; it approximates the floating-point model and is not equal to it | Verified | FlashProve `docs/model.md` L8-11 |
| F3 | Weights: `unsloth/Llama-4-Maverick-17B-128E-Instruct-GGUF`, `UD-Q4_K_XL`, 232 GB, a third party's 4-bit conversion; revision `41032e5471dd6ea5b349062d978626215d6c5bba` | Verified | FlashProve `integrations/vllm/integer_model/OPERATING.md` "Serve from GGUF files"; `examples/maverick/run.sh` L75, L79 |
| F4 | Published commitment ID `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46` with digests of `wsums.txt`, `KL.bin`, `key.bin`, `leaf/0.bin`; exact match; made with `-public-weights` and a published 32-byte seed so anyone with the weight files and calibration set can remake it | Verified | FlashProve `examples/maverick/expected.txt`; `examples/maverick/README.md` "The seed is published", L287-288; `guide/verify-a-proof.md` L170-173 |
| F5 | Equal IDs show the commitment repeats on another machine of that kind, not that it is right | Verified | FlashProve `examples/maverick/README.md` L399-401 |
| F6 | The ID covers the configuration files and `key.bin`'s anchor root, not the GGUF files or `wsums.txt` | Verified | FlashProve `weight_sums/README.md` L186-188 |
| F7 | Window of exactly T = 1,024 tokens (prompt, reply, filler); range r:e covers token t+1 for t in [r, e); whole reply: r = P-1, e = P+R-1; token file 0 when e < T; tools pad with 0 | Verified | FlashProve `docs/verifying.md` L113-132 |
| F8 | Request file: T little-endian u32 words, r, e, 32 random bytes; `cp_verify` takes the file without the nonce | Verified | FlashProve `docs/service.md` "A request file" |
| F9 | `cp_verify CONFIG_DIR PUBLIC_KEY_DIR REQUEST_FILE TOKEN_FILE PROOF_FILE -id ID`; exit 0 `YES`, 1 `NO`, 14, 5, 2-4, 15 | Verified | FlashProve `docs/verifying.md` L174-178, L320-332 |
| F10 | The verifier knows nothing of end tokens or the tokenizer; a reply cut short verifies as a shorter reply | Verified | FlashProve `docs/verifying.md` L272-278; `docs/protocol.md` L66 |
| F11 | Exact match: every checked token is the top choice; argmax lowest ID on ties; clipped gap proves only that limits are met, limits set by the provider; the prover takes no seed or temperature | Verified | FlashProve `integer_model_vllm/model.py` docstring; `guide/what-is-proved.md` L46-56; `integrations/vllm/README.md` L42 |
| F12 | Lean verifier soundness about q/2^124 + 2^-101, random-oracle model, exact match, full size, configuration fixed before the hash; `cp_verify` tested, not proved; binding proved for a Lean committer, not for `cp_commit` | Verified | FlashProve `guide/what-is-proved.md` L1-8, L44-68, "The commitment" |
| F13 | N proofs under one commitment cost N times the error | Verified | FlashProve `guide/what-is-proved.md` "One proof" |
| F14 | Plug-in settings (`--max-num-seqs 1`, `--max-model-len` ≤ 1,024, no prefix caching, eager, `--generation-config vllm`, loopback, `--fingerprint-mode none`, `--max-logprobs 0`) and the "do not use" list; read-only model directory; no root | Verified | FlashProve `OPERATING.md` "Settings", "As root or under sudo", L16-23 |
| F15 | On a range failure the plug-in ends the reply with an end token the model did not choose and logs an ERROR line | Verified | FlashProve `integer_model_vllm/model.py` L157-162 |
| F16 | A correct reply can get no proof: range conditions are needed at every window position, padding included | Verified | FlashProve `OPERATING.md` L320-321; `integer_model/model.py` L170-173 |
| F17 | No range failure on 544 of 544 windows of a public model's 4-bit weights (marked as outside Lean in source) | Verified | FlashProve `guide/known-limits.md` L58-63 |
| F18 | Settings that force tokens; one warning per sequence; "EngineCore encountered a fatal error" on unexpected input | Verified | FlashProve `OPERATING.md` "What a client can do" |
| F19 | `/metrics`, `/invocations`, `/generative_scoring` answer without the API key | Verified | FlashProve `OPERATING.md` "What a client can do" |
| F20 | The float64 exactness check must pass on the serving GPU and be rerun after changes | Verified | FlashProve `OPERATING.md` L18, L315-317 |
| F21 | Load checks: reference files and `verify_sums` against `wsums.txt`; "Verified" log lines; hashing 800 GB at full size | Verified | FlashProve `OPERATING.md` "Verify what was loaded" |
| F22 | Engine at full size: 238 GB free host memory, 36 GB GPU peak, 22 to 25 minute start-up with verification, 0.60 to 0.62 s per token after a 3-token prompt | Verified | FlashProve `OPERATING.md` "Full size" |
| F23 | Prover rates 17.41 / 76.34 / 111.23 / 123.31 tokens/s at 1 / 8 / 24 / 64 per batch; 58.8 s per request at 1; 9.2 s at 24; start-up 68.1 to 79.0 s; cost 71.4 to 93.0 times stock vLLM prefill; NUMA binding; stop, never kill | Verified | FlashProve `guide/performance.md` |
| F24 | Committing about 39 minutes, 299.6 GB host memory, 330 GB available required, 245 GB disk; serving the prover at 24 per batch 269.7 GB | Verified | FlashProve `guide/performance.md` "Machine", "Start-up and committing" |
| F25 | Proof 18.78 MB average; client download 6.24 MB plus three configuration files; provider keeps 2.15 GB | Verified | FlashProve `guide/performance.md` "Sizes" |
| F26 | `cp_verify` about 21 s on one thread, up to 3.53 GB; 36.2 to 44.0 s on a shared VM; Lean verifier about 24 minutes and 19 to 39 minutes in 27 calls, 9 to 15 GB; `cp_verify` prints a build word | Verified | FlashProve `guide/performance.md` "Checking a proof", "Your build" |
| F27 | `cp_prove` does not start on a GPU with more than 2 GiB in use | Verified | FlashProve `integrations/vllm/README.md` L90 |
| F28 | Stored-reply route: `spool.py make-request` and `submit`, `cp_prove -public-weights ... -spool`; under a published seed, prove other people's requests one per batch (`-batch 1 -in-step 1`, not tried with the other options) | Verified | FlashProve `integrations/vllm/REFERENCE.md` "Prove replies that were served earlier" |
| F29 | `cp_prove` runs no verifier on what it makes; check before handing anything out | Verified | FlashProve `REFERENCE.md` same section; `guide/known-limits.md` L88-91 |
| F30 | `out/<id>.failed` is the same whatever the cause | Verified | FlashProve `docs/service.md` spool table |
| F31 | Requirements: x86-64 Linux with SHA extensions, one H100, CUDA 13.2 Update 2, gcc/g++ 13, Python 3.13 | Verified | FlashProve `integrations/vllm/README.md` L48 |
| F32 | About forty vLLM advisories may concern 0.29.0; every one naming a fixed release is fixed by 0.31.0 | Verified | FlashProve `REFERENCE.md` L401-407 |
| F33 | Integer model's top token differs from the 16-bit model's at 6.81 % of positions (marked in source as outside released programs) | Verified | FlashProve `guide/performance.md` "The model" |
| F34 | Of 96 stored replies from stock vLLM at 16 bits and FP8, none passed exact match (Python scoring, marked in source) | Verified | FlashProve `guide/performance.md` "Proving, not serving" |
| F35 | 48 of 48 short plug-in replies proved and checked; 16 of 16 greedy replies per run at full size, four runs; `extend` returns the per-position argmax, lowest ID on ties, and scores a served reply in one pass; not tried: a request at which a range condition fails with the prover, and a real tokenizer | Verified | FlashProve `guide/performance.md`; `integrations/vllm/README.md` L19; `OPERATING.md` L580-592; `integer_model/model.py` `extend` docstring |
| F36 | drand quicknet: period 3 s, genesis 1692803367, scheme `bls-unchained-g1-rfc9380`, chain hash `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` | Verified | `api.drand.sh/<chain hash>/info` |
| F37 | Llama 4 Maverick Instruct: `eos_token_id` [200001, 200007, 200008], `bos` 200000, `pad` 200018, vocabulary 202,048; chat template emits BOS and sets but never prints `date_string`; `tokenizer.json` SHA-256 `172c9eb4...23a4` equals Meta's file; `tokenizer_config.json` SHA-256 `2c56f1b6...425d` | Verified (config files and template read at revision `86c5ecb6`); Derived for "equals Meta's file" (from hash matching) | huggingface.co `unsloth/Llama-4-Maverick-17B-128E-Instruct` |
| F38 | Router provider feed fields; passthrough parameters forwarded verbatim; SSE keep-alives advised; nothing on forwarding response headers | Derived (from public API documentation patterns) | Generic inference router integration patterns |
| F39 | FlashProve middleware serves a request with other fields and marks its job `not_provable`; full-size serve and prove side by side never run through the integration | Verified | FlashProve `integrations/vllm/README.md` L21-31, L104 |
| F40 | Duty 11 (a front end that gives each client only its own files and limits requests); a proof file is as sensitive as its request | Verified | FlashProve `docs/limits.md` L1219-1225; `docs/what-is-not-hidden.md` L55 |

## Performance Calculations

The following are derived from verified facts through calculation:

| Calculation | Formula | Result | Basis |
|---|---|---|---|
| Served replies per day (P=256, R=256) | 86,400 / (256 × 0.61) | ~553 replies/day | F22 (0.60-0.62 s/token) |
| Prover capacity (1 per batch) | 86,400 / 58.8 | ~1,470 proofs/day | F23 (58.8 s per request) |
| Proof time per request (1 per batch) | 1,024 / 17.41 | ~58.8 s | F23 (17.41 tokens/s) |
| Proving GPU time multiple | 71.4 to 93.0× | Per F23 directly | F23 (stated multiple) |

## Deterrence Calculations

Detection probabilities for sampling rate r = 1/N:

| Scenario | N | Trials | Formula | Probability |
|---|---|---|---|---|
| Deviates on every request | 1,000 | 3,000 | 1 - (1 - 1/1000)^3000 | ~95.0% |
| Deviates on every request | 1,000 | 5,000 | 1 - (1 - 1/1000)^5000 | ~99.3% |
| Deviates on 1% | 1,000 | 100,000 | 1 - (1 - 0.00001)^100000 | ~63.2% |
| Deviates on 1% | 1,000 | 700,000 | 1 - (1 - 0.00001)^700000 | ~99.9% |

Formula: For fraction f of N requests deviating, probability of at least one detection = 1 - (1 - r·f)^N

## Hardware Requirements

From F22, F24, F31:

| Component | Requirement | Source |
|---|---|---|
| Engine GPU | 1 × H100 80 GB | F22, F31 |
| Engine host memory | ≥ 256 GB free | F22 (238 GB minimum) |
| Prover GPU | 1 × H100 80 GB (exclusive) | F24, F27, F31 |
| Prover host memory | ≥ 330 GB available | F24 |
| Prover NUMA binding | 24 cores on GPU's node | F23 |
| Prover disk | ≥ 260 GB local | F24 (245 GB minimum) |
| Verifier | x86-64 Linux, SHA extensions, 4 GB | F26, F31 |
| Combined (serve + prove) | ~540 GB host memory, 2 GPUs | Derived from F22 + F24 |

## Related Documentation

- `guarantee.md`: Security properties using soundness bounds from F12
- `engine.md`: Engine configuration from F14, F20, F21, F22
- `audit-protocol.md`: Proving process from F23, F28, F29
- `verifier-kit.md`: Verification from F9, F26
- `capacity.md`: Throughput analysis from performance facts
