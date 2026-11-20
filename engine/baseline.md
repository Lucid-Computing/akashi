# Recheck a real-model M0 run

The 2026-11-20 run independently verified all 16 real whole replies on the eligible primary H100. The secondary refused startup twice, differed on all three primary cases and changed on its own first-case replay. The archived report includes each request’s prefill, decode, proof and verification measurements, the streaming result and both host configurations. [Measured M0 report](evidence/maverick-m0.json)

Run the CPU replay on the x86-64 Linux verifier host after a successful commitment rebuild, real engine startup and singleton proving run. The verifier needs the pinned F4 public verification files, the native binary, its release manifest, the public tokenizer assets and private artifacts from those runs. The fixed synthetic workload contains eight short chat requests and eight requests spanning 200 through 768 rendered prompt tokens. Each row specifies the original messages and caller budget. [M0 exit tests](../specs/build-plan.md#m0-bring-up) · [Workload](../tests/fixtures/m0-workload.jsonl)

Set `VIG_M0_CONFIG` to a private JSON configuration and run the gate from the repository root.

```sh
VIG_M0_CONFIG=/private/m0/run.json make gate-m0
```

The version 1 configuration uses these fields. Use absolute paths for the deployment's inputs.

| Field | Input |
| --- | --- |
| `schema_version` | Integer 1 |
| `capture` | Private directory with engine observations |
| `proofs` | Directory containing one subdirectory per workload ID |
| `assets` | Directory with both F37 tokenizer files |
| `rebuild_report` | Successful JSON from `make verify-commitment` |
| `ready`, `cross_host`, `float64_junit` | Engine eligibility with its observed canaries and platform, OQ9 assessment and serving GPU test results |
| `prover_startup` | JSON recording `startup_ns`, `measurement` and `batch_size: 1` |
| `verifier` | Object with `binary`, `manifest`, `config_dir`, `public_key_dir`, `timeout_seconds`, `memory_bytes` and `max_proof_bytes` |

The serving capture includes `unproven-candidates.json` with the prompt, reply IDs and budget for each row, each original `<id>.request`, and `per-case-metrics.jsonl` with isolated before/after snapshots. Collect `startup-measurement.json` when both loader markers and HTTP health first hold. Record the origin as `supervisor_start_to_both_markers_and_health_ns` when timing from the provider supervisor start, or `after_popen_to_both_markers_and_health_ns` when timing from the return of the engine launch call. The gate preserves the measured interval name. Capture the science-rain native stream in `stream.private.jsonl` and its terminal summary in `stream-measurement.json`. Keep original vectors, transcripts, proof input and operator paths private. The eligible startup must replay the first three cases after the golden values have been independently proved.

Each proof subdirectory contains the actual `example.proof`, its binary `example.y` and a `timing.json` with the integer fields `proof_ns` and `batch_size`. The persistent prover processes one request at a time. Measure startup from process launch to the first request entering work. Measure each proof from dispatch to publication of the proof file. Verification time includes staging inputs, running the native verifier and checking its terminal record.

The gate re-renders all 16 prompts and reconstructs each original whole-reply statement. It requires a zero public output and independently runs the F4 verifier on every proof. It reports per-case token counts, timings, proof sizes, stream ID agreement, startup and host observations in `build/gate-m0.json`. A missing prerequisite yields an incomplete report and a nonzero exit. Replay the counter, streaming, corpus and verifier-failure controls with `VIG_RENDER_ASSETS=/path/to/assets uv run --locked python -m unittest -v tests.test_gate_m0`. [Open technical questions](../specs/open-questions.md) · [Exact proof contract](../docs/rfcs/RFC-0006-proof-runtime.md)

The gate qualifies only the primary engine whose eligible startup record it checks. It records the SHA-256 of that record and a digest for each proved public workload case. Each case digest covers the ASCII domain `vig/m0/whole-reply/1`, followed by the 32-byte SHA-256 of the original statement and the 32-byte SHA-256 of its proof. Downstream gates can bind an original private capture to the declared primary configuration. Keep raw host fingerprints and token observations in protected capture storage.

For a measured cross-host disagreement, provide the secondary's three observed prompt, budget and reply vectors for the same primary canaries, both private host fingerprints, both model settings, and the refusal from the secondary's normal startup gate. The gate checks which replies differed and confirms that the normal startup refused the first corresponding canary. It publishes the comparison count and refusal outcome. Each secondary deployment needs its own successful startup before receiving traffic. [Engine startup requirements](../docs/rfcs/RFC-0001-engine-integrity.md)

The CPU replay checks the serving GPU JUnit result against all 51 case names independently collected from the pinned arithmetic suite. It verifies the SHA-256 of the sorted ASCII names, with one line feed after each name, and rejects any missing, skipped or failed case. [Pinned arithmetic suite](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/integrations/vllm/integer_model/tests/test_arithmetic_edges.py)
