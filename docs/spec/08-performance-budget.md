# Performance budget

## Measurement contract

Record a run as `{revision, dependency_lock, model_id, hardware, driver, workload, sample_count, measurements}`. Each measurement has `{phase, unit, aggregation, value}`. Report cold and warm runs separately, prompt and generated lengths, and measurement failures. Publish only redacted aggregate data.

| Quantity | Known baseline | Basis |
|---|---|---|
| Engine | 0.60–0.62 s/token after a three-token prompt; 22–25 min startup | F22 |
| Prover | 58.8 s/request at batch one on measured workload | F23; whole-reply baseline open |
| CPU verification | About 21 s single-thread; 36.2–44.0 s on measured shared VM | F26 |
| Proof size | 18.78 MB mean | F25 |

See the [facts register](../../specs/facts-register.md#facts-register) for hardware and scope. Keep reference measurements separate from operational directives in [parameters](../../specs/parameters.md#service-parameters). Measure prefill, decode, queue wait, proof time, verification, merge delay, proof bytes and RSS/GPU peaks independently. Attribute sampled deadline misses and measure the on-demand p95 with a warm prover. Capacity arithmetic excluding prefill is a planning estimate; verify actual throughput and resource stability in the M4 soak.
