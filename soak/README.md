# Run the Mode R soak

For a local demonstration with a fixture engine, run `make setup demo-router`. The mock router exercises opaque response handling, sealed pickup and signed log inclusion. The all-audit soak uses that router with a qualified physical engine, the native prover, and a separate holder process. These measurements cover a single-operator deployment. An independently administered router or holder needs its own deployment evidence. [Router demonstration](../router/README.md) · [M4 exit test and traffic](../specs/build-plan.md#m4-router-path-and-soak)

## Start and recover a run

Use the primary engine that passed M0 and its original eligibility receipt. Start the sole authorized prover against its private spool. Provision the holder with its own bearer, pinned public keys, renderer and a public-only native verifier. Keep the holder's state separate from gateway escrow, auditor private data and the prover key. Run all roles under the cluster scheduler. The log and audit service must start with isolated state for this workload.

On a provisioned Linux node, start `python -m soak.deployment --root "$VIG_M4_ROOT" --config "$VIG_M4_DEPLOYMENT_CONFIG"` from the staged checkout. The launcher authenticates the measured primary, the two dedicated GPU assignments, the spool and the public verifier. It starts the gateway, auditor, router, loopback TLS listener and separate holder within their role mounts before recording traffic. It writes protected role settings and keeps the original holder trust across a controller restart.

The operator uses a mode-0600 JSON configuration. Start the gateway with `python -m soak.gateway_service --config "$GATEWAY_CONFIG"`, and the auditor with one process for each of `index`, `worker`, `custody` and `http` using `python -m soak.audit_service --config "$AUDITOR_CONFIG" --role "$ROLE"`. Start the local opaque router against the gateway. Keep the authenticated provider control socket, escrow socket, spool, and auditor key paths within their roles. Private configurations and logs stay with the operator.

Start `python -m soak.runner --config "$VIG_M4_CONFIG"` after service readiness. The runner checks the F37 fixture against the renderer, the physical primary against the original host identity and the current startup against its original measurements. The four prompt shapes exercise 50, 768, 200 and 512 tokens with completion budgets of 10, 256, 64 and 128. The final gate checks the observed reply lengths. Traffic runs with one request in flight, N=1 and the actual quicknet draw for each receipt. The first cycle also challenges through the separate holder. A holder receiving an ambiguous response after transmission records uncertainty. Restarting the runner uses the private journal and holder state to resume safe reads.

The 72 hours start with the first journaled run on the ready deployment. During the run, the journal records resource observations for the engine, prover, gateway and auditor. It tracks process identity, process-tree resident memory and open file descriptors, and reserved GPU memory for the engine and prover. The gate rejects missing coverage, process changes and final quiescent usage exceeding the first complete workload cycle's measured peak. The report includes both that baseline and the highest observed value across the run. [Soak parameters](../specs/parameters.md) · [Range failure question](../specs/open-questions.md#oq8-range-failure-rate-and-padding)

## Check the result

Run `make test-m4` for CPU checks of the holder, custody and evidence rules. The hardware gate reads the completed journal and signed history.

```sh
export VIG_M4_CONFIG=/absolute/private/path/to/runner.json
make gate-m4
```

The gate writes `build/gates/m4.json`. A passing result authenticates every warranted receipt against the final signed head, recomputes every pinned beacon selection, checks the corresponding signed sample verdict and compares recovered holder evidence. It reports the unwarranted and EXCUSED_RANGE rates, achieved requests per hour, padding range, resource observations and hashes of M0 through M3. Missing inputs, an unfinished clock, an ambiguous request or a failed check produce an incomplete result and a nonzero exit. Only the redacted report belongs in release artifacts. [Release evidence requirements](../docs/rfcs/RFC-0011-release-gates.md#proposed-design)
