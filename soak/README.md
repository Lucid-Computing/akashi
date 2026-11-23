# Run the Mode R soak

For a local demonstration with a fixture engine, run `make setup demo-router`. The mock router exercises opaque response handling, sealed pickup and signed log inclusion. The all-audit soak uses that router with a qualified physical engine, the native prover, and a separate holder process. These measurements cover a single-operator deployment. An independently administered router or holder needs its own deployment evidence. [Router demonstration](../router/README.md) · [M4 exit test and traffic](../specs/build-plan.md#m4-router-path-and-soak)

## Serve an independent CLI client

On a provisioned primary, use the normal deployment configuration and add `--services-only` to start the physical provider for a client you operate separately.

```sh
python -m soak.deployment --services-only \
  --root "$VIG_M4_ROOT" --config "$VIG_M4_DEPLOYMENT_CONFIG"
```

The supervisor runs the hardware, spool and service readiness checks, starts the retention workers, and waits for client traffic. A private `traffic/runner/services-ready.json` records the supervisor PID and fresh startup digest. Check the current supervisor and use the pinned CA to authenticate the log's signed tree head before sending the request. The router accepts chat on its loopback port. The separate TLS ingress serves pickup, log and challenge requests. Use approved private connections for both endpoints and give the client its own credentials. [Holder protocol](../docs/rfcs/RFC-0010-router-pickup.md) · [Installed verifier](../verifier/README.md#verify-a-private-chat-reply-with-the-installed-native-checker)

Once the client has its complete private proof bundle, stop the supervisor with SIGTERM or SIGINT. It removes its readiness record and shuts down its application processes. The provider operator owns the engine and prover jobs and their normal drain procedure. This mode produces no soak journal or M4 qualification report.

## Start and recover a run

Use the primary engine that passed M0 and its original eligibility receipt. Start the sole authorized prover against its private spool. Provision the holder with its own bearer, pinned public keys, renderer and a public-only native verifier. Keep the holder's state separate from gateway escrow, auditor private data and the prover key. Run all roles under the cluster scheduler. The log and audit service must start with isolated state for this workload.

On a provisioned Linux node, start `python -m soak.deployment --root "$VIG_M4_ROOT" --config "$VIG_M4_DEPLOYMENT_CONFIG"` from the staged checkout. The launcher authenticates the measured primary, the two dedicated GPU assignments, the spool and the public verifier. It starts the gateway, auditor, router, loopback TLS listener and separate holder within their role mounts before recording traffic. It writes protected role settings and keeps the original holder trust across a controller restart.

Create owner-only `$VIG_M4_ROOT/proof-io/{submission,spool}` for this allocation. Set `VIG_M4_PROVER_SPOOL` and the provider endpoint's `spool` to that spool directory. Bind the common `proof-io` directory once, read-write, inside the auditor namespace. The native prover receives only its `spool` child. Keep auditor databases and signing material outside the common mount. Before starting traffic services, the launcher runs `python -m soak.audit_service --role check-spool --config "$AUDITOR_CONFIG"` in the auditor namespace. It atomically moves an empty non-request file from the submission directory to the live spool's incoming directory and removes it. This checks the no-replace publication operation used for durable jobs, including when separate bind mounts report the same filesystem device.

The operator uses a mode-0600 JSON configuration. Start the gateway with `python -m soak.gateway_service --config "$GATEWAY_CONFIG"`, and the auditor with one process for each of `index`, `worker`, `custody` and `http` using `python -m soak.audit_service --config "$AUDITOR_CONFIG" --role "$ROLE"`. Start the local opaque router against the gateway. Keep the authenticated provider control socket, escrow socket, spool, and auditor key paths within their roles. Private configurations and logs stay with the operator.

Start `python -m soak.runner --config "$VIG_M4_CONFIG"` after service readiness. The runner checks the F37 fixture against the renderer, the physical primary against the original host identity and the current startup against its original measurements. The four prompt shapes exercise 50, 768, 200 and 512 tokens with completion budgets of 10, 256, 64 and 128. The final gate checks the observed reply lengths. Traffic runs with one request in flight, N=1 and the actual quicknet draw for each receipt. The first cycle also challenges through the separate holder. A holder receiving an ambiguous response after transmission records uncertainty. Restarting the runner uses the private journal and holder state to resume safe reads.

The 72 hours start with the first journaled run on the ready deployment. During the run, the journal records resource observations for the engine, prover, gateway and auditor. It tracks process identity, process-tree resident memory and descriptor coverage. It also measures reserved GPU memory for the engine and prover. The gate rejects missing coverage, process changes and final quiescent usage exceeding the first complete workload cycle's measured peak. The report includes both that baseline and the highest observed value across the run. [Soak parameters](../specs/parameters.md) · [Range failure question](../specs/open-questions.md#oq8-range-failure-rate-and-padding)

### File descriptor coverage

The collector calibrates Linux procfs before starting traffic. An isolated helper with three standard descriptors checks its FD directory size as it opens one file, closes it, then closes its standard descriptors. On a kernel reporting the exact 3, 4, 3 and 0 counts, the collector obtains each role process's open descriptor count from the kernel's FD directory metadata. This includes the hardened prover, the auditor's native verifier and the verifier's forked stages. Each role reports `warm_peak_fds`, `peak_fds` and `final_fds`. The journal binds the calibrated source for the run. [Linux procfs implementation](https://github.com/torvalds/linux/blob/v6.2/fs/proc/fd.c#L268-L285)

On kernels without this measurement the collector enumerates readable FD directories. If the kernel denies enumeration for the authenticated native prover root, the collector reads its separately named `FDSize` capacity from procfs. The protected startup record binds this process to its PID, kernel start ticks and host cgroup. Other live processes must still supply exact counts. A missing required process or denied measurement stops the run with a bounded role, error class and errno. A short-lived descendant or thread that disappears before measurement contributes nothing to that observation; the collector checks that it really disappeared. [Linux proc status](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)

When the native-prover fallback is in use, `prover.fd_basis` is `exact_visible_plus_native_fdsize`. The report shows separate warm, observed peak and final values for `protected_fd_slots` (allocated slots in the native process's descriptor table) and `exact_fds_visible` (open descriptors in its readable descendants). The visible subtotal is JSON null when there is no readable contributing process. Coverage includes the minimum, maximum and final number of such processes. The gate checks final table capacity and visible counts against their respective warm peaks. It can detect table growth, but descriptor changes within the same allocation are unobservable. Sampling also leaves changes that occur entirely between observations unmeasured. [Resource collector](ledger.py)

### Resume the signed archive

Once the traffic interval finishes, the runner saves its end time and freezes the signed terminal tree head. It verifies and checkpoints each archive leaf against that head, the holder's saved request, its authentic quicknet round and its signed sampled verdict. The archive phase retries transient read failures within the operator's configured `limits.archive_drain_seconds`, measured from the original monotonic end time. A permanent evidence mismatch fails the phase. Its final read checks that the signed tree still has the same size and root.

To resume an interrupted archive while the same evidence services are available, use the private runner configuration on the same boot. This command reads a completed journal, continues after the last committed leaf and publishes `archive.json` atomically. It sends no inference or challenge requests and leaves the original traffic duration unchanged.

```sh
python -m soak.runner --config /absolute/private/path/to/runner.json --archive-only
```

## Check the result

Run `make test-m4` for CPU checks of the holder, custody and evidence rules. The hardware gate reads the completed journal and signed history.

```sh
export VIG_M4_CONFIG=/absolute/private/path/to/runner.json
make gate-m4
```

The gate writes `build/gates/m4.json`. A passing result authenticates every warranted receipt against the final signed head, recomputes every pinned beacon selection, checks the corresponding signed sample verdict and compares recovered holder evidence. It reports the unwarranted and EXCUSED_RANGE rates, achieved requests per hour, padding range, resource observations and hashes of M0 through M3. Missing inputs, an unfinished clock, an ambiguous request or a failed check produce an incomplete result and a nonzero exit. Only the redacted report belongs in release artifacts. [Release evidence requirements](../docs/rfcs/RFC-0011-release-gates.md#proposed-design)
