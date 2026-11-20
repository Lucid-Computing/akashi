# Observability

## Prometheus Metrics

All metrics are private (not publicly exposed). Metric names below are proposed implementations; spec section 18 describes categories without specifying exact names or labels.

### Gateway Metrics

```
# Request handling
vig_requests_total{status="200|400|429|502|503"}
vig_queue_depth
vig_engine_seconds{phase="prefill|decode"}

# Integrity
vig_unwarranted_total{reason="range_failure|forced_token|engine_error"}
```

### Log Metrics

```
# Merkle log
vig_log_tree_size
vig_promise_to_sth_seconds  # Time from promise to STH inclusion

# Receipt generation
vig_receipt_generation_seconds
```

### Sampling Metrics

```
# Beacon and selection
vig_beacon_lag_seconds  # Time behind latest beacon round
vig_selected_total{N="1|20|1000"}
vig_escrow_gaps_total  # Transcripts expired before beacon
vig_escrow_age_seconds  # Age of oldest transcript in escrow
```

### Auditor Metrics

```
# Proof generation
vig_prove_seconds
vig_verify_seconds
vig_verdicts_total{result="CONFORMS|DEVIATES|INCOMPLETE|UNDEFINED_SERVED|EXCUSED_RANGE|ESCROW_GAP|ERROR"}
vig_overdue_total  # Proofs past deadline

# Prover resource usage
vig_prover_gpu_utilization
vig_prover_host_memory_bytes
```

## Alerts

From specification section 18. Alert thresholds below are proposed initial values.

### Critical Alerts (Immediate Response)

```yaml
- alert: EngineStartupGateFailure
  expr: vig_engine_startup_gate_failed > 0
  severity: critical
  description: Engine failed float64 check, tensor verification, or canary

- alert: DeviationDetected
  expr: increase(vig_verdicts_total{result="DEVIATES"}[5m]) > 0
  severity: critical
  description: Provider served incorrect output

- alert: LeanVerifierDisagreement
  expr: vig_verifier_disagreement > 0
  severity: critical
  description: cp_verify and Lean verifier disagree on a proof
```

### High Priority

```yaml
- alert: PromiseToSTHExceedsMMD
  expr: vig_promise_to_sth_seconds > 10
  severity: high
  description: Merkle log not keeping up with MMD (10s)

- alert: BeaconLagHigh
  expr: vig_beacon_lag_seconds > 60
  severity: high
  description: Sampler falling behind beacon

- alert: EscrowGap
  expr: increase(vig_escrow_gaps_total[1h]) > 0
  severity: high
  description: Transcripts expired before beacon selection

- alert: SampledCasePastDeadline
  expr: vig_overdue_total{trigger="sampled"} > 0
  severity: high
  description: Sampled proof not delivered within 24h
```

### Medium Priority

```yaml
- alert: QueueFull
  expr: vig_queue_depth >= 4
  severity: medium
  description: Gateway queue at capacity, returning 429

- alert: UnwarrantedReplyRate
  expr: rate(vig_unwarranted_total[1h]) > 0.01
  severity: medium
  description: Unexpected unwarranted replies (>1% of requests)

- alert: HighProofLatency
  expr: histogram_quantile(0.95, vig_prove_seconds) > 120
  severity: medium
  description: p95 proof time above 2 minutes
```

## Structured Logging

### Log Levels

- **ERROR**: Unwarranted replies, range failures, prover failures, beacon unavailable
- **WARN**: Queue near capacity, proof retries, slow operations
- **INFO**: Request IDs, receipt IDs, selections, verdicts, STH updates
- **DEBUG**: Detailed trace (not in production)

### Log Format

JSON structured logs with fields:

```json
{
  "timestamp": "2026-11-20T07:22:00.000Z",
  "level": "INFO",
  "component": "gateway|engine|log|sampler|auditor",
  "event": "request_served|receipt_generated|entry_selected|proof_generated",
  "request_id": "uuid",
  "receipt_id": "rcpt_...",
  "leaf_hash": "...",
  "duration_ms": 123,
  "status": "success|failure",
  "reason": "..."
}
```

### Privacy in Logs

Gateway logs contain:
- Request IDs, sizes, timings, status codes
- Receipt IDs and leaf hashes
- **Never** prompt or reply content
- **Never** user identifiers beyond request ID

Engine logs at INFO level:
- Request IDs
- Token counts
- Latencies
- **No token content** (unless DEBUG level for troubleshooting)

## Monitoring Dashboards

### Gateway Dashboard

- Requests per second (by status code)
- p50, p95, p99 latency
- Queue depth over time
- Unwarranted reply rate
- Engine health (start-up gates, availability)

### Log Dashboard

- Tree size growth
- Promise-to-STH latency
- STH update frequency
- Consistency check results (from monitors)

### Sampler Dashboard

- Beacon lag
- Selections per N (1, 20, 1,000)
- Escrow population
- Gap count

### Auditor Dashboard

- Proof queue depth
- Proof generation time (by trigger: sampled, challenge)
- Verdict counts by result
- Overdue proof count
- Verifier disagreements (cp_verify vs Lean)

## Trace Propagation

Request tracing with OpenTelemetry (optional):

```
span: /v1/chat/completions
  ├─ span: canonical_render
  ├─ span: engine_request
  ├─ span: receipt_generate
  ├─ span: merkle_append
  └─ span: response_encode
```

Each span carries:
- Request ID (never content)
- Latencies
- Component identifiers

## Health Endpoints

Private health checks (not public):

```
GET /health/live    # Liveness: process alive
GET /health/ready   # Readiness: accepting traffic (engine up, log reachable)
GET /health/startup # Startup: engine gates passed
```

Response:

```json
{
  "status": "healthy|degraded|unhealthy",
  "checks": {
    "engine": "pass|fail",
    "log": "pass|fail",
    "beacon": "pass|fail"
  },
  "uptime_seconds": 12345
}
```

### Run the M1 checks

Mount `operations.health.HealthApp` on the private monitoring listener. Supply
startup, engine and log probes that inspect the running service and the
metrics exporter for that same service. Liveness reports process health.
Readiness reevaluates the gates and required dependencies on each request.
A failed probe yields a bounded check status. Its exception text stays private.

Use `operations.telemetry` for structured events, stage timing and metrics.
The shared collector accepts bounded labels and issues its own internal
correlation IDs. Run `make test-telemetry` from the repository root for the
health, privacy and metric checks.
[Operational telemetry contract](../docs/spec/05-observability.md#telemetry-contract)

## Monitor Scripts

A simple log monitor (200-line script in the repository):

1. Fetches STHs periodically
2. Checks consistency between STHs
3. Recomputes selections from log and beacon
4. Compares with audit API selections
5. Alerts on discrepancies

Runs independently by:
- Auditor (validates own selections)
- Third parties (public accountability)

## Performance Baselines

Record at M0 (bring-up) and track over time:

| Metric | M0 Baseline | Regression Alert |
|--------|-------------|------------------|
| Engine decode | 0.60-0.62 s/token | >0.65 s/token |
| Proof generation (1/batch) | 58.8 s | >70 s |
| Verification (single thread) | 21 s | >25 s |
| Receipt generation | <10 ms | >20 ms |
| Merkle append | <50 ms | >100 ms |

## Incident Response Playbooks

### Deviation Detected

1. Alert sent to auditor and router
2. Review audit history for provider
3. Fetch affected verdicts and proofs
4. Escalate to router for provider action
5. Increase sampling to N=1 for provider
6. Consider notifying recent users

### Engine Unwarranted Spike

1. Check engine logs for range failures or forced tokens
2. Identify prompts causing failures
3. If systematic, investigate model or engine version
4. If targeted, potential attack (red team analysis)

### Beacon Unavailable

1. Transcripts queue in escrow
2. Monitor escrow depth
3. If approaching hard cap (5 min), alert users of delay
4. When beacon returns, process backlog
5. Report any gaps (expired transcripts)

## Related Specifications

- `capacity.md`: Performance baselines F22-F27
- `guarantee.md`: Security properties to monitor
- `hardening.md`: Security logging requirements
- `retention.md`: Log retention and privacy
