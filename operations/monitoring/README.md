# Operational alerts and incident response

Serve role metrics and readiness on the existing private listener. Configure a Prometheus scrape job named `akashi-private` with one target per role listener. A target needs the role's existing access controls. Keep this listener outside the public gateway and router. Load `alerts.yml` as a Prometheus rule file. Import `dashboard.json` into Grafana and select the private Prometheus data source. Configure notification routing for the owner labels in the deployment's Alertmanager. [Observability contract](../../docs/spec/05-observability.md#telemetry-contract) · [Prometheus alert rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/) · [Grafana dashboard JSON](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/view-dashboard-json-model/)

## Engine integrity

The engine owner checks private startup readiness and the failing gate. Keep the gateway ineligible during startup, repeat float64, tensor and canary checks using the pinned deployment, then verify readiness and observe a successful request. For an increase in unwarranted replies, inspect bounded integrity reasons and deployed model versions. The alert divides unwarranted outcomes by all dispatched engine requests during the same hour and compares the fraction to the proposed one-percent threshold. Record the gate state, count, fraction and recovery time. [Engine integrity gates](../../specs/engine.md) · [Proposed thresholds](../../specs/observability.md#alerts)

## Signed deviation

The auditor verifies the signed public verdict against its archived key and checks the proof through the holder-authorized route. The router owner reviews the affected provider and can move it to the specified N=1 mode. Preserve signed public metadata and the private holder's custody of its proof. Record the public verification outcome and the response owners in the incident. The five-minute alert window can clear while the historical verdict remains valid. [Deviation playbook](../../specs/observability.md#deviation-detected) · [Audit protocol](../../specs/audit-protocol.md)

## Beacon coverage

The sampler owner checks whether sampling is enabled and whether the current observation authenticated against the pinned quicknet chain. Inspect lag and escrow age on the role's private interface, preserve the original assigned rounds, and replay eligible handoffs when observation resumes. At the five-minute escrow expiry, retain the public gap for reconciliation. Record the coverage state, verified lag and gap count. A disabled sampler and a missing observation have distinct readouts. [Beacon recovery](../../specs/observability.md#beacon-unavailable) · [Escrow expiry](../../specs/sampling.md#selection-rule)

## Signed history

The log monitor owner checks the last verified tree size and the incident kind. Preserve the stored signed promise or conflicting checkpoints before restarting observation. Historical incident counters survive process restart. A new observation can clear the alert window while the original evidence remains in the monitor ledger. Keep signatures, leaf-level evidence and private holder material out of notifications. [Independent monitor](../../log/README.md) · [Security properties](../../specs/guarantee.md)

## Run the drills

From the repository root, run `make setup test-operational-alerts`. The target exercises private role sources and evaluates the installed rules with real `promtool`. Set `PROMTOOL` to an existing executable for an offline run. On Linux x86-64 and macOS arm64, the helper can obtain the checksum-pinned 3.16.0 release in `build/tools`. The drill report in `build/gates/operational-alerts.json` contains the checked conditions and recovery results. [Prometheus rule tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/) · [Prometheus 3.16.0](https://github.com/prometheus/prometheus/releases/tag/v3.16.0)

## Connect the private listeners

- **Engine.** Keep one `operations.role_metrics.EngineMetrics(mode=...)` per gateway process. Pass it to `attach_engine(..., metrics=registry)` on each attachment. On the private `HealthApp`, use `startup=registry.startup_passed`, the active adapter's `ready` property for the engine probe, the configured log probe, and `metrics=registry.prometheus`. The counter starts after successful attachment and excludes startup canaries.
- **Sampler.** Construct `BeaconMetrics` with the role's configured sampling-enabled flag and a reader yielding the quicknet metadata and latest signed round. Pass `beacon=registry.ready` and `metrics=registry.prometheus` to the private app. Missing evidence omits lag. Explicitly disabled sampling has its own state.
- **Auditor.** Use `SignedVerdictMetrics(recent=store.recent, lookup_key=archive.lookup, mode=...)` on the auditor's private listener with its readiness probe and `metrics=registry.prometheus`. The role verifies recent signed public records against archived keys. The mode identifies the monitored deployment. A complete trusted public history is required for a zero count.
- **Log monitor.** Supply `metrics=lambda: monitor.prometheus(mode=...)`. The exporter reads the verified checkpoint and groups retained incidents by bounded kind in one transaction. A monitor with no verified checkpoint omits tree size. Use `monitor.incidents()` inside the role for the signed witness.

A private listener exposes one registry. Configure separate scrape targets for separate registries. [Private health application](../health.py) · [Role metric sources](../role_metrics.py) · [Monitor](../../log/monitor.py)
