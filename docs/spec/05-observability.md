# Observability

## Telemetry contract

Emit structured events with timestamp, severity, service, event name, optional internal correlation ID and bounded reason. Emit counters for request outcomes, gates and unwarranted replies, append failures, beacon status and selection gaps, and proof and verdict outcomes. Record durations as seconds and state depths as gauges; track gateway wait, engine decode, log merge and proof phases separately. Use service, mode and outcome labels; keep subject identifiers and tokens out of metric labels.

Maintain health and readiness separately. Readiness covers the serving gates and required downstream services. Trace stage boundaries with internal correlation only. Redact prompts, reply text, token IDs, salt, challenge and pickup capabilities, keys and proof material before telemetry serialization. Correlation IDs must not function as public lookup credentials.

Alert and dashboard definitions follow [observability](../../specs/observability.md#alerts). Preserve signed evidence for log omissions and inconsistency. Classify missing data or disabled coverage as distinct from zero incidents. Run incident drills for deviation, engine integrity spikes and unavailable beacon; record the accountable owner and recovery evidence.
