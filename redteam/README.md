# Red Team

Attack simulation test suite for security validation.

## Purpose

Red team tests exercise all attack vectors R1-R19 from spec § 19 to verify that security properties S1-S7 hold and that deviations are detected.

## Attack Vectors

See `specs/redteam-suite.md` for the complete R1-R19 table with expected outcomes.

## Testing

Run the current CPU regression suite from the repository root. M3 release evidence is recorded separately. [Release gates](../docs/spec/07-testing-strategy.md#release-gates)

```bash
make setup test-unit
```

Exit criteria from spec § 19.2:
- 100% of attacks caught
- 0 false positives
- All 19 attack vectors tested

## Related Specifications

- `specs/redteam-suite.md`: Complete R1-R19 attack list
- `specs/guarantee.md`: Threat model and security properties
- `specs/build-plan.md`: M3 milestone (red team phase)

## Transcript and log evidence

Run `make test-evidence-regressions`. It writes `build/gates/m3-evidence.json` with per-scenario trial and control counts for R10–R17. To use an offline checkout of the pinned F37 assets, set `VIG_RENDER_ASSETS`. The report records the source revision and fixture digests. The proof replay and commitment controls exercise synthetic F9 terminal records through the holder's statement and verifier policy. Physical proof verification has its own milestone evidence. [M3 criteria](../specs/build-plan.md#m3-red-team) · [F9](../specs/facts-register.md#flashprove-foundation)

For a live delivery, a holder can record when it received the signed promise and supply that UTC timestamp to `vig verify` with `--observed-at`. The monitor accepts the same contemporaneous observation via `hold(receipt, observed_at=...)`. An observation more than 30 seconds after the signed time produces a warning and a monitor incident. It records a timing discrepancy that can include delivery latency. When verifying an archived receipt, leave the option unset unless the original delivery observation is available. [R17](../specs/redteam-suite.md)
