# Red Team

Attack simulation test suite for security validation.

## Purpose

Red team tests exercise all attack vectors R1-R19 from spec § 19 to verify that security properties S1-S7 hold and that deviations are detected.

## Attack Vectors

See `specs/redteam-suite.md` for the complete R1-R19 table with expected outcomes.

## Testing

```bash
cd redteam/
pytest tests/ -v
```

Exit criteria from spec § 19.2:
- 100% of attacks caught
- 0 false positives
- All 19 attack vectors tested

## Related Specifications

- `specs/redteam-suite.md`: Complete R1-R19 attack list
- `specs/guarantee.md`: Threat model and security properties
- `specs/build-plan.md`: M3 milestone (red team phase)
