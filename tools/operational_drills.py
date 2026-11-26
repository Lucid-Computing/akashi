"""Evaluate private role scrapes and the installed incident rules with promtool."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.gate_m1 import ROOT, _write

MONITORING = ROOT / "operations/monitoring"
RULES = MONITORING / "alerts.yml"
DASHBOARD = MONITORING / "dashboard.json"
_CONDITIONS = {
    "EngineStartupGateFailure": (
        "engine",
        "critical",
        "engine",
        "Engine startup integrity gates failed",
    ),
    "DeviationDetected": (
        "auditor",
        "critical",
        "auditor",
        "An authenticated deviation verdict was published in the last five minutes",
    ),
    "BeaconUnavailable": (
        "sampler",
        "high",
        "sampler",
        "The enabled sampler could not authenticate the beacon",
    ),
    "BeaconLagHigh": (
        "sampler",
        "high",
        "sampler",
        "The authenticated beacon is more than one minute behind",
    ),
    "UnwarrantedReplyRate": (
        "engine",
        "medium",
        "engine",
        "More than one percent of dispatched engine requests were unwarranted",
    ),
    "ObservationUnavailable": (
        "auditor",
        "high",
        "operations",
        "A configured role cannot provide a current observation",
    ),
    "PrivateScrapeUnavailable": (
        None,
        "high",
        "operations",
        "A private monitoring target is down or exposes no role observations",
    ),
    "SignedHistoryIncident": (
        "log",
        "high",
        "log",
        "The independent monitor recorded a signed-history incident",
    ),
}


def _check(name: str, when: str, active: bool, **extra: str) -> dict[str, Any]:
    service, severity, owner, summary = _CONDITIONS[name]
    labels = {"severity": severity, "owner": owner, **extra}
    if service is not None:
        labels["mode"] = "live"
        if name != "UnwarrantedReplyRate":
            labels["service"] = service
    return {
        "alertname": name,
        "eval_time": when,
        "exp_alerts": [{"exp_labels": labels, "exp_annotations": {"summary": summary}}]
        if active
        else [],
    }


def _series(scrapes: dict[str, list[str]]) -> list[dict[str, str]]:
    observed: dict[str, list[str]] = {}
    if set(scrapes) != {"engine", "auditor", "sampler"}:
        raise ValueError("Incomplete private role observations")
    for role, readings in scrapes.items():
        if len(readings) != 3:
            raise ValueError("Incomplete private role observations")
        base = f'service="{role}",mode="live"'
        allowed = {f"akashi_observation_coverage{{{base}}}"}
        if role == "engine":
            allowed.update(
                {
                    f"akashi_engine_startup_gate_failed{{{base}}}",
                    f"akashi_engine_requests_total{{{base}}}",
                    f'akashi_unwarranted_total{{{base},outcome="engine_error",reason="engine_error"}}',
                }
            )
        elif role == "auditor":
            allowed.add(f"akashi_signed_deviations_last_5m{{{base}}}")
        else:
            allowed.update(
                {f"akashi_beacon_available{{{base}}}", f"akashi_beacon_lag_seconds{{{base}}}"}
            )
            allowed.update(
                f'akashi_sampling_coverage{{{base},state="{state}"}}'
                for state in ("available", "disabled", "unknown")
            )
        for i, reading in enumerate(readings):
            for line in reading.splitlines():
                if not line or line.startswith("#"):
                    continue
                sample, value = line.rsplit(" ", 1)
                if sample not in allowed or not math.isfinite(float(value)):
                    raise ValueError("Invalid private fixture metric")
                history = observed.setdefault(sample, ["stale"] * 3)
                if history[i] != "stale":
                    raise ValueError("Duplicate fixture sample")
                history[i] = value
    return [
        {"series": key, "values": " ".join(values)}
        for key, values in sorted(observed.items())
    ]


def _rules_test(series: list[dict[str, str]]) -> dict[str, Any]:
    live = ("EngineStartupGateFailure", "DeviationDetected", "BeaconUnavailable")
    normal = [
        _check(name, f"{minute}m", minute == 1) for name in live for minute in range(3)
    ]
    normal.append(_check("UnwarrantedReplyRate", "1m", True))
    shape = [
        ('akashi_beacon_lag_seconds{service="sampler",mode="live"}', "60 61 60"),
        ('akashi_observation_coverage{service="auditor",mode="live"}', "1 0 1"),
        ('akashi_observation_coverage{service="sampler",mode="live"}', "1 0 1"),
        (
            'akashi_sampling_coverage{service="sampler",mode="live",state="disabled"}',
            "0 1 0",
        ),
        ('up{job="akashi-private",instance="fixture"}', "1 0 1"),
        (
            'akashi_log_checkpoint_known{job="akashi-private",instance="fixture",service="log",mode="live"}',
            "1 stale 1",
        ),
        (
            'akashi_log_incidents_total{service="log",mode="live",kind="omitted_promise"}',
            "0 1 1+0x6",
        ),
    ]
    tested = [
        _check(name, f"{minute}m", minute == 1)
        for name in ("BeaconLagHigh", "ObservationUnavailable")
        for minute in range(3)
    ]
    tested.extend(
        _check(
            "PrivateScrapeUnavailable",
            f"{minute}m",
            minute == 1,
            job="akashi-private",
            instance="fixture",
        )
        for minute in range(3)
    )
    tested.extend(
        _check("SignedHistoryIncident", when, active, kind="omitted_promise")
        for when, active in (("0m", False), ("1m", True), ("7m", False))
    )
    return {
        "rule_files": [str(RULES)],
        "evaluation_interval": "1m",
        "tests": [
            {
                "name": "private role scrapes",
                "interval": "1m",
                "input_series": series,
                "alert_rule_test": normal,
            },
            {
                "name": "monitor and coverage controls",
                "interval": "1m",
                "input_series": [
                    {"series": key, "values": values} for key, values in shape
                ],
                "alert_rule_test": tested,
            },
        ],
    }


def _promtool(*args: str) -> None:
    subprocess.run(
        [str(ROOT / "tools/run-promtool.sh"), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def gate(output: Path) -> bool:
    report: dict[str, object] = {"schema_version": 1, "status": "incomplete"}
    _write(output, report)
    stage = "private_roles"
    try:
        from tests.test_operational_sources import role_drill_scrapes

        series = _series(role_drill_scrapes())
        with tempfile.TemporaryDirectory() as tmp:
            stage = "alert_rules"
            _promtool("check", "rules", str(RULES))
            inputs = Path(tmp) / "drills.yml"
            inputs.write_text(json.dumps(_rules_test(series)))
            _promtool("test", "rules", str(inputs))
            stage = "dashboard_queries"
            dashboard = json.loads(DASHBOARD.read_bytes())
            targets = [
                target["expr"] for p in dashboard["panels"] for target in p["targets"]
            ]
            if not targets:
                raise ValueError("Dashboard has no queries")
            panels = Path(tmp) / "panels.yml"
            panels.write_text(
                json.dumps(
                    {
                        "groups": [
                            {
                                "name": "queries",
                                "rules": [
                                    {"record": f"akashi_drill_panel_{i}", "expr": expr}
                                    for i, expr in enumerate(targets)
                                ],
                            }
                        ]
                    }
                )
            )
            _promtool("check", "rules", str(panels))
        report.update(
            status="passed",
            checked_rules=sorted(_CONDITIONS),
            dashboard_queries=len(targets),
            recovery_checked=[
                "engine_startup",
                "signed_deviation_window",
                "beacon_availability",
            ],
            source_revision=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            artifact_sha256={
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (RULES, DASHBOARD)
            },
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AssertionError,
        RuntimeError,
        ImportError,
        subprocess.SubprocessError,
    ) as exc:
        report.update(failed_stage=stage, reason=type(exc).__name__)
    _write(output, report)
    return report["status"] == "passed"


if __name__ == "__main__":
    output = ROOT / "build/gates/operational-alerts.json"
    passed = gate(output)
    print(
        f"Operational alerts {'passed' if passed else 'incomplete'}. Evidence is in {output}"
    )
    raise SystemExit(0 if passed else 1)
