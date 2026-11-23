"""Validate checksum-pinned milestone reports for an exact release candidate."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from tools.gate_m1 import ROOT

MILESTONES = ("M0", "M1", "M2", "M3", "M4")
_REPORTS = {name: name.lower() + ".json" for name in MILESTONES}


def require(ok: object, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def document(raw: bytes) -> dict[str, Any]:
    def unique(fields: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(fields)
        require(len(result) == len(fields), "duplicate JSON field")
        return result

    def number(text: str) -> float:
        result = float(text)
        require(math.isfinite(result), "nonfinite JSON value")
        return result

    data = json.loads(
        raw, object_pairs_hook=unique, parse_float=number, parse_constant=number
    )
    if not isinstance(data, dict):
        raise TypeError("expected evidence object")
    return data


def fingerprint(value: object, length: int) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch("[a-f0-9]{" + str(length) + "}", value)
    )


def checked_files(
    directory: Path, expected: str, revision: str
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    raw = (directory / "manifest.json").read_bytes()
    require(
        fingerprint(expected, 64) and sha(raw) == expected,
        "untrusted evidence manifest",
    )
    manifest = document(raw)
    require(
        manifest.keys() == {"schema_version", "candidate_revision", "milestones"}
        and type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 1
        and fingerprint(revision, 40)
        and manifest["candidate_revision"] == revision
        and manifest["milestones"].keys() == set(MILESTONES),
        "candidate or milestone set differs",
    )
    reports = {}
    hashes = {}
    for name, filename in _REPORTS.items():
        pin = manifest["milestones"][name]
        require(
            pin.keys() == {"sha256", "source_revision"}
            and fingerprint(pin["sha256"], 64)
            and fingerprint(pin["source_revision"], 40),
            "invalid milestone pin",
        )
        data = (directory / filename).read_bytes()
        require(sha(data) == pin["sha256"], "milestone digest differs")
        report = document(data)
        source = (
            report["source"]["commit"] if name == "M1" else report["source_revision"]
        )
        require(
            type(report["schema_version"]) is int
            and report["schema_version"] == 1
            and report["gate"] == name
            and report["status"] == "passed"
            and source == pin["source_revision"],
            "failed or mismatched milestone",
        )
        reports[name], hashes[name] = report, pin["sha256"]
    return reports, hashes


def linked(reports: dict[str, dict[str, Any]], hashes: dict[str, str]) -> None:
    m0, m1, m2, m3, m4 = (reports[k] for k in MILESTONES)
    primary = m0["platform"]["eligible_startup_sha256"]
    require(
        fingerprint(primary, 64)
        and m0["platform"]["serving_eligibility_scope"] == "primary_engine_only",
        "eligible primary missing",
    )
    require(
        m1["source"]["dirty"] is False and m3["dirty"] is False,
        "CPU evidence from modified source",
    )
    require(
        m2["milestone_evidence_sha256"] == {k: hashes[k] for k in ("M0", "M1")}
        and m4["milestone_evidence_sha256"] == {k: hashes[k] for k in MILESTONES[:-1]}
        and m4["eligible_startup_sha256"] == primary,
        "hardware evidence chain differs",
    )
    checks = m2["checks"]
    require(
        all(
            checks[k] is True
            for k in (
                "elapsed_age_verified",
                "separate_cpu_verifier",
                "reference_trace_bound",
                "receipt_and_verdict_signatures_verified",
                "eligible_primary_and_original_proof_bound",
                "corrected_prefix_matches_proof",
                "capability_isolation_checked",
            )
        )
        and checks["challenge_clock"] == "elapsed_wall_clock"
        and checks["actual_elapsed_seconds"] >= 3 * 86400
        and checks["challenge_age_seconds"] >= 3 * 86400
        and all(
            type(checks[k]) in (int, float)
            for k in ("actual_elapsed_seconds", "challenge_age_seconds")
        )
        and type(checks["conformance_exit"]) is int
        and type(checks["deviation_exit"]) is int
        and (checks["conformance_exit"], checks["deviation_exit"]) == (0, 21),
        "independent historical verification missing",
    )
    from release.soak_report import check_soak

    require(
        fingerprint(m4["archive_sha256"], 64)
        and fingerprint(m4["active_startup_sha256"], 64),
        "missing physical archive binding",
    )
    check_soak(m4)


def verify(
    directory: Path, expected: str, revision: str, package: dict[str, Any]
) -> dict[str, Any]:
    reports, hashes = checked_files(directory, expected, revision)
    linked(reports, hashes)
    # The milestone implementations also check their own fixture contracts and exact inputs.
    from importlib import import_module

    m2 = import_module("tools.gate_m2")
    m4 = import_module("tools.gate_m4")
    for name in ("M0", "M1"):
        require(
            m2.prerequisite(directory / _REPORTS[name], name) == hashes[name],
            "invalid milestone prerequisite",
        )
    require(
        m4.prerequisites(
            {n: str(directory / _REPORTS[n]) for n in MILESTONES[:-1]},
            reports["M4"]["eligible_startup_sha256"],
        )
        == {n: hashes[n] for n in MILESTONES[:-1]},
        "M4 prerequisites differ",
    )
    require(
        reports["M4"]["fixture_digest"]
        == sha((ROOT / "tests/fixtures/m4-chat.jsonl").read_bytes()),
        "soak corpus differs",
    )
    current_m1 = document((ROOT / "build/gates/m1.json").read_bytes())
    current_m3 = document((ROOT / "build/gates/m3.json").read_bytes())
    require(
        current_m1["status"] == "passed"
        and current_m1["source"] == {**reports["M1"]["source"], "commit": revision}
        and current_m1["public_fixtures"] == reports["M1"]["public_fixtures"]
        and current_m1["mode_d"] == reports["M1"]["mode_d"],
        "current M1 fixture replay differs",
    )
    require(
        current_m3["status"] == "passed"
        and current_m3["dirty"] is False
        and current_m3["source_revision"] == revision
        and all(
            current_m3[k] == reports["M3"][k]
            for k in ("fixture_digest", "scenarios", "totals")
        ),
        "current M3 fixture replay differs",
    )
    archived_m3 = reports["M3"]
    component_names = {"m3-admission.json", "m3-evidence.json", "m3-model.json"}
    require(
        archived_m3["artifacts"].keys() == component_names,
        "missing M3 component evidence",
    )
    for filename in sorted(component_names):
        raw = (directory / filename).read_bytes()
        require(
            sha(raw) == archived_m3["artifacts"][filename],
            "M3 component digest differs",
        )
        component = document(raw)
        require(
            component["status"] == "passed"
            and component["source_revision"] == archived_m3["source_revision"],
            "M3 component scope differs",
        )
    original = next(
        r for r in reports["M0"]["replies"] if r["id"] == "arithmetic-apples"
    )
    native = document(
        (ROOT / "distribution/verifier/evidence/native-clean-install.json").read_bytes()
    )
    require(
        native["status"] == "passed"
        and native["wheel_sha256"] == package["wheel_sha256"]
        and native["requirements_sha256"] == package["lock_sha256"]
        and native["installed_runtime_sha256"] == package["native_inputs_sha256"]
        and native["m0_report_sha256"] == hashes["M0"]
        and native["m0_evidence_sha256"] == original["evidence_sha256"]
        and native["original"] == {"exit_code": 0, "outcome": "CONFORMS"}
        and native["single_bit_altered_proof"]
        == {"exit_code": 20, "outcome": "PROOF_REJECTED"}
        and native["verification_network"] == "disabled"
        and native["runtime_configuration"] == "operator_bounds_only",
        "wheel lacks matched native proof qualification",
    )
    return {
        "milestone_sha256": hashes,
        "evidence_manifest_sha256": expected,
        "source_revisions": {
            n: (v["source"]["commit"] if n == "M1" else v["source_revision"])
            for n, v in reports.items()
        },
        "eligible_startup_sha256": reports["M4"]["eligible_startup_sha256"],
        "signed_log_root": reports["M4"]["checks"]["log_root"],
        "soak_archive_sha256": reports["M4"]["archive_sha256"],
        "holder_operation": reports["M4"]["checks"]["holder_operation"],
        "router": reports["M4"]["checks"]["router"],
    }
