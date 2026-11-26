"""R16/R17 defense checks using fixed local test identities and two offline snapshots."""

import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from auditor.beacon import round_for
from gateway.discovery import ServiceConfig
from gateway.renderer import RAW_PROFILE_DIGEST
from log.monitor import LogMonitor
from log.receipt import leaf_hash, params_digest, transcript_commitment
from log.store import MerkleLog
from prover.submission import COMMITMENT
from tests.test_discovery import CONFIG
from tests.test_log_store import KEY, KEY_ID, LOG_ID, preimage
from verifier.holder import verify

_SERVED = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
_BOUNDARY = _SERVED + timedelta(seconds=30)
_SALT = "23" * 32  # Published, synthetic fixture material.
_COUNT = 20


def _snapshot(root: Path, name: str, stamp: datetime) -> MerkleLog:
    return MerkleLog(
        root / name,
        log_id=LOG_ID,
        log_key_id=KEY_ID,
        signing_key=KEY,  # RFC 8032 public test key.
        leaf_hash=leaf_hash,
        clock=lambda: stamp,
    )


def _bundle(log: MerkleLog, index: int) -> dict[str, Any]:
    prompt, reply = [9, index + 2], [400 + index]
    fields = {
        **preimage(index),
        "served_at": _SERVED.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "render_profile": RAW_PROFILE_DIGEST,
        "beacon_round": round_for(_SERVED),
        "params_digest": params_digest(1),
        "transcript_commitment": transcript_commitment(
            COMMITMENT, RAW_PROFILE_DIGEST, 1, _SALT, prompt, reply
        ),
    }
    receipt = log.append(fields)
    assert receipt.pop("leaf_index") == index
    receipt["salt"] = _SALT
    return {
        "input": prompt,
        "text": None,
        "max_tokens": 1,
        "verification": {
            "version": "akashi/1",
            "receipt": receipt,
            "prompt_token_ids": prompt,
            "reply_token_ids": reply,
        },
    }


def _monitor(path: Path, now: datetime) -> LogMonitor:
    keys = {("log", KEY_ID): KEY.public_key().public_bytes_raw()}
    return LogMonitor(
        path, log_id=LOG_ID, lookup_key=lambda r, k: keys[r, k], clock=lambda: now
    )


def _summary(
    scenario: str,
    expected: str,
    samples: list[str],
    honest_expected: str,
    controls: list[str],
) -> dict[str, object]:
    observed, honest = Counter(samples), Counter(controls)
    return {
        "scenario": scenario,
        "trials": len(samples),
        "caught": observed[expected],
        "expected": expected,
        "observed": dict(observed),
        "honest_controls": len(controls),
        "honest_passed": honest[honest_expected],
        "honest_expected": honest_expected,
        "honest_observed": dict(honest),
    }


def run_history_cases() -> list[dict[str, object]]:
    descriptor = ServiceConfig(
        **{
            **CONFIG,
            "log_id": LOG_ID,
            "log_key_id": KEY_ID,
            "log_public_key": KEY.public_key().public_bytes_raw().hex(),
        }
    ).descriptor()
    omitted, backdated, included, clean = [], [], [], []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        delivered = _snapshot(root, "issued.db", _SERVED)
        bundles = [_bundle(delivered, i) for i in range(_COUNT)]
        full_head = delivered.head()
        full: dict[str, object] = {
            "sth": full_head,
            **{f"receipts/{i}": delivered.receipt(i) for i in range(_COUNT)},
        }
        # A second fixed snapshot was empty at this signed post-MMD time.
        empty = {"sth": _snapshot(root, "empty.db", _BOUNDARY).head()}

        for i, bundle in enumerate(bundles):
            receipt = bundle["verification"]["receipt"]
            holder_missing = verify(
                bundle, descriptor, now=_BOUNDARY, receipt_only=True
            )
            missing_db = root / f"missing-{i}.db"
            missing = _monitor(missing_db, _BOUNDARY)
            missing.hold(receipt, observed_at=_SERVED)
            missing.observe(empty.__getitem__)
            incidents = _monitor(missing_db, _BOUNDARY).incidents()
            omission = (
                holder_missing.outcome == "INCLUSION_UNAVAILABLE"
                and holder_missing.warnings == ("MERGE_DEADLINE_ELAPSED",)
                and len(incidents) == 1
                and incidents[0]["kind"] == "omitted_promise"
                and incidents[0]["promise"]
                == {k: v for k, v in receipt.items() if k != "salt"}
                and incidents[0]["checkpoint"] == empty["sth"]
            )
            omitted.append(
                "omitted_promise" if omission else "missing_omission_evidence"
            )
            bundle["history"] = {
                "sth": full_head,
                "inclusion": {
                    "tree_size": _COUNT,
                    "leaf_index": i,
                    "audit_path": [node.hex() for node in delivered.path(i, _COUNT)],
                },
            }
            ordinary = _monitor(root / f"included-{i}.db", _BOUNDARY)
            ordinary.hold(receipt, observed_at=_BOUNDARY)
            ordinary.observe(full.__getitem__)
            holder = verify(
                bundle,
                descriptor,
                now=_BOUNDARY,
                observed_at=_BOUNDARY,
                receipt_only=True,
            )
            verified = holder.outcome == "RECEIPT_VERIFIED" and not holder.warnings
            quiet = (
                not ordinary.incidents()
                and ordinary.verified_leaf(i) == full[f"receipts/{i}"]
            )
            included.append(
                "included" if verified and quiet else "unexpected_inclusion_result"
            )
            clean.append(
                "receipt_verified + no_alert"
                if verified and quiet
                else "unexpected_boundary_result"
            )

            seen = _BOUNDARY + timedelta(milliseconds=i + 1)
            late = _monitor(root / f"delivery-{i}.db", seen)
            late.hold(receipt, observed_at=seen)
            late.observe(full.__getitem__)
            holder = verify(
                bundle, descriptor, now=seen, observed_at=seen, receipt_only=True
            )
            incidents = late.incidents()
            detected = (
                holder.outcome == "RECEIPT_VERIFIED"
                and holder.warnings == ("PROMISE_BACKDATED",)
                and len(incidents) == 1
                and incidents[0]["kind"] == "promise_backdated"
                and incidents[0]["promise"]["promise_sig"] == receipt["promise_sig"]
                and incidents[0]["observed_at"] == seen.isoformat()
            )
            backdated.append(
                "PROMISE_BACKDATED + promise_backdated"
                if detected
                else "missing_delivery_warning"
            )
    return [
        _summary("R16", "omitted_promise", omitted, "included", included),
        _summary(
            "R17",
            "PROMISE_BACKDATED + promise_backdated",
            backdated,
            "receipt_verified + no_alert",
            clean,
        ),
    ]
