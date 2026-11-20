"""R19 checks over signed public fixtures, local callables and disposable SQLite state."""

import hashlib
import io
import json
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import timedelta
from threading import Barrier
from typing import Any

from auditor.challenge_http import ChallengeApp
from tests.test_challenge_intake import ChallengeIntakeTests as _SignedFixture

_EXPECTED = "429/rate_limited + bounded_queue"
_HONEST = "202/pending + independent_handle"
_READERS = {
    name: name
    for name in ("hourly", "reader-a", "reader-b", "reader-c", "reader-d", "eligible")
}
_METRICS = (
    "holder_boundaries",
    "transcript_boundaries",
    "retry_after_verified",
    "durable_queue_verified",
    "dedup_verified",
    "rollovers_verified",
)


@dataclass(frozen=True, repr=False)
class _Reply:
    status: int
    retry: str | None
    doc: dict[str, Any]

    def accepted(self) -> bool:
        return (
            self.status == 202
            and self.retry is None
            and self.doc.get("status") == "pending"
            and set(self.doc) == {"status", "challenge_id", "capability"}
        )

    def limited(self, seconds: int) -> bool:
        return (
            self.status == 429
            and self.retry == str(seconds)
            and self.doc == {"error": {"code": "rate_limited"}}
        )


def _submit(fixture: _SignedFixture, reader: str, bundle: dict[str, Any]) -> _Reply:
    body = json.dumps(
        {"bundle": bundle, "leaf_index": bundle["history"]["inclusion"]["leaf_index"]}
    ).encode()
    # This callable accepts only the fixed local fixture identities. The WSGI
    # request and response stay in memory; no server or socket is opened.
    app = ChallengeApp(
        fixture.reopen().submit, authenticate=_READERS.get, body_limit=len(body)
    )
    metadata: list[tuple[int, str | None]] = []

    def start(status: str, headers: list[tuple[str, str]]) -> None:
        values = dict(headers)
        if values.get("Cache-Control") != "no-store":
            raise ValueError("Private fixture response permitted caching")
        metadata.append((int(status.split()[0]), values.get("Retry-After")))

    payload = b"".join(
        app(
            {
                "PATH_INFO": "/audit/v1/challenges",
                "REQUEST_METHOD": "POST",
                "HTTP_AUTHORIZATION": f"Bearer {reader}",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
            },
            start,
        )
    )
    [(code, retry)] = metadata
    return _Reply(code, retry, json.loads(payload))


def _last_slot(
    fixture: _SignedFixture,
    left: tuple[str, dict[str, Any]],
    right: tuple[str, dict[str, Any]],
) -> tuple[_Reply, _Reply]:
    barrier = Barrier(2)

    def arrive(request: tuple[str, dict[str, Any]]) -> _Reply:
        barrier.wait(timeout=10)
        return _submit(fixture, *request)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(arrive, left)
        second = pool.submit(arrive, right)
        return first.result(), second.result()


def _handles(fixture: _SignedFixture, responses: list[_Reply]) -> list[str]:
    """Check the database's per-reader capability binding without exporting it."""
    handles = [response.doc["challenge_id"] for response in responses]
    caps = [response.doc["capability"] for response in responses]
    if len(set(handles)) != len(handles) or len(set(caps)) != len(caps):
        raise ValueError("Duplicated private fixture handle")
    jobs = []
    with closing(sqlite3.connect(fixture.db)) as db:
        for handle, cap in zip(handles, caps, strict=True):
            row = db.execute(
                "SELECT job_id,capability_hash FROM challenge_handles WHERE challenge_id=?",
                (handle,),
            ).fetchone()
            if row is None or row[1] != hashlib.sha256(cap.encode("ascii")).digest():
                raise ValueError("Private fixture handle differs from committed state")
            jobs.append(str(row[0]))
    return jobs


def _case(number: int) -> tuple[dict[str, bool], bool]:
    fixture = _SignedFixture()
    try:
        fixture.setUp()
        # The existing signed-bundle fixture creates real Ed25519 promises,
        # signed heads and Merkle inclusion paths for distinct synthetic inputs.
        inputs = [fixture.make_bundle(16 * number + i) for i in range(14)]
        initial = [_submit(fixture, "hourly", bundle) for bundle in inputs[:9]]
        if not all(reply.accepted() for reply in initial) or fixture.counts() != (9, 9):
            raise ValueError(
                "Signed fixture admission failed before the hourly boundary"
            )
        hour = _last_slot(fixture, ("hourly", inputs[9]), ("hourly", inputs[10]))
        hour_winners = [r for r in hour if r.accepted()]
        hour_ok = len(hour_winners) == 1 and sorted(r.status for r in hour) == [
            202,
            429,
        ]
        hour_count = fixture.counts() == (10, 10)
        target = inputs[11]
        shared = [
            _submit(fixture, reader, target) for reader in ("reader-a", "reader-b")
        ]
        if not all(reply.accepted() for reply in shared):
            raise ValueError(
                "Signed fixture admission failed before the daily boundary"
            )
        day = _last_slot(fixture, ("reader-c", target), ("reader-d", target))
        day_winners = [r for r in day if r.accepted()]
        day_ok = len(day_winners) == 1 and sorted(r.status for r in day) == [202, 429]
        before = fixture.counts()
        # These probes use newly opened intake connections and verify the actual
        # Retry-After header. Neither refusal may create a handle or work item.
        holder_refused = _submit(fixture, "hourly", inputs[13])
        transcript_refused = _submit(fixture, "eligible", target)
        queue_ok = hour_count and before == fixture.counts() == (13, 11)
        retries = (
            sum(r.limited(3600) for r in hour) == 1
            and sum(r.limited(86400) for r in day) == 1
            and holder_refused.limited(3600)
            and transcript_refused.limited(86400)
        )
        winners = initial + hour_winners + shared + day_winners
        ids = _handles(fixture, winners)
        dedup = (
            hour_ok
            and day_ok
            and len(set(ids[:10])) == 10
            and len(set(ids[10:])) == 1
            and ids[-1] not in ids[:10]
        )
        # A genuinely eligible reader and transcript still get their own durable
        # work while the original holder and the shared transcript remain full.
        eligible = _submit(fixture, "eligible", inputs[12])
        honest = eligible.accepted() and fixture.counts() == (14, 12)
        if honest:
            jobs = _handles(fixture, [*winners, eligible])
            honest = jobs[-1] not in jobs[:-1]
        fixture.clock = fixture.received + timedelta(hours=1, microseconds=-1)
        almost_hour = _submit(fixture, "hourly", inputs[13])
        hour_unchanged = fixture.counts() == (14, 12)
        fixture.clock = fixture.received + timedelta(hours=1)
        fresh_hour = _submit(fixture, "hourly", inputs[13])
        fixture.clock = fixture.received + timedelta(days=1, microseconds=-1)
        almost_day = _submit(fixture, "eligible", target)
        day_unchanged = fixture.counts() == (15, 13)
        fixture.clock = fixture.received + timedelta(days=1)
        fresh_day = _submit(fixture, "eligible", target)
        rolled = (
            almost_hour.limited(1)
            and almost_day.limited(1)
            and hour_unchanged
            and day_unchanged
            and fresh_hour.accepted()
            and fresh_day.accepted()
            and fixture.counts() == (16, 13)
        )
        if rolled and honest:
            final = _handles(fixture, [*winners, eligible, fresh_hour, fresh_day])
            rolled = final[-2] not in final[:-2] and final[-1] == ids[-1]
        return {
            "holder_boundaries": hour_ok,
            "transcript_boundaries": day_ok,
            "retry_after_verified": retries,
            "durable_queue_verified": queue_ok,
            "dedup_verified": dedup,
            "rollovers_verified": rolled,
        }, honest
    finally:
        fixture.doCleanups()


def run_admission_cases() -> list[dict[str, object]]:
    """Run twenty independent pairs of hourly and daily boundary checks offline."""
    observed: Counter[str] = Counter()
    honest: Counter[str] = Counter()
    metrics = {name: 0 for name in _METRICS}
    for number in range(20):
        checks, passed = _case(number)
        for name in _METRICS:
            metrics[name] += int(checks[name])
        observed[_EXPECTED if all(checks.values()) else "BOUNDARY_CHECK_FAILED"] += 1
        honest[_HONEST if passed else "ELIGIBLE_CONTROL_FAILED"] += 1
    return [
        {
            "scenario": "R19",
            "trials": observed.total(),
            "caught": observed[_EXPECTED],
            "expected": _EXPECTED,
            "observed": dict(observed),
            "honest_controls": honest.total(),
            "honest_passed": honest[_HONEST],
            "honest_expected": _HONEST,
            "honest_observed": dict(honest),
            **metrics,
        }
    ]
