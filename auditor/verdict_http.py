"""WSGI access to public audit verdicts and capability-scoped private artifacts."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from http import HTTPStatus
from typing import Protocol

from auditor.verdict_signing import public_verdict
from prover.request import VOCABULARY_SIZE, WINDOW

_BASE = "/audit/v1"
_CHALLENGES = _BASE + "/challenges"
_COMMITMENTS = _BASE + "/verdicts"
_RECENT = _COMMITMENTS + "/recent"
_STATS = _BASE + "/stats"
_PRIVATE = re.compile(
    _CHALLENGES + r"/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})(/proof)?"
)
_BEARER = re.compile(r"Bearer +([A-Za-z0-9._~+/-]+=*)", re.ASCII | re.IGNORECASE)
_COUNTS = (
    "total_challenges",
    "conform",
    "deviate",
    "incomplete",
    "excused_range",
    "unavailable",
    "pending",
)

Start = Callable[[str, list[tuple[str, str]]], object]
Route = Callable[[Mapping[str, object], Start], list[bytes]]


class VerdictStore(Protocol):
    def private_status(
        self, challenge_id: str, capability: str, /
    ) -> dict[str, object] | None: ...
    def private_proof(
        self, challenge_id: str, capability: str, /
    ) -> dict[str, object] | None: ...
    def by_commitment(self, t: str, /) -> list[dict[str, object]]: ...
    def recent(self, hours: int, /) -> list[dict[str, object]]: ...
    def stats(self) -> dict[str, object]: ...


def _stats(value: dict[str, object]) -> dict[str, object]:
    counts = {name: value[name] for name in _COUNTS}
    if not all(type(n) is int and n >= 0 for n in counts.values()):
        raise ValueError("Invalid audit statistics")
    at = value["last_updated"]
    if not isinstance(at, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", at
    ):
        raise ValueError("Invalid audit timestamp")
    datetime.fromisoformat(at[:-1] + "+00:00")
    return {**counts, "last_updated": at}


def _artifact(value: dict[str, object]) -> dict[str, object]:
    kind, statement, proof = (
        value.get("kind"),
        value.get("statement"),
        value.get("proof"),
    )
    if (
        kind not in ("conformance", "deviation")
        or not isinstance(statement, str)
        or len(statement) != 8 * (WINDOW + 2)
        or not re.fullmatch(r"[0-9a-f]+", statement)
        or not isinstance(proof, str)
        or not proof
        or len(proof) % 4
        or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", proof)
        or (proof.endswith("==") and proof[-3] not in "AQgw")
        or (
            proof.endswith("=")
            and not proof.endswith("==")
            and proof[-2] not in "AEIMQUYcgkosw048"
        )
        or value.get("y", "00000000") != "00000000"
    ):
        raise ValueError("Invalid proof artifact")
    result: dict[str, object] = {"kind": kind, "statement": statement, "proof": proof}
    if kind == "deviation":
        index, expected = value.get("index"), value.get("expected")
        if (
            type(index) is not int
            or not 0 <= index < 256
            or type(expected) is not int
            or not 0 <= expected < VOCABULARY_SIZE
        ):
            raise ValueError("Invalid deviation artifact")
        result.update(index=index, expected=expected)
    return result


def _status(value: dict[str, object], challenge_id: str) -> dict[str, object]:
    state = value.get("status")
    if value.get("challenge_id") != challenge_id or state not in (
        "pending",
        "verifying",
        "completed",
    ):
        raise ValueError("Invalid audit status")
    result: dict[str, object] = {"challenge_id": challenge_id, "status": state}
    if state == "completed":
        verdict = public_verdict(value.get("verdict"))
        if verdict["challenge_id"] != challenge_id:
            raise ValueError("Incorrect verdict identity")
        result["verdict"] = verdict
    return result


class VerdictApp:
    def __init__(
        self,
        store: VerdictStore,
        *,
        intake: Route | None = None,
        selections: Route | None = None,
    ) -> None:
        self._store, self._intake, self._selections = store, intake, selections

    def __call__(self, env: Mapping[str, object], start_response: Start) -> list[bytes]:
        path = env.get("PATH_INFO")
        method = env.get("REQUEST_METHOD")
        delegate = (
            {
                _CHALLENGES: self._intake,
                _BASE + "/selections": self._selections,
            }.get(path)
            if isinstance(path, str)
            else None
        )
        if delegate is not None:
            # Both mounted WSGI routes produce bounded, buffered responses. Commit
            # their headers only after they return successfully.
            response: list[tuple[str, list[tuple[str, str]]]] = []

            def capture(status: str, headers: list[tuple[str, str]]) -> None:
                response.append(
                    (
                        status,
                        [(k, v) for k, v in headers if k.lower() != "cache-control"],
                    )
                )

            try:
                delegated_body = delegate(env, capture)
                [(status, delegated_headers)] = response
            except Exception:  # noqa: BLE001 -- database and authentication diagnostics are private.
                delegated_body = [b""]
                status, delegated_headers = (
                    "503 Service Unavailable",
                    [("Content-Length", "0")],
                )
            start_response(status, [*delegated_headers, ("Cache-Control", "no-store")])
            return delegated_body
        private = _PRIVATE.fullmatch(path) if isinstance(path, str) else None
        code = HTTPStatus.NOT_FOUND
        body = b""
        headers = [("Cache-Control", "no-store")]
        if private or path in (_COMMITMENTS, _RECENT, _STATS):
            if method != "GET":
                code = HTTPStatus.METHOD_NOT_ALLOWED
                headers.append(("Allow", "GET"))
            else:
                try:
                    code, result = self._read(env, path, private)
                    if code == HTTPStatus.OK:
                        body = json.dumps(
                            result, separators=(",", ":"), allow_nan=False
                        ).encode("ascii")
                        headers.append(("Content-Type", "application/json"))
                except Exception:  # noqa: BLE001 -- never surface service diagnostics or bearer material.
                    code = HTTPStatus.SERVICE_UNAVAILABLE
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{code.value} {code.phrase}", headers)
        return [body]

    def _read(
        self, env: Mapping[str, object], path: object, private: re.Match[str] | None
    ) -> tuple[HTTPStatus, object]:
        query = env.get("QUERY_STRING", "")
        if private:
            credential = env.get("HTTP_AUTHORIZATION")
            bearer = (
                _BEARER.fullmatch(credential) if isinstance(credential, str) else None
            )
            if bearer is None or query:
                return HTTPStatus.NOT_FOUND, None
            challenge_id, download = private.groups()
            if download:
                found = self._store.private_proof(challenge_id, bearer[1])
                if found is not None:
                    return HTTPStatus.OK, _artifact(found)
            else:
                found = self._store.private_status(challenge_id, bearer[1])
                if found is not None:
                    return HTTPStatus.OK, _status(found, challenge_id)
            return HTTPStatus.NOT_FOUND, None
        if not isinstance(query, str):
            return HTTPStatus.BAD_REQUEST, None
        if path == _COMMITMENTS and (
            m := re.fullmatch(r"commitment=([0-9a-f]{64})", query)
        ):
            rows = [public_verdict(v) for v in self._store.by_commitment(m[1])]
            if any(row["transcript_commitment"] != m[1] for row in rows):
                raise ValueError("Incorrect commitment in verdict query")
            return HTTPStatus.OK, {"verdicts": rows}
        if (
            path == _RECENT
            and (m := re.fullmatch(r"hours=0*([1-9][0-9]{0,2})", query))
            and int(m[1]) <= 168
        ):
            return HTTPStatus.OK, {
                "verdicts": [public_verdict(v) for v in self._store.recent(int(m[1]))]
            }
        if path == _STATS and not query:
            return HTTPStatus.OK, _stats(self._store.stats())
        return HTTPStatus.BAD_REQUEST, None
