"""A restartable Mode R holder for the fixed synthetic M4 workload."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import ssl
import stat
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import rfc8785

from auditor.verdict_signing import verify_signed
from log.receipt import checked_public_leaf
from log.verification import verify_head
from operations.private_db import private_database_file
from pickup.crypto import VERSION, lookup_id
from pickup.crypto import open as open_pickup
from prover.request import END_TOKENS
from router.mock import origin
from verifier.holder import verify

Json = dict[str, Any]
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*", re.ASCII)
_FINAL = {"recovered", "conforms", "deviates", "excused_range", "failed", "unwarranted"}
_STAGE = {
    "new": "checkpoint",
    "chat_post": "chat",
    "pickup": "pickup",
    "history": "receipt",
    "submit": "challenge",
    "challenge_post": "challenge",
    "poll": "verdict",
    "recovered": "receipt",
    "conforms": "proof",
    "deviates": "proof",
    "excused_range": "verdict",
    "unwarranted": "chat",
}
_PUBLISHED = (
    "leaf_index",
    "leaf_hash",
    "transcript_commitment",
    "proof_sha256",
    "statement_sha256",
    "prompt_tokens",
    "reply_tokens",
    "http_status",
    "verdict_sha256",
    "verdict_outcome",
    "verdict_reason",
)


def _require(value: bool) -> None:
    if not value:
        raise ValueError("Invalid holder input or evidence")


def _unique(pairs: list[tuple[str, Any]]) -> Json:
    result = dict(pairs)
    _require(len(result) == len(pairs))
    return result


def _read_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique)


def _private_config(path: Path) -> Json:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        _require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_mode & 0o077 == 0
        )
        data = _read_json(file.read())
        _require(isinstance(data, dict))
        return dict(data)


def _absolute(value: object) -> Path:
    _require(isinstance(value, str) and Path(value).is_absolute())
    return Path(str(value))


def _endpoint(
    value: str, substitute: str | None = None, *, loopback: bool = False
) -> str:
    parsed = urlsplit(value)
    server = origin(f"{parsed.scheme}://{parsed.netloc}")
    _require(
        not parsed.query
        and not parsed.fragment
        and "\\" not in parsed.path
        and not any(ord(c) <= 32 for c in parsed.path)
    )
    if substitute is not None:
        _require(server.scheme == "https")
        server = origin(substitute)
    if loopback or substitute is not None or server.scheme == "http":
        _require(server.hostname in ("127.0.0.1", "::1"))
    return f"{server.scheme}://{server.netloc}{parsed.path}".rstrip("/")


class _Pending(Exception):
    pass


class _Reload(Exception):
    pass


def _report(phase: str, state: Json) -> Json:
    status = (
        phase
        if phase in _FINAL
        else "uncertain"
        if phase in ("chat_post", "challenge_post")
        else "pending"
    )
    return {
        "schema_version": 1,
        "status": status,
        "stage": state.get("failed_stage", _STAGE.get(phase, "state")),
        **{k: state[k] for k in _PUBLISHED if k in state},
    }


class SoakHolder:
    def __init__(
        self,
        config: Json,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        required = {
            "state",
            "descriptor",
            "assets",
            "runtime",
            "router_origin",
            "inference_bearer",
            "challenge_bearer",
            "timeout_seconds",
            "max_response_bytes",
        }
        _require(
            required <= config.keys() <= required | {"ca_file", "loopback_origins"}
        )
        self.clock = clock
        self.path, self.assets = _absolute(config["state"]), _absolute(config["assets"])
        self.descriptor: Json = _read_json(_absolute(config["descriptor"]).read_bytes())
        self.runtime: Json = _read_json(_absolute(config["runtime"]).read_bytes())
        self.limit, self.timeout = (
            config["max_response_bytes"],
            config["timeout_seconds"],
        )
        _require(
            type(self.limit) is int
            and self.limit > 0
            and type(self.timeout) in (int, float)
            and math.isfinite(self.timeout)
            and self.timeout > 0
        )
        self.tls = ssl.create_default_context(
            cafile=str(_absolute(config["ca_file"])) if "ca_file" in config else None
        )
        self.chat_auth, self.audit_auth = (
            config["inference_bearer"],
            config["challenge_bearer"],
        )
        _require(
            all(
                isinstance(v, str) and _BEARER.fullmatch(v)
                for v in (self.chat_auth, self.audit_auth)
            )
        )
        overrides = config.get("loopback_origins", {})
        _require(
            isinstance(overrides, dict)
            and overrides.keys() <= {"log", "pickup", "audit"}
        )
        origin(config["router_origin"])
        self.chat_url = (
            _endpoint(config["router_origin"], loopback=True) + "/v1/chat/completions"
        )
        desc = self.descriptor
        self.log = _endpoint(desc["log"]["url"], overrides.get("log"))
        self.pickup = _endpoint(desc["pickup_url"], overrides.get("pickup"))
        self.challenge = _endpoint(desc["challenge_url"], overrides.get("audit"))
        audit = _endpoint(desc["audit_url"], overrides.get("audit"))
        _require(self.challenge == audit + "/challenges")
        self.keys: dict[tuple[str, str], bytes] = {}
        key_rows = [
            {
                "role": "auditor",
                "key_id": desc["auditor_key_id"],
                "public_key": desc["auditor_public_key"],
            },
            {
                "role": "log",
                "key_id": desc["log"]["log_key_id"],
                "public_key": desc["log"]["log_public_key"],
            },
            *desc.get("verification_keys", []),
        ]
        for row in key_rows:
            key = (row["role"], row["key_id"])
            raw = bytes.fromhex(row["public_key"])
            _require(
                key[0] in ("log", "auditor")
                and len(raw) == 32
                and self.keys.setdefault(key, raw) == raw
            )
        private_database_file(self.path)
        # Bind pending private capabilities to the same endpoints, log, identity and model across restarts.
        scope = hashlib.sha256(
            rfc8785.dumps(
                [
                    self.chat_url,
                    self.log,
                    self.pickup,
                    self.challenge,
                    desc["log"]["log_id"],
                    desc["model"],
                    self.chat_auth,
                    self.audit_auth,
                ]
            )
        ).hexdigest()
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL)"
            )
            db.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (scope,))
            _require(db.execute("SELECT scope FROM identity").fetchone()[0] == scope)
            db.execute(
                "CREATE TABLE IF NOT EXISTS holder_cases(id TEXT PRIMARY KEY, request BLOB NOT NULL,phase TEXT NOT NULL, state TEXT NOT NULL)"
            )

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA secure_delete=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db

    def _key(self, role: str, kid: str) -> bytes:
        return self.keys[role, kid]

    def _request(
        self, url: str, *, data: Json | None = None, bearer: str | None = None
    ) -> tuple[int, dict[str, str], Any]:
        parts = urlsplit(url)
        assert parts.hostname is not None
        connection = (
            HTTPSConnection(
                parts.hostname, parts.port, timeout=self.timeout, context=self.tls
            )
            if parts.scheme == "https"
            else HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        )
        headers = {"Accept": "application/json"}
        if bearer is not None:
            headers["Authorization"] = "Bearer " + bearer
        payload = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(
                data, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode()
        with closing(connection):
            path = parts.path + ("?" + parts.query if parts.query else "")
            connection.request(
                "POST" if data is not None else "GET",
                path,
                body=payload,
                headers=headers,
            )
            with connection.getresponse() as reply:
                raw = reply.read(self.limit + 1)
                _require(len(raw) <= self.limit)
                hdr = {k.lower(): v for k, v in reply.getheaders()}
                if raw and 200 <= reply.status < 300:
                    doc = _read_json(raw)
                else:
                    try:
                        doc = _read_json(raw) if raw else None
                    except (ValueError, RecursionError):
                        doc = None
                return reply.status, hdr, doc

    def _get(
        self, url: str, *, private: bool = False, bearer: str | None = None
    ) -> Any:
        code, headers, doc = self._request(url, bearer=bearer)
        if code in (404, 429, 500, 502, 503, 504):
            raise _Pending
        _require(
            code == 200 and (not private or headers.get("cache-control") == "no-store")
        )
        return doc

    def _head(self) -> Json:
        raw = self._get(self.log + "/sth")
        verify_head(raw, log_id=self.descriptor["log"]["log_id"], lookup_key=self._key)
        return dict(raw)

    def _save(self, case_id: str, before: str, after: str, data: Json) -> None:
        generation = data.get("generation", 0)
        data["generation"] = generation + 1
        with self._db() as db:
            changed = db.execute(
                """UPDATE holder_cases SET phase=?,state=? WHERE id=? AND phase=?
                   AND COALESCE(json_extract(state,'$.generation'),0)=?""",
                (after, json.dumps(data, allow_nan=False), case_id, before, generation),
            ).rowcount
            if changed != 1:
                raise _Reload

    def advance(self, case: Json) -> Json:
        _require(
            case.keys() == {"case_id", "messages", "max_tokens", "challenge"}
            and isinstance(case["case_id"], str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case["case_id"]) is not None
            and isinstance(case["messages"], list)
            and bool(case["messages"])
            and type(case["max_tokens"]) is int
            and 1 <= case["max_tokens"] <= self.descriptor["max_tokens_cap"]
            and type(case["challenge"]) is bool
        )
        name = case["case_id"]
        request = rfc8785.dumps(case)
        with self._db() as db:
            db.execute(
                "INSERT OR IGNORE INTO holder_cases VALUES(?,?,'new','{}')",
                (name, request),
            )
            _require(
                db.execute(
                    "SELECT request FROM holder_cases WHERE id=?", (name,)
                ).fetchone()[0]
                == request
            )
        while True:
            with self._db() as db:
                phase, serialized = db.execute(
                    "SELECT phase,state FROM holder_cases WHERE id=?", (name,)
                ).fetchone()
            state: Json = json.loads(serialized)
            if phase in _FINAL or phase in ("chat_post", "challenge_post"):
                return _report(phase, state)
            try:
                if phase == "new":
                    head = self._head()
                    state.update(
                        before=head,
                        cursor=head["tree_size"],
                        secret=secrets.token_hex(32),
                    )
                    self._save(name, phase, "chat_post", state)
                    phase = "chat_post"
                    body = {
                        "model": self.descriptor["model"],
                        "messages": case["messages"],
                        "max_tokens": case["max_tokens"],
                        "user": VERSION + ":" + state["secret"],
                    }
                    code, headers, reply = self._request(
                        self.chat_url, data=body, bearer=self.chat_auth
                    )
                    if code != 200:
                        state["http_status"] = code
                    if (
                        code == 502
                        and isinstance(reply, dict)
                        and isinstance(reply.get("error"), dict)
                        and reply["error"].get("code") == "unwarranted_reply"
                        and "verification" not in reply
                        and "x-akashi-receipt" not in headers
                    ):
                        self._save(name, phase, "unwarranted", state)
                        return _report("unwarranted", state)
                    if code >= 500:
                        self._save(name, phase, phase, state)
                        return _report(phase, state)
                    _require(
                        code == 200
                        and isinstance(reply, dict)
                        and "verification" not in reply
                        and "pickup_id" not in reply
                        and "x-akashi-receipt" not in headers
                        and reply["object"] == "chat.completion"
                        and reply["model"] == body["model"]
                        and len(reply["choices"]) == 1
                    )
                    choice = reply["choices"][0]
                    _require(
                        choice["message"]["role"] == "assistant"
                        and isinstance(choice["message"]["content"], str)
                        and type(choice["index"]) is int
                        and choice["index"] == 0
                        and choice["finish_reason"] in ("length", "stop")
                    )
                    state.update(reply=reply, at=self.clock().isoformat())
                    self._save(name, phase, "pickup", state)
                elif phase == "pickup":
                    text = state["reply"]["choices"][0]["message"]["content"]
                    secret = bytes.fromhex(state["secret"])
                    digest = lookup_id(
                        case["messages"], case["max_tokens"], text, secret
                    )
                    envelope = self._get(self.pickup + "/" + digest, private=True)
                    opened = open_pickup(
                        envelope, secret, case["messages"], case["max_tokens"], text
                    )
                    _require(opened.get("pickup_id", digest) == digest)
                    state["bundle"] = {
                        "verification": opened,
                        "input": case["messages"],
                        "max_tokens": case["max_tokens"],
                        "text": text,
                    }
                    del state["secret"]
                    self._save(name, phase, "history", state)
                elif phase == "history":
                    if not self._history(state):
                        self._save(name, phase, phase, state)
                        return _report(phase, state)
                    self._save(
                        name,
                        phase,
                        "submit" if case["challenge"] else "recovered",
                        state,
                    )
                elif phase == "submit":
                    if self.clock().timestamp() < state.get("eligible", 0):
                        return _report(phase, state)
                    self._save(name, phase, "challenge_post", state)
                    phase = "challenge_post"
                    code, headers, handle = self._request(
                        self.challenge,
                        data={
                            "bundle": state["bundle"],
                            "leaf_index": state["leaf_index"],
                        },
                        bearer=self.audit_auth,
                    )
                    if code >= 500:
                        return _report(phase, state)
                    _require(headers.get("cache-control") == "no-store")
                    if code == 429:
                        retry = headers.get("retry-after", "")
                        _require(
                            isinstance(handle, dict)
                            and handle == {"error": {"code": "rate_limited"}}
                            and re.fullmatch("[1-9][0-9]{0,4}", retry) is not None
                            and int(retry) <= 86400
                        )
                        state["eligible"] = self.clock().timestamp() + int(retry)
                        self._save(name, phase, "submit", state)
                        return _report("submit", state)
                    _require(
                        code == 202
                        and isinstance(handle, dict)
                        and handle.keys() == {"challenge_id", "capability", "status"}
                        and str(UUID(handle["challenge_id"])) == handle["challenge_id"]
                        and handle["status"] == "pending"
                        and isinstance(handle["capability"], str)
                        and _BEARER.fullmatch(handle["capability"]) is not None
                    )
                    state.update(
                        handle=handle["challenge_id"], capability=handle["capability"]
                    )
                    self._save(name, phase, "poll", state)
                elif phase == "poll":
                    terminal = self._proof(state)
                    self._save(name, phase, terminal, state)
                else:
                    raise ValueError("Unknown private holder phase")
            except _Reload:
                continue
            except (_Pending, OSError, HTTPException):
                return _report(phase, state)
            except (
                KeyError,
                TypeError,
                ValueError,
                AttributeError,
                OverflowError,
                IndexError,
            ):
                state["failed_stage"] = _STAGE[phase]
                try:
                    self._save(name, phase, "failed", state)
                except _Reload:
                    continue
                return _report("failed", state)

    def _history(self, state: Json) -> bool:
        head = self._head()
        size = head["tree_size"]
        start = state["cursor"]
        _require(type(start) is int and 0 <= start <= size)
        bundle = state["bundle"]
        verification = bundle["verification"]
        rec = verification["receipt"]
        old = state["before"]
        consistency = self._get(
            f"{self.log}/consistency?from={old['tree_size']}&to={size}"
        )
        # One small bounded page per poll also supports other traffic on this log.
        end = min(size, start + 32)
        rows = self._get(f"{self.log}/receipts/range?start={start}&end={end}")
        _require(isinstance(rows, list) and len(rows) == end - start)
        for index, row in enumerate(rows, start=start):
            public = checked_public_leaf(
                row, index=index, log_id=self.descriptor["log"]["log_id"]
            )
            if public["leaf_hash"] != rec["leaf_hash"]:
                continue
            bundle["history"] = {
                "sth": head,
                "consistency": consistency,
                "inclusion": self._get(f"{self.log}/proof/{index}?size={size}"),
            }
            _require(bundle["history"]["inclusion"]["leaf_index"] == index)
            result = verify(
                bundle,
                self.descriptor,
                old,
                assets=self.assets,
                receipt_only=True,
                now=self.clock(),
                observed_at=datetime.fromisoformat(state["at"]),
            )
            if result.outcome in (
                "ASSETS_UNAVAILABLE",
                "INCLUSION_UNAVAILABLE",
                "CONSISTENCY_UNAVAILABLE",
            ):
                raise _Pending
            _require(
                result.outcome == "RECEIPT_VERIFIED"
                and not result.warnings
                and rec["sampling_mode"] == "soak"
            )
            reply = state["reply"]
            usage = reply["usage"]
            p, r = (
                len(verification["prompt_token_ids"]),
                len(verification["reply_token_ids"]),
            )
            _require(
                reply["id"] == "chatcmpl-" + rec["request_id"]
                and type(reply["created"]) is int
                and reply["created"]
                == int(
                    datetime.fromisoformat(rec["served_at"][:-1] + "+00:00").timestamp()
                )
                and all(
                    type(usage.get(k)) is int and usage[k] == v
                    for k, v in (
                        ("prompt_tokens", p),
                        ("completion_tokens", r),
                        ("total_tokens", p + r),
                    )
                )
                and reply["choices"][0]["finish_reason"]
                == (
                    "stop"
                    if verification["reply_token_ids"][-1] in END_TOKENS
                    else "length"
                )
            )
            state.update(
                leaf_index=index,
                leaf_hash=rec["leaf_hash"],
                transcript_commitment=rec["transcript_commitment"],
                prompt_tokens=p,
                reply_tokens=r,
            )
            return True
        state["cursor"] = end
        return False

    def _proof(self, state: Json) -> str:
        path = self.challenge + "/" + state["handle"]
        row = self._get(path, bearer=state["capability"], private=True)
        _require(isinstance(row, dict) and row["challenge_id"] == state["handle"])
        if row["status"] in ("pending", "verifying") and row.keys() == {
            "status",
            "challenge_id",
        }:
            raise _Pending
        _require(row["status"] == "completed")
        verdict: Json = verify_signed(row["verdict"], self._key)
        _require(
            verdict["challenge_id"] == state["handle"]
            and verdict["transcript_commitment"] == state["transcript_commitment"]
        )
        state.update(
            signed_verdict=verdict,
            verdict_outcome=verdict["outcome"],
            verdict_reason=verdict["reason"],
            verdict_sha256=hashlib.sha256(rfc8785.dumps(verdict)).hexdigest(),
        )
        if verdict["outcome"] == "EXCUSED_RANGE":
            return "excused_range"
        _require(verdict["outcome"] in ("CONFORMS", "DEVIATES"))
        artifact = self._get(path + "/proof", bearer=state["capability"], private=True)
        expected = verdict["outcome"]
        _require(
            artifact["kind"]
            == ("conformance" if expected == "CONFORMS" else "deviation")
        )
        max_bytes = self.runtime.get("max_proof_bytes")
        _require(
            type(max_bytes) is int
            and max_bytes > 0
            and isinstance(artifact["proof"], str)
            and 0 < len(artifact["proof"]) <= 4 * ((max_bytes + 2) // 3)
            and isinstance(artifact["statement"], str)
            and len(artifact["statement"]) == 8 * (1024 + 2)
        )
        statement = bytes.fromhex(artifact["statement"])
        proof = base64.b64decode(artifact["proof"], validate=True)
        _require(
            hashlib.sha256(statement).hexdigest() == verdict["statement_sha256"]
            and hashlib.sha256(proof).hexdigest() == verdict["proof_sha256"]
        )
        result = verify(
            {**state["bundle"], "proof": artifact},
            self.descriptor,
            state["before"],
            assets=self.assets,
            runtime=self.runtime,
            now=self.clock(),
            observed_at=datetime.fromisoformat(state["at"]),
        )
        if result.outcome in ("ASSETS_UNAVAILABLE", "NO_VERDICT"):
            raise _Pending
        _require(
            result.outcome == expected
            and result.exit_code == (0 if expected == "CONFORMS" else 21)
            and not result.warnings
        )
        state.update(
            proof_sha256=verdict["proof_sha256"],
            statement_sha256=verdict["statement_sha256"],
        )
        return str(expected).lower()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    args = parser.parse_args()
    try:
        holder = SoakHolder(_private_config(args.config))
        report = holder.advance(_read_json(args.case.read_bytes()))
    except Exception:  # noqa: BLE001 -- never serialize inputs, paths, credentials or peer diagnostics.
        report = {
            "schema_version": 1,
            "status": "failed",
            "stage": "configuration_or_state",
        }
    print(json.dumps(report, sort_keys=True))
    return {
        "conforms": 0,
        "recovered": 0,
        "unwarranted": 0,
        "excused_range": 0,
        "deviates": 1,
        "failed": 1,
        "pending": 2,
        "uncertain": 3,
    }[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
