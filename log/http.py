"""Authenticated promise writes and public RFC-0004 history reads under /log/v1/."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime
from threading import Event
from typing import BinaryIO, cast
from urllib.parse import parse_qs

from log.store import IdentityConflict, MerkleLog


class _HTTPError(Exception):
    def __init__(self, status: str) -> None:
        self.status = status


def _uint(text: object) -> int:
    if (
        not isinstance(text, str)
        or not text.isascii()
        or not text.isdecimal()
        or len(text) > 20
    ):
        raise ValueError("expected unsigned decimal")
    value = int(text)
    if value >= 1 << 64:
        raise ValueError("expected uint64")
    return value


def _params(query: str, *fields: str) -> dict[str, int]:
    values = parse_qs(query, keep_blank_values=True, strict_parsing=True)
    if set(values) != set(fields) or any(len(items) != 1 for items in values.values()):
        raise ValueError("unexpected query parameters")
    return {k: _uint(items[0]) for k, items in values.items()}


def _unique(fields: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(fields)
    if len(result) != len(fields):
        raise ValueError("duplicate JSON member")
    return result


def run_checkpoints(log: MerkleLog, stop: Event) -> None:
    """Run in a supervised task for the lifetime of the log service."""
    while not stop.is_set():
        head = log.checkpoint()
        issued = datetime.fromisoformat(str(head["timestamp"]).replace("Z", "+00:00"))
        age = (log.clock() - issued).total_seconds()
        if stop.wait(max(0, min(log.checkpoint_seconds, log.checkpoint_seconds - age))):
            return


class LogApp:
    """Mount behind a host that sets WSGI REMOTE_USER from authenticated credentials."""

    def __init__(
        self, log: MerkleLog, *, gateway_identity: str, max_body: int = 256 * 1024
    ) -> None:
        if not isinstance(gateway_identity, str) or not gateway_identity.strip():
            raise ValueError("expected an authenticated gateway identity")
        if type(max_body) is not int or max_body <= 0:
            raise ValueError("expected a positive body limit")
        self.log = log
        self.gateway_identity = gateway_identity
        self.max_body = max_body

    def _route(self, env: Mapping[str, object]) -> object:
        path = env.get("PATH_INFO")
        if not isinstance(path, str) or not path.startswith("/log/v1/"):
            raise _HTTPError("404 Not Found")
        route = path.removeprefix("/log/v1/")
        query = env.get("QUERY_STRING", "")
        if not isinstance(query, str):
            raise TypeError("invalid query")
        if route == "promise":
            if env.get("REQUEST_METHOD") != "POST":
                raise _HTTPError("405 Method Not Allowed")
            if env.get("REMOTE_USER") != self.gateway_identity:
                raise _HTTPError("401 Unauthorized")
            _params(query)
            length = _uint(env.get("CONTENT_LENGTH"))
            if length > self.max_body:
                raise _HTTPError("413 Content Too Large")
            stream = cast(BinaryIO, env["wsgi.input"])
            body = stream.read(length)
            if len(body) != length:
                raise ValueError("incomplete body")
            fields = json.loads(body.decode("utf-8"), object_pairs_hook=_unique)
            if not isinstance(fields, dict):
                raise ValueError("expected a public leaf preimage")
            return self.log.append(fields)

        if route not in {
            "sth",
            "receipts/range",
            "consistency",
        } and not route.startswith(("receipts/", "proof/")):
            raise _HTTPError("404 Not Found")
        if env.get("REQUEST_METHOD") != "GET":
            raise _HTTPError("405 Method Not Allowed")
        if route == "sth":
            if query:
                parts = parse_qs(query, keep_blank_values=True, strict_parsing=True)
                if parts.keys() == {"size", "log_key_id"} and all(
                    len(v) == 1 for v in parts.values()
                ):
                    return self.log.head(
                        _uint(parts["size"][0]), log_key_id=parts["log_key_id"][0]
                    )
                return self.log.head(_params(query, "size")["size"])
            return self.log.head()
        if route == "receipts/range":
            bounds = _params(query, "start", "end")
            return self.log.receipts(bounds["start"], bounds["end"])
        if route.startswith("receipts/"):
            _params(query)
            return self.log.receipt(_uint(route.removeprefix("receipts/")))
        if route.startswith("proof/"):
            index = _uint(route.removeprefix("proof/"))
            size = (
                _params(query, "size")["size"]
                if query
                else cast(int, self.log.head()["tree_size"])
            )
            path_hashes = self.log.path(index, size)
            return {
                "leaf_index": index,
                "tree_size": size,
                "audit_path": [h.hex() for h in path_hashes],
            }
        bounds = _params(query, "from", "to")
        proof = self.log.consistency(bounds["from"], bounds["to"])
        return {
            "from": bounds["from"],
            "to": bounds["to"],
            "consistency_path": [h.hex() for h in proof],
        }

    def __call__(
        self,
        env: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        try:
            status = "200 OK"
            value = self._route(env)
        except _HTTPError as exc:
            status, value = exc.status, None
        except IdentityConflict:
            status, value = "409 Conflict", None
        except KeyError:
            status, value = "404 Not Found", None
        except (TypeError, ValueError, RecursionError, OverflowError):
            status, value = "400 Bad Request", None
        except (sqlite3.Error, OSError, RuntimeError):
            status, value = "500 Internal Server Error", None
        body = (
            json.dumps(
                value, separators=(",", ":"), sort_keys=True, allow_nan=False
            ).encode()
            if value is not None
            else b""
        )
        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ]
        if status.startswith("405 "):
            headers.append(
                (
                    "Allow",
                    "POST" if env.get("PATH_INFO") == "/log/v1/promise" else "GET",
                )
            )
        start_response(status, headers)
        return [body]
