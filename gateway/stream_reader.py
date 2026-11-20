"""Read terminal gateway delivery evidence from a complete direct-mode SSE response."""

import json
from collections.abc import Iterable
from http.client import HTTPException
from typing import Any


class IncompleteStream(ValueError):
    """The response did not finish with exactly one terminal verification and DONE."""


def terminal_evidence(lines: Iterable[bytes]) -> dict[str, Any]:
    """Return the private bundle for independent holder verification after reading to EOF."""
    data: list[bytes] = []
    terminal = None
    done = False
    try:
        for line in lines:
            if not line.endswith(b"\n"):
                raise IncompleteStream("Incomplete SSE line")
            raw = line.removesuffix(b"\n").removesuffix(b"\r")
            if raw:
                name, sep, value = raw.partition(b":")
                if name == b"data":
                    data.append(value.removeprefix(b" ") if sep else b"")
                continue
            if not data:
                continue
            payload = b"\n".join(data)
            data.clear()
            if done:
                raise IncompleteStream("Unexpected event after DONE")
            if payload == b"[DONE]":
                if terminal is None:
                    raise IncompleteStream("No terminal verification")
                done = True
                continue
            event = json.loads(payload)
            if not isinstance(event, dict) or terminal is not None:
                raise IncompleteStream("Invalid terminal event order")
            if "verification" in event:
                evidence = event["verification"]
                if (
                    not isinstance(evidence, dict)
                    or evidence.get("version") != "vig/1"
                    or not isinstance(evidence.get("receipt"), dict)
                ):
                    raise IncompleteStream("Delivery was unwarranted")
                terminal = evidence
        if data or not done or terminal is None:
            raise IncompleteStream("Incomplete SSE response")
        return terminal
    except (HTTPException, OSError, ValueError, RecursionError) as exc:
        if isinstance(exc, IncompleteStream):
            raise
        raise IncompleteStream("Invalid or interrupted SSE response") from None
