"""Public log reads against the origin pinned by a trusted deployment descriptor."""

import json
import math
import ssl
from contextlib import closing
from http.client import HTTPException, HTTPSConnection
from urllib.parse import urlsplit


class LogReader:
    def __init__(
        self,
        url: str,
        *,
        timeout: float,
        max_response_bytes: int,
        context: ssl.SSLContext | None = None,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Expected a pinned HTTPS log URL")
        if (
            not math.isfinite(timeout)
            or timeout <= 0
            or type(max_response_bytes) is not int
            or max_response_bytes <= 0
        ):
            raise ValueError("Invalid public log read limits")
        self.host, self.port, self.prefix = (
            parsed.hostname,
            parsed.port,
            parsed.path.rstrip("/") + "/",
        )
        self.timeout, self.limit, self.context = (
            timeout,
            max_response_bytes,
            context or ssl.create_default_context(),
        )
        if (
            not self.context.check_hostname
            or self.context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError("Log origin requires authenticated TLS")

    def __call__(self, route: str) -> object:
        if (
            not route
            or route.startswith("/")
            or ".." in route
            or "#" in route
            or any(ord(c) <= 32 for c in route)
        ):
            raise ValueError("Invalid relative log read")

        def unique(items: list[tuple[str, object]]) -> dict[str, object]:
            fields = dict(items)
            if len(fields) != len(items):
                raise ValueError("Duplicate public log field")
            return fields

        try:
            with closing(
                HTTPSConnection(
                    self.host, self.port, timeout=self.timeout, context=self.context
                )
            ) as client:
                client.request("GET", self.prefix + route)
                with client.getresponse() as response:
                    if response.status != 200:
                        raise OSError("Log read unavailable")
                    data = response.read(self.limit + 1)
                if len(data) > self.limit:
                    raise ValueError("Public log response exceeds operator limit")
                return json.loads(data.decode("utf-8"), object_pairs_hook=unique)
        except HTTPException:
            raise OSError("Log read unavailable") from None
        except RecursionError:
            raise ValueError("Public log response nests too deeply") from None
