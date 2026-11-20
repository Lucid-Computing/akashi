"""WSGI health and metrics endpoints for the service's private listener."""

import json
import time
from collections.abc import Callable, Mapping


class HealthApp:
    def __init__(
        self,
        *,
        startup: Callable[[], bool],
        engine: Callable[[], bool],
        log: Callable[[], bool],
        metrics: Callable[[], str],
        beacon: Callable[[], bool] | None = None,
    ) -> None:
        self._startup = {"startup": startup}
        self._readiness = {**self._startup, "engine": engine, "log": log}
        if beacon is not None:
            self._readiness["beacon"] = beacon
        self._metrics = metrics
        self._started = time.monotonic()

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[[str, list[tuple[str, str]]], object],
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        content_type = "application/json"
        headers: list[tuple[str, str]] = [("Cache-Control", "no-store")]
        if path not in ("/health/live", "/health/ready", "/health/startup", "/metrics"):
            status, body = "404 Not Found", b'{"status":"unknown"}'
        elif environ.get("REQUEST_METHOD") != "GET":
            headers.append(("Allow", "GET"))
            status, body = "405 Method Not Allowed", b'{"status":"method_not_allowed"}'
        elif path == "/metrics":
            try:
                body = self._metrics().encode("utf-8")
            except Exception:  # noqa: BLE001
                # Keep exporter diagnostics out of both the response and WSGI error log.
                status, body = "503 Service Unavailable", b'{"status":"unhealthy"}'
            else:
                status = "200 OK"
                content_type = "text/plain; version=0.0.4; charset=utf-8"
        else:
            probes = self._readiness if path == "/health/ready" else self._startup
            checks: dict[str, str] = {}
            if path != "/health/live":
                for name, probe in probes.items():
                    try:
                        passed = probe() is True
                    except Exception:  # noqa: BLE001
                        # A dependency exception may include credentials or transcript data.
                        passed = False
                    checks[name] = "pass" if passed else "fail"
            healthy = "fail" not in checks.values()
            status = "200 OK" if healthy else "503 Service Unavailable"
            condition = "healthy" if healthy else "degraded"
            if path == "/health/startup" and not healthy:
                condition = "unhealthy"
            body = json.dumps(
                {
                    "status": condition,
                    "checks": checks,
                    "uptime_seconds": int(time.monotonic() - self._started),
                }
            ).encode("utf-8")
        headers.extend(
            [("Content-Type", content_type), ("Content-Length", str(len(body)))]
        )
        start_response(status, headers)
        return [body]
