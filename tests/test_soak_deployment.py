"""Check real role provisioning, certificate ingress, and supervisor failure boundaries."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from prover.submission import COMMITMENT
from soak import deployment as deploy
from soak.ledger import NativeProcess
from soak.settings import digest, private
from tools.gate_m1 import _write


class Echo(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(self.server.server_port).encode())  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        pass


class DeploymentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.t = self.root / "traffic"
        self.verifier = self.root / "verifier"
        self.verifier.mkdir(mode=0o700)
        _write(self.verifier / "manifest.json", {"fixture": True})
        for name in ("spool", "control", "prover", "gateway", "primary"):
            (self.root / name).mkdir(mode=0o700)
        self.previous = self.root / "primary/ready.json"
        self.fresh = self.root / "gateway/ready.json"
        self.ep = {
            "schema_version": 1,
            "host": "127.0.0.1",
            "model": "maverick-int",
            "provider_uid": os.geteuid(),
            "port": 12345,
            "control_socket": str(self.root / "control/s"),
            "spool": str(self.root / "spool"),
            **{
                k: str(self.root / "gateway" / n)
                for k, n in (
                    ("ca", "ca.crt"),
                    ("key", "client.key"),
                    ("cert", "client.crt"),
                )
            },
        }
        self.conf: dict[str, Any] = {
            "python": sys.executable,
            "audit_python": sys.executable,
            "source": str(self.root),
            "audit_source": str(self.root),
            "schema_version": 1,
            "role_command": "/operator/role-command",
            "primary_ready_sha256": "",
            "reference": {
                "model": "/operator/reference",
                "manifest": "/operator/manifest",
                "rebuild_report": "/operator/rebuild",
            },
            "haproxy": "/operator/haproxy",
            "assets": "/operator/f37",
            "limits": {
                **dict.fromkeys(deploy.SECS, 1),
                **dict.fromkeys(deploy.COUNTS, 1),
                "lease_seconds": 6,
                "proof_deadline_seconds": 5,
                "max_observation_gap_seconds": 2,
                "request_timeout": 3,
                "pickup_limit": {"requests": 4, "period_seconds": 1, "max_peers": 1},
            },
        }
        self.gpus = {
            "engine": "GPU-00000000-0000-4000-8000-000000000001",
            "prover": "GPU-00000000-0000-4000-8000-000000000002",
        }
        original = {
            "schema_version": 1,
            "phase": "eligible",
            "commitment_id": COMMITMENT,
            "dtype": "float32",
            "same_process_f21": True,
            "float64_cases_passed": 44,
            "platform": "fixture",
            "canaries": [
                {"prompt": [n], "max_tokens": 1, "expected": [1]} for n in range(3)
            ],
        }
        _write(self.previous, original)
        self.conf["primary_ready_sha256"] = digest(self.previous)
        _write(
            self.fresh,
            {
                **original,
                "primary_host": "host-fixture",
                "primary_ready_sha256": self.conf["primary_ready_sha256"],
                "instance": "test-instance",
            },
        )
        _write(
            self.root / "control/provider-observed.json", {"instance": "test-instance"}
        )
        _write(self.root / "engine-endpoint.json", self.ep)
        (self.previous.parent / "host-fingerprint").write_text("host-fixture")
        (self.root / "control/provider.pid").write_text("123")
        _write(
            self.root / "prover/ready.json",
            {
                "schema_version": 1,
                "phase": "spool_open",
                "native_pid": 456,
                "start_ticks": 5566,
                "cgroup": "0::/two",
                "commitment_id": COMMITMENT,
                "batch": 1,
            },
        )
        (self.root / "control/gpu-assignment").write_text("0, " + self.gpus["engine"])
        (self.root / "prover/gpu-assignment").write_text(self.gpus["prover"] + ", 12")
        (self.root / "spool/mark.txt").write_text(
            "cp-folder 1\nkind spool\ncommitment " + COMMITMENT + "\n"
        )
        _write(
            self.verifier / "verified.json",
            {
                "schema_version": 1,
                "native_published_example": "VERIFIED",
                "manifest_sha256": digest(self.verifier / "manifest.json"),
            },
        )
        self.primary = deploy.Primary(
            self.previous,
            self.fresh,
            123,
            NativeProcess(456, 5566, "0::/two"),
            self.gpus,
            self.ep,
            self.verifier,
            self.root / "spool",
        )

    def test_primary_evidence_and_live_roles(self) -> None:
        env = {
            "VIG_M4_" + k: str(path)
            for k, path in {
                "ROOT": self.root,
                "PRIMARY_READY": self.previous,
                "FRESH_READY": self.fresh,
                "ENGINE_ENDPOINT": self.root / "engine-endpoint.json",
                "PROVER_SPOOL": self.root / "spool",
                "VERIFIER": self.verifier,
            }.items()
        }
        original = Path.read_text

        def text(path: Path) -> str:
            if path == Path("/proc/123/cgroup"):
                return "0::/one"
            if path == Path("/proc/456/stat"):
                return "456 (cp_prove) " + " ".join(["S"] + ["0"] * 18 + ["5566"])
            if path == Path("/proc/456/cgroup"):
                return "0::/two"
            return original(path)

        with (
            patch.object(deploy, "primary_host_matches", return_value=True) as host,
            patch.object(os, "kill") as pid,
            patch.object(Path, "read_text", text),
        ):
            self.assertEqual(deploy.physical(self.root, self.conf, env), self.primary)
            self.assertEqual(pid.call_count, 2)
            host.return_value = False
            with self.assertRaisesRegex(ValueError, "startup"):
                deploy.physical(self.root, self.conf, env)
            host.return_value = True
            (self.root / "prover/gpu-assignment").write_text(
                self.gpus["engine"] + ", 12"
            )
            with self.assertRaisesRegex(ValueError, "share a GPU"):
                deploy.physical(self.root, self.conf, env)
            _write(
                self.root / "control/provider-observed.json",
                {"instance": "other-instance"},
            )
            with self.assertRaisesRegex(ValueError, "startup"):
                deploy.physical(self.root, self.conf, env)

    def test_private_keys_trust_layout_and_immutable_restart(self) -> None:
        ports = deploy.provision(self.root, self.conf, self.primary)
        observed = {p: p.read_bytes() for p in self.t.rglob("*") if p.is_file()}
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in observed))
        self.assertTrue(
            all(
                stat.S_IMODE(p.stat().st_mode) == 0o700
                for p in self.t.rglob("*")
                if p.is_dir()
            )
        )
        gw, au, holder = (
            private(self.t / k / "config.json")
            for k in ("gateway", "auditor", "holder")
        )
        desc = private(Path(holder["descriptor"]))
        for private_key, public_hex in (
            (bytes.fromhex(gw["log_signer"]), desc["log"]["log_public_key"]),
            (Path(au["verdict_signing_key"]).read_bytes(), desc["auditor_public_key"]),
        ):
            self.assertEqual(
                Ed25519PrivateKey.from_private_bytes(private_key)
                .public_key()
                .public_bytes_raw()
                .hex(),
                public_hex,
            )
            self.assertNotIn(private_key.hex(), json.dumps(holder))
        self.assertEqual(
            bytes(PrivateKey(Path(au["recipient_key"]).read_bytes()).public_key).hex(),
            gw["auditor_recipient"],
        )
        self.assertNotIn("spool", json.dumps(holder))
        self.assertNotIn(self.ep["key"], json.dumps(au))
        self.assertNotIn("loopback_origins", holder)
        self.assertNotEqual(holder["challenge_bearer"], holder["inference_bearer"])
        self.assertEqual(ports, deploy.provision(self.root, self.conf, self.primary))
        self.assertEqual(observed, {p: p.read_bytes() for p in observed})
        with self.assertRaisesRegex(ValueError, "Existing deployment"):
            deploy.provision(self.root, self.conf, replace(self.primary, engine=789))
        self.assertEqual(observed, {p: p.read_bytes() for p in observed})

    def test_rejects_torn_provisioning_and_bad_limits(self) -> None:
        with (
            patch.object(deploy, "_certificate", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            deploy.provision(self.root, self.conf, self.primary)
        self.assertFalse(self.t.exists())
        self.assertFalse(list(self.root.glob(".traffic-*")))
        self.conf["limits"]["resource_poll_seconds"] = self.conf["limits"][
            "max_observation_gap_seconds"
        ]
        with self.assertRaisesRegex(ValueError, "observation bounds"):
            deploy.provision(self.root, self.conf, self.primary)

    def test_role_commands_use_mount_launcher_and_never_start_native_writer(
        self,
    ) -> None:
        ports = deploy.provision(self.root, self.conf, self.primary)
        runs = deploy.commands(self.t, self.conf, self.primary, ports)
        self.assertEqual(
            {r.name for r in runs},
            {
                "gateway",
                "ingress",
                "router",
                "http",
                "worker",
                "index",
                "custody",
                "sweep-auditor",
                "sweep-spool",
            },
        )
        for cmd in runs:
            self.assertEqual(cmd.argv[:3], ("/operator/role-command", cmd.role, "--"))
            self.assertNotIn("cp_prove", str(cmd.argv))
            self.assertNotIn("client.key", str(cmd.argv))
            if cmd.role == "router":
                self.assertIn("opaque", cmd.argv)
                self.assertNotIn("--config", cmd.argv)

    def test_recovers_only_unbound_role_owned_socket(self) -> None:
        endpoint = self.root / "owned.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint))
            listener.listen()
            with self.assertRaisesRegex(RuntimeError, "already active"):
                deploy._clear_stale_socket(endpoint)
        deploy._clear_stale_socket(endpoint)
        self.assertFalse(endpoint.exists())
        endpoint.touch(mode=0o600)
        with self.assertRaisesRegex(ValueError, "socket"):
            deploy._clear_stale_socket(endpoint)
        self.assertTrue(endpoint.is_file())

    def test_shutdown_reaps_owned_children(self) -> None:
        children = deploy.Children()
        a = deploy.Command(
            "gateway",
            "gateway",
            (sys.executable, "-c", "import time;time.sleep(60)"),
            self.root,
        )
        b = deploy.Command(
            "auditor",
            "worker",
            (sys.executable, "-c", "raise SystemExit(1)"),
            self.root,
        )
        children.start(a, self.root / "gw.log")
        try:
            children.start(b, self.root / "au.log")
            children.live["worker"].wait(timeout=10)
            with self.assertRaisesRegex(RuntimeError, "worker"):
                children.check(threading.Event())
        finally:
            children.shutdown(5)
        self.assertIsNotNone(children.live["gateway"].returncode)

    def test_real_loopback_tls_ingress_and_route_boundary(self) -> None:
        hap = shutil.which(os.environ.get("HAPROXY", "haproxy"))
        if hap is None:
            self.skipTest("HAProxy binary required for live TLS mount test")
        ports = deploy.provision(self.root, self.conf, self.primary)
        with ExitStack() as stack:
            for name in ("log", "audit", "pickup"):
                sv = stack.enter_context(
                    ThreadingHTTPServer(("127.0.0.1", ports[name]), Echo)
                )
                th = threading.Thread(target=sv.serve_forever)
                th.start()
                stack.callback(th.join)
                stack.callback(sv.shutdown)
            cmd = [hap, "-db", "-f", str(self.t / "gateway/ingress.cfg")]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            stack.callback(proc.wait, 10)
            stack.callback(proc.terminate)
            ctx = ssl.create_default_context(
                cafile=str(self.t / "public/ingress-ca.pem")
            )

            def call(route: str, method: str = "GET") -> tuple[int, bytes]:
                conn = http.client.HTTPSConnection(
                    "127.0.0.1", ports["ingress"], context=ctx, timeout=3
                )
                try:
                    conn.request(method, route)
                    reply = conn.getresponse()
                    return reply.status, reply.read()
                finally:
                    conn.close()

            end = time.monotonic() + 10
            while True:
                try:
                    status, data = call("/log/v1/sth")
                    break
                except ConnectionRefusedError:
                    if proc.poll() is not None or time.monotonic() > end:
                        self.fail("HAProxy failed to bind local TLS listener")
                    time.sleep(0.02)
            self.assertEqual((status, data), (200, str(ports["log"]).encode()))
            self.assertEqual(
                call("/audit/v1/selections"), (200, str(ports["audit"]).encode())
            )
            self.assertEqual(
                call("/receipts/v1/pickup/" + "0" * 64),
                (200, str(ports["pickup"]).encode()),
            )
            self.assertEqual(call("/internal/escrow/status/")[0], 403)
            self.assertEqual(call("/log/v1/receipts", "POST")[0], 403)


if __name__ == "__main__":
    unittest.main()
