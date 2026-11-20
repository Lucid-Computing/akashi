import os
import runpy
import shlex
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast

ASSETS = Path(__file__).resolve().parents[1] / "deploy/service-roles"
check_directory = cast(
    Callable[..., None],
    runpy.run_path(str(ASSETS / "check-keys.py"))["check_directory"],
)


class RoleTests(unittest.TestCase):
    def test_private_keys_require_role_owner_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            role = Path(tmp)
            secret = role / "key"
            secret.touch(mode=0o600)
            check_directory(role, os.geteuid())
            with self.assertRaises(ValueError):
                check_directory(role, os.geteuid() + 1)
            secret.chmod(0o644)
            with self.assertRaises(ValueError):
                check_directory(role, os.geteuid())
            secret.chmod(0o600)
            os.link(secret, role / "other-slot")
            with self.assertRaises(ValueError):
                check_directory(role, os.geteuid())
            (role / "other-slot").unlink()
            (role / "linked-slot").symlink_to(secret)
            with self.assertRaises(ValueError):
                check_directory(role, os.geteuid())
            (role / "linked-slot").unlink()
            role.chmod(0o755)
            with self.assertRaises(ValueError):
                check_directory(role, os.geteuid())

    def test_prover_key_directories_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp)
            (keys / "ivk").mkdir(mode=0o700)
            key = keys / "ivk/key.bin"
            key.touch(mode=0o400)
            check_directory(keys, os.geteuid(), prover_keys=True)
            key.chmod(0o600)
            with self.assertRaises(ValueError):
                check_directory(keys, os.geteuid(), prover_keys=True)

    def test_every_service_has_a_distinct_nonlogin_account_and_key_directory(
        self,
    ) -> None:
        accounts = [
            shlex.split(line)
            for line in (ASSETS / "vig.sysusers").read_text().splitlines()
            if line.startswith("u ")
        ]
        names = {row[1] for row in accounts}
        roles = [
            "engine",
            "proxy",
            "gateway",
            "log",
            "sampler",
            "escrow",
            "pickup",
            "auditor",
            "prover",
            "verifier",
        ]
        self.assertEqual(names, {f"vig-{role}" for role in roles})
        self.assertTrue(all(row[-1] == "/usr/sbin/nologin" for row in accounts))
        directories = (ASSETS / "vig.tmpfiles").read_text().splitlines()
        for role in roles:
            self.assertIn(
                f"d /etc/vig/keys/{role} 0700 vig-{role} vig-{role} -", directories
            )

    def test_engine_unit_requires_private_launch_and_readonly_models(self) -> None:
        unit = (ASSETS / "vig@.service").read_text().splitlines()
        self.assertIn("User=vig-%i", unit)
        self.assertIn("Group=vig-%i", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn(
            "ExecStartPre=/usr/bin/python3 -I /usr/local/libexec/vig/check-keys.py %i",
            unit,
        )
        engine = (
            (ASSETS / "vig@engine.service.d/isolation.conf").read_text().splitlines()
        )
        self.assertIn("BindReadOnlyPaths=/models", engine)
        self.assertIn("Requires=vig-engine-firewall.service", engine)
        self.assertIn("After=nftables.service vig-engine-firewall.service", engine)
        firewall = (ASSETS / "vig-engine-firewall.service").read_text().splitlines()
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/vig/engine.nft", firewall)
        start = next(line for line in engine if line.startswith("ExecStart=/"))
        command = shlex.split(start.removeprefix("ExecStart="))
        self.assertEqual(command[:2], ["/usr/bin/env", "-i"])
        self.assertEqual(command[-4:], ["--host", "127.0.0.1", "--port", "8000"])
