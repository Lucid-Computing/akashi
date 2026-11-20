import subprocess
import unittest
from unittest.mock import patch

from tools.check_hardware import check_hardware


class HardwarePreflightTest(unittest.TestCase):
    def test_unsupported_host_fails_before_invoking_vendor_tools(self) -> None:
        with (
            patch("platform.system", return_value="Darwin"),
            patch("subprocess.check_output") as probe,
            self.assertRaisesRegex(ValueError, "x86-64 Linux"),
        ):
            check_hardware()
        probe.assert_not_called()

    def test_compiler_driver_version_cannot_substitute_for_toolkit_manifest(
        self,
    ) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
            patch("sys.version_info", (3, 13)),
            patch("shutil.which", return_value="/cuda/bin/nvcc"),
            patch(
                "subprocess.check_output",
                side_effect=["NVIDIA H100", "13.1", "13.1"] * 2,
            ),
            patch(
                "pathlib.Path.read_text",
                side_effect=[
                    "flags : sha_ni",
                    '{"cuda":{"version":"13.2.1"}}',
                    "flags : sha_ni",
                    '{"cuda":{"version":"13.2.2"}}',
                ],
            ),
        ):
            with self.assertRaisesRegex(ValueError, "Update 2"):
                check_hardware()
            check_hardware()

    def test_probe_failure_propagates(self) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="x86_64"),
            patch("sys.version_info", (3, 13)),
            patch("pathlib.Path.read_text", return_value="flags : sha_ni"),
            patch(
                "subprocess.check_output",
                side_effect=subprocess.CalledProcessError(1, "nvidia-smi"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            check_hardware()
