"""Calibrate Linux procfs directory metadata in a disposable, stdio-only process."""

import os
import sys
from pathlib import Path

UNSUPPORTED = 3  # Distinct from an interpreter or helper failure.


def probe(directory: Path) -> bool:
    """Run only in the isolated helper; close its own three standard descriptors."""
    if directory.stat().st_size != 3:
        return False
    with open(os.devnull, "rb"):
        if directory.stat().st_size != 4:
            return False
    if directory.stat().st_size != 3:
        return False
    for fd in (0, 1, 2):
        os.close(fd)
    return directory.stat().st_size == 0


if __name__ == "__main__":
    sys.exit(
        0 if sys.platform == "linux" and probe(Path("/proc/self/fd")) else UNSUPPORTED
    )
