"""Exercise the actual pinned CPU-only FlashProve Spool implementation on Linux."""

import os
import subprocess
import tempfile
import time
from pathlib import Path

from prover.request import build_statement
from prover.submission import COMMITMENT, SubmissionStore
from prover.worker import CandidateProof, ProofWorker, Unavailable

REVISION = "9e2bdd8ff5bf9c62f18263d7dac189b0400b260c"


def main() -> None:
    source = Path(os.environ["FLASH_PROVE_DIR"]).resolve(strict=True)
    fixture = Path(__file__).parent / "fixtures/proof-worker/spool.cpp"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        checkout = root / "source"
        subprocess.run(
            ["git", "clone", "-q", "--no-checkout", "--", str(source), str(checkout)],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "core.hooksPath=/dev/null",
                "checkout",
                "-q",
                "--detach",
                REVISION,
            ],
            check=True,
        )
        program = root / "spool-test"
        subprocess.run(
            [
                "g++-13",
                "-O1",
                "-fno-ipa-modref",
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-pthread",
                "-msha",
                "-msse4.1",
                "-mssse3",
                "-I",
                str(checkout / "prover"),
                "-I",
                str(checkout / "blocks"),
                str(fixture),
                "-o",
                str(program),
            ],
            check=True,
        )
        spool = root / "spool"
        spool.mkdir(mode=0o700)
        mark = spool / "mark.txt"
        mark.write_text(f"cp-folder 1\nkind spool\ncommitment {COMMITMENT}\n")
        mark.chmod(0o600)
        store = SubmissionStore(root / "state", spool)
        worker = ProofWorker(store, max_proof_bytes=1024)
        statement = build_statement([14, 17], [12])
        for label, expected in (
            ("candidate", CandidateProof(statement, bytes(4), b"private fixture")),
            ("failed", Unavailable("spool_failure")),
        ):
            job = store.submit(
                label, statement, deadline_ns=time.time_ns() + 30_000_000_000
            )
            subprocess.run([program, spool, label], check=True)
            assert worker.wait(label, poll_seconds=0.1) == expected
            assert store.resume(label) == job and not list((spool / "in").glob("*.req"))
        print(
            "Pinned native spool passed both publication, collection and restart cases"
        )


if __name__ == "__main__":
    main()
