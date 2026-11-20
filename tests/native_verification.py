"""Exercise the real native verifier on the pinned public synthetic next-token request."""

import argparse
import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path

from prover.request import VOCABULARY_SIZE, WINDOW
from verifier.proof import NativeVerifier


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        required=True,
        help="private local copy with config/, ivk/, example.req, example.y and example.proof",
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--memory-bytes", type=int, required=True)
    parser.add_argument("--max-proof-bytes", type=int, required=True)
    args = parser.parse_args()
    folder = args.fixture.absolute()
    # The deterministic formula of prover/tools/make_request.py at the pinned revision.
    tokens = [(2654435761 * (i + 1) >> 7) % VOCABULARY_SIZE for i in range(WINDOW)]
    statement = struct.pack(f"<{WINDOW + 2}I", *tokens, WINDOW - 1, WINDOW)
    if statement != (folder / "example.req").read_bytes():
        parser.exit(1, "Fixture differs from the upstream public request\n")
    checker = NativeVerifier(
        args.binary.absolute(),
        args.manifest.absolute(),
        folder / "config",
        folder / "ivk",
        args.timeout_seconds,
        args.memory_bytes,
        args.max_proof_bytes,
    )
    y = (folder / "example.y").read_bytes()
    with (folder / "example.proof").open("rb") as source:
        proof = source.read(args.max_proof_bytes + 1)
    changed = bytes([statement[0] ^ 1]) + statement[1:]
    results = {
        "public_request": checker.check(statement, y, proof),
        "changed_request": checker.check(changed, y, proof),
        "missing_key": replace(checker, public_key_dir=folder / "absent").check(
            statement, y, proof
        ),
    }
    passed = results == {
        "public_request": "verified",
        "changed_request": "rejected",
        "missing_key": "unavailable",
    }
    print(
        json.dumps(
            {
                "schema_version": 1,
                "fixture": "upstream-public-next-token",
                "passed": passed,
                "outcomes": results,
                "statement_sha256": hashlib.sha256(statement).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
