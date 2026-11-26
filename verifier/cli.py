"""Offline holder verification entry point."""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from verifier.holder import VerificationResult, verify


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.exit(64, json.dumps(VerificationResult(64, "USAGE").as_json()) + "\n")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate field")
    return result


def _observation(value: str) -> datetime:
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
        value,
    ):
        raise argparse.ArgumentTypeError("expected a UTC delivery observation")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _constant(value: str) -> NoReturn:
    raise ValueError("nonfinite JSON number")


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_bytes(), object_pairs_hook=_unique, parse_constant=_constant
    )
    if not isinstance(value, dict):
        raise TypeError("expected object")
    return value


def main(argv: list[str] | None = None) -> int:
    cli = Parser(prog="akashi")
    cmd = cli.add_subparsers(dest="command", required=True).add_parser(
        "verify", help=__doc__
    )
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument(
        "--descriptor",
        type=Path,
        required=True,
        help="separately trusted akashi/1 descriptor",
    )
    cmd.add_argument(
        "--checkpoint", type=Path, help="holder's previously trusted signed head"
    )
    cmd.add_argument(
        "--observed-at",
        type=_observation,
        help="holder's independently recorded UTC time of receipt delivery",
    )
    cmd.add_argument("--receipt-only", action="store_true")
    cmd.add_argument(
        "--assets",
        type=Path,
        default=os.environ.get("AKASHI_RENDER_ASSETS"),
        help="pinned chat tokenizer files",
    )
    cmd.add_argument(
        "--runtime", type=Path, help="trusted native verifier configuration"
    )
    args = cli.parse_args(argv)
    try:
        descriptor = _object(args.descriptor)
        bundle = _object(args.bundle)
        checkpoint = _object(args.checkpoint) if args.checkpoint else None
        runtime = (
            _object(args.runtime) if args.runtime and not args.receipt_only else None
        )
        result = verify(
            bundle,
            descriptor,
            checkpoint,
            assets=args.assets,
            receipt_only=args.receipt_only,
            runtime=runtime,
            observed_at=args.observed_at,
        )
    except OSError:
        result = VerificationResult(30, "INPUT_UNAVAILABLE")
    except (ValueError, TypeError, RecursionError):
        result = VerificationResult(64, "INVALID_JSON")
    print(json.dumps(result.as_json(), sort_keys=True, allow_nan=False))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
