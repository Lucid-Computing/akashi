"""Publish a discovery snapshot with current and retired Ed25519 verification keys."""

import argparse
import fcntl
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path

from operations.key_archive import PublicKeyArchive

# The base is a public gateway descriptor (specs/gateway-api.md). Reject extensions
# until their fields have been reviewed for public disclosure.
_PUBLIC_FIELDS = {
    "version",
    "model",
    "commitment_id",
    "window",
    "max_tokens_cap",
    "end_tokens",
    "sampling_rate",
    "render_profile",
    "render_profiles",
    "log",
    "beacon",
    "pickup_url",
    "challenge_url",
    "audit_url",
    "auditor_key_id",
    "auditor_public_key",
}
_SECTIONS = {
    "log": {"log_id", "log_key_id", "log_public_key", "url"},
    "sampling_rate": {"live", "shadow"},
    "beacon": {"chain", "chain_hash", "url"},
    "render_profile": {
        "profile",
        "digest",
        "tokenizer_json_url",
        "tokenizer_config_url",
        "tokenizer_json_sha256",
        "tokenizer_config_sha256",
    },
}


def _public_section(value: object, fields: set[str]) -> None:
    if not isinstance(value, dict) or value.keys() - fields:
        raise ValueError("unexpected discovery fields")
    if any(type(item) not in (str, int) for item in value.values()):
        raise ValueError("unexpected discovery value")


def _check_base(descriptor: Mapping[str, object]) -> None:
    if descriptor.keys() - _PUBLIC_FIELDS or descriptor.get("version") != "vig/1":
        raise ValueError("unexpected discovery version or fields")
    for name, value in descriptor.items():
        if name in _SECTIONS:
            _public_section(value, _SECTIONS[name])
        elif name == "render_profiles":
            if not isinstance(value, list):
                raise ValueError("invalid render profiles")
            for profile in value:
                _public_section(profile, _SECTIONS["render_profile"])
        elif name == "end_tokens":
            if not isinstance(value, list) or any(
                type(token) is not int for token in value
            ):
                raise ValueError("invalid end tokens")
        elif type(value) not in (str, int):
            raise ValueError("unexpected discovery value")


def publish(
    descriptor: Mapping[str, object], archive: PublicKeyArchive, target: Path
) -> None:
    _check_base(descriptor)
    log_section = descriptor.get("log")
    if not isinstance(log_section, dict):
        raise TypeError("expected a log object in the vig/1 discovery descriptor")
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        # Serialize snapshot reads and publication to prevent a slow writer reverting a rotation.
        fcntl.flock(directory, fcntl.LOCK_EX)
        document = dict(descriptor)
        log = dict(log_section)
        keys = archive.public_keys()
        for role in ("log", "auditor"):
            current = [key for key in keys if key["role"] == role and key["active"]]
            if len(current) != 1:
                raise ValueError(f"expected one active {role} verification key")
            destination = log if role == "log" else document
            if not any(
                key["role"] == role
                and key["key_id"] == destination.get(f"{role}_key_id")
                and key["public_key"] == destination.get(f"{role}_public_key")
                for key in keys
            ):
                raise ValueError(f"base {role} key does not belong to this archive")
            destination[f"{role}_key_id"] = current[0]["key_id"]
            destination[f"{role}_public_key"] = current[0]["public_key"]
        document["log"] = log
        document["verification_keys"] = keys
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as staging:
            tmp = Path(staging.name)
            try:
                staging.write(json.dumps(document, allow_nan=False).encode("utf-8"))
                staging.flush()
                os.fchmod(staging.fileno(), 0o644)
                os.fsync(staging.fileno())
                os.replace(tmp, target)
                os.fsync(directory)
            finally:
                tmp.unlink(missing_ok=True)
    finally:
        os.close(directory)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("descriptor", type=Path, help="trusted base discovery JSON")
    parser.add_argument(
        "archive", type=Path, help="operator-maintained verification key archive"
    )
    parser.add_argument("output", type=Path, help="public /.well-known/vig.json file")
    args = parser.parse_args()
    if not args.archive.is_file():
        parser.error("public key archive is missing")
    with args.descriptor.open(encoding="utf-8") as stream:
        descriptor = json.load(stream)
    if not isinstance(descriptor, dict):
        parser.error("expected a discovery object")
    for source in (args.archive, args.descriptor):
        if source.resolve() == args.output.resolve():
            parser.error("publish to a separate file")
    publish(descriptor, PublicKeyArchive(args.archive), args.output)


if __name__ == "__main__":
    main()
