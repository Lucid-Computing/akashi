"""Retain two real signed deliveries and exercise the M2 historical CPU challenge flow."""

import argparse
import base64
import fcntl
import hashlib
import importlib
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nacl.public import PrivateKey

from engine.mock import MockEngine
from escrow.store import EscrowStore
from gateway.commit_delivery import DeliveryCommitter
from gateway.discovery import ServiceConfig
from gateway.policy import InferenceRequest
from gateway.renderer import ChatRenderer
from log.receipt import leaf_hash
from log.store import MerkleLog
from prover.reference import ReferenceTrace
from prover.request import WINDOW, build_statement
from prover.runtime import REVISION
from prover.submission import COMMITMENT
from prover.worker import CandidateProof
from tools.m2_reference import BoundTrace, host_id
from verifier.proof import NativeVerifier

_CASE = "arithmetic-apples"
_AGE = timedelta(days=3)


def require(ok: object, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def save(path: Path, data: object) -> None:
    body = (json.dumps(data, sort_keys=True, allow_nan=False) + "\n").encode()
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=".saving-", delete=False
    ) as f:
        try:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
            name = Path(f.name)
        except BaseException:
            Path(f.name).unlink(missing_ok=True)
            raise
    os.replace(name, path)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def settings(config: dict[str, Any]) -> tuple[dict[str, Any], NativeVerifier]:
    runtime = config["native_runtime"]
    checker = NativeVerifier(
        Path(runtime["binary"]),
        Path(runtime["manifest"]),
        Path(runtime["config_dir"]),
        Path(runtime["public_key_dir"]),
        runtime["timeout_seconds"],
        runtime["memory_bytes"],
        runtime["max_proof_bytes"],
    )
    return runtime, checker


def captured(
    config: dict[str, Any],
) -> tuple[list[dict[str, str]], tuple[int, ...], tuple[int, ...], CandidateProof]:
    folder = Path(config["capture"])
    inputs = read(folder / "inputs-16.json")
    workload = [
        json.loads(line)
        for line in (
            Path(__file__).resolve().parents[1] / "tests/fixtures/m0-workload.jsonl"
        )
        .read_bytes()
        .splitlines()
    ]
    original = next(row for row in workload if row["id"] == _CASE)
    index = next(i for i, v in enumerate(inputs) if v["id"] == _CASE)
    candidate = read(folder / "unproven-candidates.json")
    ready = read(folder / "ready.json")
    taken = candidate["canaries"][index]
    require(
        ready["phase"] == "eligible"
        and ready["same_process_f21"] is True
        and ready["commitment_id"] == candidate["commitment_id"] == COMMITMENT
        and taken in ready["canaries"],
        "missing eligible primary capture",
    )
    msgs = original["messages"]
    prompt = ChatRenderer(Path(config["assets"])).render(msgs)
    reply = tuple(taken["expected"])
    require(
        list(prompt) == inputs[index]["prompt"] == taken["prompt"]
        and inputs[index]["max_tokens"]
        == taken["max_tokens"]
        == original["max_tokens"]
        == len(reply)
        == 1,
        "M2 fixture differs from the observed singleton",
    )
    statement = (folder / (_CASE + ".request")).read_bytes()
    require(
        statement == build_statement(prompt, reply), "whole-reply statement mismatch"
    )
    sub = Path(config["proofs"]) / _CASE
    timing = read(sub / "timing.json")
    require(
        timing["request_sha256"] == sha(statement) and timing["batch_size"] == 1,
        "proof batch differs from captured wire",
    )
    _, checker = settings(config)
    with (sub / "example.proof").open("rb") as f:
        proof = f.read(checker.max_proof_bytes + 1)
    y = (sub / "example.y").read_bytes()
    require(
        y == bytes(4) and 0 < len(proof) <= checker.max_proof_bytes,
        "invalid proof files",
    )
    return msgs, prompt, reply, CandidateProof(statement, y, proof)


def prepare(config: dict[str, Any], work: Path) -> Path:
    target = work / "delivery"
    if target.is_dir():
        return target
    messages, prompt, reply, proof = captured(config)
    runtime, checker = settings(config)
    require(
        checker.check(proof.statement, proof.y, proof.proof) == "verified",
        "independent CPU did not confirm original proof",
    )
    require(
        re.fullmatch(r"[a-f0-9]{64}", config["proof_source_host"])
        and host_id() != config["proof_source_host"],
        "proof and verification must use separate hosts",
    )
    renderer = ChatRenderer(Path(config["assets"]))
    changed = MockEngine().generate(prompt, 1).tokens
    require(
        len(changed) == 1 and changed != reply,
        "substitute did not change the served reply",
    )
    with tempfile.TemporaryDirectory(dir=work, prefix=".delivery-") as tmp:
        folder = Path(tmp)
        issued_at = datetime.now(timezone.utc)
        log_key = Ed25519PrivateKey.generate()
        signer = Ed25519PrivateKey.generate()
        key = PrivateKey.generate()
        hmac_key = os.urandom(32)
        service = ServiceConfig(
            **{
                **config["service"],
                "created": int(issued_at.timestamp()),
                "log_public_key": log_key.public_key().public_bytes_raw().hex(),
                "auditor_public_key": signer.public_key().public_bytes_raw().hex(),
            }
        )

        def clock() -> datetime:
            return datetime.now(timezone.utc)

        escrow_moment: list[datetime] = []

        def escrow_clock() -> datetime:
            return escrow_moment[0] if escrow_moment else clock()

        history = MerkleLog(
            folder / "history.sqlite",
            log_id=service.log_id,
            log_key_id=service.log_key_id,
            signing_key=log_key,
            leaf_hash=leaf_hash,
            clock=clock,
        )
        checkpoint = history.head()
        escrow = EscrowStore(
            folder / "escrow.sqlite",
            wrapping_key=os.urandom(32),
            auditor_public_key=bytes(key.public_key),
            clock=escrow_clock,
        )
        committer = DeliveryCommitter(
            service,
            endpoint_id=config["endpoint_id"],
            sampling_mode="live",
            stage=escrow.stage,
            append=history.append,
            clock=clock,
        )
        request = InferenceRequest(service.model, "chat", prompt, 1, False, False)
        save(folder / "descriptor.json", service.descriptor())
        save(folder / "checkpoint.json", checkpoint)
        save(folder / "native-runtime.json", runtime)
        save(
            folder / "audit-private.json",
            {
                "signer": signer.private_bytes_raw().hex(),
                "recipient": bytes(key).hex(),
                "hmac": hmac_key.hex(),
                "key_id": service.auditor_key_id,
            },
        )
        for name, tokens in (("original", reply), ("substitute", changed)):
            display = renderer.decode(tokens)
            attempt = committer.prepare(
                request, tokens, original_chat=messages, reply_text=display
            )
            verification = committer.commit(attempt, guard=lambda: None)
            sth = history.head()
            size = cast(int, sth["tree_size"])
            index = size - 1
            old_size = cast(int, checkpoint["tree_size"])
            bundle = {
                "verification": verification,
                "input": messages,
                "text": display,
                "max_tokens": 1,
                "history": {
                    "sth": sth,
                    "inclusion": {
                        "tree_size": size,
                        "leaf_index": index,
                        "audit_path": [h.hex() for h in history.path(index, size)],
                    },
                    "consistency": {
                        "from": old_size,
                        "to": size,
                        "consistency_path": [
                            h.hex() for h in history.consistency(old_size, size)
                        ],
                    },
                },
            }
            save(folder / (name + ".json"), bundle)
        # The controlled historical fixture advances the ES clock past W_escrow.
        # Keep its accountability records while erasing the private carrier and key.
        escrow_moment.append(issued_at + _AGE)
        escrow.sweep()
        save(
            folder / "provenance.json",
            {
                "commitment_id": COMMITMENT,
                "flashprove_revision": REVISION,
                "original_statement_sha256": sha(proof.statement),
                "substitute_statement_sha256": sha(build_statement(prompt, changed)),
                "proof_sha256": sha(proof.proof),
                "issued_at": issued_at.isoformat(),
                "proof_source_host": config["proof_source_host"],
                "verifier_host": host_id(),
            },
        )
        folder.rename(target)
    return target


def holder(
    bundle: Path, delivery: Path, assets: Path, *, receipt_only: bool
) -> tuple[int, str]:
    cmd = [
        sys.executable,
        "-m",
        "verifier.cli",
        "verify",
        str(bundle),
        "--descriptor",
        str(delivery / "descriptor.json"),
        "--checkpoint",
        str(delivery / "checkpoint.json"),
        "--assets",
        str(assets),
    ]
    if receipt_only:
        cmd.append("--receipt-only")
    else:
        cmd.extend(["--runtime", str(delivery / "native-runtime.json")])
    call = subprocess.run(
        cmd, capture_output=True, stdin=subprocess.DEVNULL, check=False
    )
    result = json.loads(call.stdout)
    require(
        result["exit_code"] == call.returncode,
        "holder process disagrees with its result",
    )
    return call.returncode, str(result["outcome"])


def audit(
    config: dict[str, Any], delivery: Path, elapsed_clock: bool
) -> dict[str, Any]:
    intake_module = importlib.import_module("auditor.intake")
    jobs_module = importlib.import_module("auditor.jobs")
    signing = importlib.import_module("auditor.verdict_signing")
    verdicts = importlib.import_module("auditor.verdicts")
    from prover.scoring import assess

    _, prompt, reply, candidate = captured(config)
    original = build_statement(prompt, reply)
    substitute = MockEngine().generate(prompt, 1).tokens
    altered = build_statement(prompt, substitute)
    source = read(delivery / "provenance.json")
    rx = read(Path(config["rx_trace"]))
    cpu = host_id()
    require(
        cpu == source["verifier_host"]
        and source["proof_source_host"] == config["proof_source_host"]
        and re.fullmatch(r"[0-9a-f]{64}", rx["source_host"])
        and rx["source_host"]
        == config.get("rx_source_host", source["proof_source_host"])
        and cpu not in (rx["source_host"], source["proof_source_host"]),
        "RX/prover and CPU placement are unbound",
    )
    require(
        rx["schema_version"] == 1
        and rx["flashprove_revision"] == source["flashprove_revision"] == REVISION
        and rx["commitment_id"] == source["commitment_id"] == COMMITMENT
        and rx["original_statement_sha256"]
        == source["original_statement_sha256"]
        == sha(original)
        and rx["substitute_statement_sha256"]
        == source["substitute_statement_sha256"]
        == sha(altered)
        and source["proof_sha256"] == sha(candidate.proof)
        and original == candidate.statement,
        "reference or proof belongs to another original or changed statement",
    )
    trace = ReferenceTrace(
        tuple(rx["choices"]), rx["range_position"], rx["range_condition"]
    )
    scorer = BoundTrace(struct.unpack_from(f"<{WINDOW}I", altered), trace)
    assessment = assess(prompt, substitute, 1, scorer)
    divergence = assessment.divergence
    require(
        assessment.kind == "deviation"
        and divergence is not None
        and divergence.index == 0
        and divergence.expected == reply[0]
        and assessment.statement == original,
        "RX did not identify the proved corrected prefix",
    )
    trusted = read(delivery / "descriptor.json")
    keys = read(delivery / "audit-private.json")
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["signer"]))
    key = PrivateKey(bytes.fromhex(keys["recipient"]))
    hmac_key = bytes.fromhex(keys["hmac"])
    runtime, checker = settings(config)
    require(
        read(delivery / "native-runtime.json") == runtime,
        "trusted verifier configuration changed",
    )
    originals = {
        name: read(delivery / (name + ".json")) for name in ("original", "substitute")
    }
    times = [
        datetime.fromisoformat(
            doc["verification"]["receipt"]["served_at"].replace("Z", "+00:00")
        )
        for doc in originals.values()
    ]
    actual_time = datetime.now(timezone.utc)
    actual_elapsed = (actual_time - max(times)).total_seconds()
    require(actual_elapsed >= 0, "signed receipt is in the future")
    audit_at = actual_time if elapsed_clock else max(times) + _AGE
    age = (audit_at - max(times)).total_seconds()
    require(age >= _AGE.total_seconds(), "historical receipt has not aged three days")

    def clock() -> datetime:
        return audit_at

    results: dict[str, Any] = {}
    retained_verdicts = {}
    with tempfile.TemporaryDirectory(dir=delivery.parent, prefix=".challenge-") as tmp:
        private = Path(tmp)
        audit_db = private / "challenge.sqlite"
        intake = intake_module.ChallengeIntake(
            audit_db,
            descriptor=trusted,
            assets=Path(config["assets"]),
            auditor_public_key=bytes(key.public_key),
            holder_hmac_key=hmac_key,
            clock=clock,
        )
        jobs = jobs_module.AuditJobs(
            audit_db,
            auditor_private_key=bytes(key),
            holder_hmac_key=hmac_key,
            clock=clock,
        )
        store = verdicts.VerdictStore(
            jobs, key_id=keys["key_id"], signer=signer, primary=checker, scorer=scorer
        )
        for name, tokens, expected, exit_code in (
            ("original", reply, "CONFORMS", 0),
            ("substitute", substitute, "DEVIATES", 21),
        ):
            bundle = originals[name]
            require(
                tuple(bundle["verification"]["prompt_token_ids"]) == prompt
                and tuple(bundle["verification"]["reply_token_ids"]) == tokens
                and bundle["max_tokens"] == 1,
                "retained historical receipt differs from the replay",
            )
            require(
                holder(
                    delivery / (name + ".json"),
                    delivery,
                    Path(config["assets"]),
                    receipt_only=True,
                )
                == (30, "RECEIPT_VERIFIED"),
                "holder could not verify historical signed receipt",
            )
            index = bundle["history"]["inclusion"]["leaf_index"]
            challenge = intake.submit("isolated-m2-holder", bundle, index)
            claim = jobs.claim(lease_time=timedelta(seconds=runtime["timeout_seconds"]))
            require(
                claim is not None and claim.prompt == prompt and claim.reply == tokens,
                "challenge did not reach the correct private audit job",
            )
            decision = store.settle(claim, candidate)
            require(
                decision.outcome == expected,
                "auditor did not independently settle expected outcome",
            )
            challenge_id, cap = challenge["challenge_id"], challenge["capability"]
            rows = store.by_commitment(claim.transcript)
            require(len(rows) == 1, "public signed verdict is missing")

            def lookup(role: str, kid: str) -> bytes | None:
                return (
                    signer.public_key().public_bytes_raw()
                    if (role, kid) == ("auditor", keys["key_id"])
                    else None
                )

            signed = signing.verify_signed(rows[0], lookup)
            require(
                signed["outcome"] == expected
                and signed["challenge_id"] == challenge_id
                and signed["proof_sha256"] == sha(candidate.proof)
                and signed["statement_sha256"] == sha(original),
                "signed verdict does not match independently checked evidence",
            )
            require(
                store.private_status(challenge_id, cap)["verdict"] == signed
                and store.private_proof(challenge_id, "invalid-capability") is None,
                "private challenge status or holder authorization failed",
            )
            artifact = store.private_proof(challenge_id, cap)
            require(
                artifact["kind"]
                == ("conformance" if name == "original" else "deviation")
                and bytes.fromhex(artifact["statement"]) == original
                and base64.b64decode(artifact["proof"], validate=True)
                == candidate.proof,
                "holder received a different checked artifact",
            )
            if name == "substitute":
                require(
                    artifact["index"] == 0 and artifact["expected"] == reply[0],
                    "incorrect deviation index or expected token",
                )
            full = private / (name + ".json")
            save(full, {**bundle, "proof": artifact})
            returned, outcome = holder(
                full, delivery, Path(config["assets"]), receipt_only=False
            )
            require(
                (returned, outcome) == (exit_code, expected),
                "holder CLI did not verify the expected outcome",
            )
            retained_verdicts[name] = signed
            results[name] = {
                "outcome": expected,
                "holder_exit": returned,
                "holder_outcome": outcome,
                "signed_verdict_verified": True,
                "receipt_reverified": True,
                "capability_rejected": True,
            }
    mode = "elapsed_wall_clock" if elapsed_clock else "controlled_plus_three_days"
    save(delivery.parent / ("signed-verdicts-" + mode + ".json"), retained_verdicts)
    return {
        "schema_version": 1,
        "status": "passed",
        "commitment_id": COMMITMENT,
        "flashprove_revision": REVISION,
        "original_statement_sha256": sha(original),
        "substitute_statement_sha256": sha(altered),
        "proof_sha256": sha(candidate.proof),
        "distinct_prover_verifier_hosts": True,
        "distinct_rx_verifier_hosts": True,
        "batch_size": 1,
        "challenge_clock": mode,
        "challenge_age_seconds": age,
        "actual_elapsed_seconds": actual_elapsed,
        "corrected_prefix_matches_proof": True,
        "original_matches_proof": True,
        "reference_trace_bound": True,
        **results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "work", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--elapsed", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    args.work.mkdir(mode=0o700, exist_ok=True)
    stat = args.work.lstat()
    if (
        not args.work.is_dir()
        or args.work.is_symlink()
        or stat.st_uid != os.geteuid()
        or stat.st_mode & 0o077
    ):
        parser.exit(1, "M2 requires an owner-only ordinary work directory\n")
    result: dict[str, Any] = {"schema_version": 1, "status": "incomplete"}
    save(args.output, result)
    try:
        config = read(args.config)
        require(config["schema_version"] == 1, "unknown configuration schema")
        with (args.work / ".lock").open("ab") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            retained = prepare(config, args.work)
            if args.prepare_only:
                result.update(
                    status="prepared",
                    commitment_id=COMMITMENT,
                    flashprove_revision=REVISION,
                )
            else:
                result = audit(config, retained, args.elapsed)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        sqlite3.Error,
        ImportError,
        subprocess.SubprocessError,
    ) as exc:
        result["reason"] = type(exc).__name__
    save(args.output, result)
    return 0 if result["status"] in ("passed", "prepared") else 1


if __name__ == "__main__":
    sys.exit(main())
