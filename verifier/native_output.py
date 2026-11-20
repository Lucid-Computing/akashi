"""Check the F9 verifier's terminal result and its coverage of the supplied statement."""

import re
import struct
from typing import Literal

from prover.request import COMMITMENT, WINDOW

Outcome = Literal["verified", "rejected", "unavailable"]
_RECORD = (
    "; the table has a record: the binding of the weights rests on the theorem on codes "
    "(ePrint 2025/2055, Theorem 4.6), taken as given"
)
_COMMITMENT = re.compile(
    r"commitment: (1 closeness round of the one-time files rests|"
    r"(?:[2-9]|[1-9][0-9]+) closeness rounds of the one-time files rest) "
    r"on another source than the bound within a third of the distance"
    + re.escape(_RECORD)
)
_WORK = re.compile(
    r"proof of work: up to ([1-9][0-9]*) bits counted in (1 round|(?:[2-9]|[1-9][0-9]+) rounds); "
    r"with it the least round has ([0-9]+\.[0-9]{2}) bits, without it ([0-9]+\.[0-9]{2}) bits"
)


def native_outcome(
    code: int, output: bytes, statement: bytes, proof: bytes, policy: dict[str, str]
) -> Outcome:
    """Only a complete exact-match call with agreeing accounting and range fields can pass."""
    lines = output.decode("ascii", errors="replace").rstrip("\n").split("\n")
    if code == 1 and re.fullmatch(r"NO: [a-z0-9-]+", lines[-1]):
        return "rejected"
    if (
        code != 0
        or len(lines) < 4
        or lines[-1] != "YES"
        or sum(line.startswith("result-v1 ") for line in lines) != 1
        or any(line.startswith("TEST BUILD:") for line in lines)
        or len(statement) != 4 * (WINDOW + 2)
        or len(proof) < 12
        or proof[:8] != b"CPPF" + policy["version"].encode("ascii")
    ):
        return "unavailable"
    record = _COMMITMENT.fullmatch(lines[-4])
    if record is None:
        return "unavailable"
    work = _WORK.fullmatch(lines[-3])
    if work:
        bits, rounds, least, without = work.groups()
        if int(bits) > 32:
            return "unavailable"
        rounds = rounds.split()[0]
        least, without = re.escape(least), re.escape(without)
    elif lines[-3] == "proof of work: none counted":
        bits, rounds, least, without = "0", "0", r"([0-9]+\.[0-9]{2})", r"\1"
    else:
        return "unavailable"
    r, e = struct.unpack_from("<II", statement, WINDOW * 4)
    if not 0 <= r < e <= WINDOW:
        return "unavailable"
    last = min(e, WINDOW - 1)
    covered = rf"{r + 1}\.\.{last}" if last > r else "none"
    claim = "exact-match" if last > r else "next-token"
    y = "yes" if e == WINDOW else "no"
    leaf = struct.unpack_from("<I", proof, 8)[0]
    parameters = " ".join(
        f"{k}={re.escape(policy[k])}"
        for k in ("C", "theta", "cap", "s", "sh", "sT", "F")
    )
    expected = (
        f"result-v1 status=0 claim={claim} id={COMMITMENT} bits=128 work={bits} work-rounds={rounds} "
        f"least-round={least} least-round-without-work={without} "
        f"commitment-assumed-rounds={record[1].split()[0]} record=1 r={r} e={e} T={WINDOW} "
        f"tokens={covered} y={y} policy=exact-match {parameters} "
        f"above-clip=0 leaf={leaf} stages=key,leaf,request dw=8 build=[0-9a-f]{{64}}"
    )
    return "verified" if re.fullmatch(expected, lines[-2]) else "unavailable"
