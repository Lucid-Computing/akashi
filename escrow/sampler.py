"""Connect an authenticated public log reader and the pinned beacon to private escrow."""

from collections.abc import Callable, Mapping
from datetime import datetime
from threading import Event

from escrow.store import EscrowStore, Transfer


def resolve_logged_leaf(
    store: EscrowStore,
    index: int,
    chain_info: Mapping[str, object] | None,
    beacon: Mapping[str, object] | None,
    *,
    read_verified_leaf: Callable[[int], Mapping[str, object]],
    leaf_hash: Callable[[Mapping[str, object]], str],
    round_for: Callable[[datetime], int],
    round_is_open: Callable[[int, datetime], bool],
    select_round: Callable[
        [bytes, int, Mapping[str, object], Mapping[str, object]], Mapping[int, bool]
    ],
) -> str:
    """Take the fixed assignment from trusted log history; outages leave it pending until expiry."""
    if type(index) is not int or index < 0:
        raise ValueError("invalid public leaf index")
    leaf = read_verified_leaf(index)
    digest = leaf_hash(leaf)
    if (
        type(leaf.get("leaf_index")) is not int
        or leaf["leaf_index"] != index
        or leaf.get("leaf_hash") != digest
    ):
        raise ValueError("inconsistent public leaf")
    binding = store.binding(digest)
    if (
        any(
            getattr(binding, field) != leaf.get(field)
            for field in (
                "transcript_commitment",
                "served_at",
                "beacon_round",
                "sampling_mode",
            )
        )
        or type(leaf.get("beacon_round")) is not int
    ):
        raise ValueError("public leaf differs from staged escrow")
    timestamp = datetime.fromisoformat(binding.served_at.replace("Z", "+00:00"))
    if round_for(timestamp) != binding.beacon_round:
        raise ValueError("invalid escrow round assignment")
    status = store.status(digest)
    if status != "pending" or chain_info is None or beacon is None:
        return status
    if not round_is_open(binding.beacon_round, store.clock()):
        return "pending"
    # select_round authenticates the chain and the exact round before computing either rate.
    selections = select_round(
        bytes.fromhex(binding.transcript_commitment),
        binding.beacon_round,
        chain_info,
        beacon,
    )
    selected = selections[{"soak": 1, "live": 20}[binding.sampling_mode]]
    if type(selected) is not bool:
        raise ValueError("invalid beacon selection")
    return store.resolve(binding, selected=selected)


def deliver_selected(
    store: EscrowStore, leaf_hash: str, accept: Callable[[Transfer], str]
) -> str:
    """Retry an authenticated auditor handoff using the original leaf as the job ID."""
    transfer = store.transfer(leaf_hash)
    if transfer is None:
        return store.status(leaf_hash)
    if accept(transfer) != leaf_hash:
        raise ValueError("auditor acknowledged a different escrow transfer")
    store.ack_transfer(leaf_hash)
    return store.status(leaf_hash)


class ExpiryWorker:
    """Run under service supervision. stop() interrupts the wait for the next deadline."""

    def __init__(self, store: EscrowStore) -> None:
        self.store = store
        self._stop = Event()

    def run(self) -> None:
        with self.store.changed.reader() as wait:
            while not self._stop.is_set():
                self.store.sweep()
                deadline = self.store.next_expiry()
                delay = (
                    None
                    if deadline is None
                    else max(0.0, (deadline - self.store.clock()).total_seconds())
                )
                if self._stop.is_set():
                    return
                wait(delay)

    def stop(self) -> None:
        self._stop.set()
        self.store.changed.set()
