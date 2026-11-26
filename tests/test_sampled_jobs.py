"""Signed log and quicknet → encrypted auditor inbox → leaf-keyed proof job."""

from __future__ import annotations

import os
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

import rfc8785
from nacl.public import PrivateKey

from auditor.sampled_jobs import SampleBridge, SampleCursor
from escrow.mailbox import AuditorInbox
from escrow.sampler import deliver_selected
from escrow.store import Binding, EscrowStore
from gateway.renderer import CHAT_PROFILE_DIGEST, RAW_PROFILE_DIGEST, ChatRenderer
from log.receipt import params_digest, transcript_commitment
from prover.submission import COMMITMENT
from tests import test_selections
from tests.test_beacon import INFO, LATER
from tests.test_selection_record import leaf_for


class SampleBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.public = test_selections.SelectionPages()
        self.public.setUp()
        self.addCleanup(self.public.doCleanups)
        self.public.state.activate(0, "soak")
        self.counter = 0
        key = PrivateKey.generate()
        self.inbox = AuditorInbox(
            self.public.root / "inbox",
            auditor_private_key=bytes(key),
            clock=lambda: self.public.now,
        )
        self.escrow = EscrowStore(
            self.public.root / "escrow",
            wrapping_key=os.urandom(32),
            auditor_public_key=bytes(key.public_key),
            clock=lambda: self.public.now,
        )
        self.jobs = Mock()
        self.jobs.enqueue_sample.side_effect = lambda **kwargs: kwargs["leaf_hash"]
        self.jobs.sample_unavailable.side_effect = lambda **kwargs: kwargs["leaf_hash"]
        self.renderer = Mock(spec=ChatRenderer)
        self.bridge = SampleBridge(
            self.public.state,
            self.public.monitor,
            self.inbox,
            self.jobs,
            renderer=self.renderer,
        )

    def material(
        self,
        *,
        mode: str = "raw",
        renderer: ChatRenderer | None = None,
        change: dict[str, object] | None = None,
        reply: tuple[int, ...] = (2, 3),
    ) -> Binding:
        self.counter += 1
        wire = leaf_for(self.counter, "soak")
        wire.pop("leaf_hash")
        wire.pop("leaf_index")
        profile = RAW_PROFILE_DIGEST if mode == "raw" else CHAT_PROFILE_DIGEST
        messages = [{"role": "user", "content": "Sampled synthetic fixture"}]
        prompt = (11, 22) if renderer is None else renderer.render(messages)
        text = None if renderer is None else renderer.decode(reply)
        salt = self.counter.to_bytes(32, "big").hex()
        transcript = transcript_commitment(COMMITMENT, profile, 2, salt, prompt, reply)
        wire.update(
            commitment_id=COMMITMENT,
            render_profile=profile,
            params_digest=params_digest(2),
            transcript_commitment=transcript,
        )
        receipt = self.public.log.append(wire)
        binding = Binding(
            str(receipt["leaf_hash"]),
            transcript,
            str(wire["served_at"]),
            cast(int, wire["beacon_round"]),
            "soak",
        )
        private: dict[str, Any] = {
            "salt": salt,
            "max_tokens": 2,
            "prompt_token_ids": list(prompt),
            "reply_token_ids": list(reply),
            "reply_text": text,
        }
        if mode == "chat":
            private["messages"] = messages
        if change:
            private.update(change)
        self.escrow.stage(binding, rfc8785.dumps(private))
        return binding

    def observe(self) -> None:
        self.public.observe()
        self.public.state.sync(
            self.public.monitor,
            custody=self.escrow.status,
            chain_info=INFO,
            read_beacon=lambda _: LATER,
            limit=100,
        )

    def accept(self, binding: Binding) -> None:
        self.escrow.resolve(binding, selected=True)
        self.assertEqual(
            deliver_selected(self.escrow, binding.leaf_hash, self.inbox.accept),
            "selected",
        )

    def test_pending_leaf_does_not_block_and_restart_reuses_identity(self) -> None:
        first, second = self.material(), self.material()
        self.accept(second)
        self.observe()
        cursor = self.bridge.poll(limit=1)
        self.assertEqual(cursor, SampleCursor(1, 2))
        self.jobs.enqueue_sample.assert_not_called()
        self.assertIsNone(self.bridge.poll(cursor, limit=1))
        observed = self.jobs.enqueue_sample.call_args.kwargs
        self.assertEqual(
            (
                observed["leaf_hash"],
                observed["transcript"],
                observed["prompt"],
                observed["reply"],
                observed["budget"],
            ),
            (second.leaf_hash, second.transcript_commitment, (11, 22), (2, 3), 2),
        )
        self.accept(first)
        self.observe()
        restarted = SampleBridge(
            self.public.state,
            self.public.monitor,
            self.inbox,
            self.jobs,
            renderer=self.renderer,
        )
        self.assertIsNone(restarted.poll(limit=2))
        self.assertEqual(
            [c.kwargs["leaf_hash"] for c in self.jobs.enqueue_sample.call_args_list],
            [second.leaf_hash, first.leaf_hash],
        )
        self.assertIsNone(self.inbox.read(second))

    def test_authenticated_gap_missing_handoff_and_lost_ack(self) -> None:
        expired, missing, lost = self.material(), self.material(), self.material()
        self.accept(missing)
        self.inbox.purge(missing.leaf_hash)
        self.escrow.resolve(lost, selected=True)
        outbox = self.escrow.transfer(lost.leaf_hash)
        assert outbox is not None
        self.inbox.accept(outbox)  # The provider never sees this acknowledgment.
        self.public.now += timedelta(minutes=5)
        self.escrow.sweep()
        self.observe()
        self.bridge.poll(limit=4)
        self.assertEqual(
            [
                (v.kwargs["leaf_hash"], v.kwargs["reason"])
                for v in self.jobs.sample_unavailable.call_args_list
            ],
            [
                (expired.leaf_hash, "selection_gap"),
                (missing.leaf_hash, "missing_handoff"),
            ],
        )
        self.assertEqual(
            self.jobs.enqueue_sample.call_args.kwargs["leaf_hash"], lost.leaf_hash
        )

    def test_rejects_wrong_private_tokens_salt_budget_or_raw_display(self) -> None:
        changes: list[dict[str, object]] = [
            {"prompt_token_ids": [22, 11]},
            {"salt": "ff" * 32},
            {"max_tokens": True},
            {"reply_token_ids": [3, 2]},
            {"reply_text": "secret"},
            {"messages": []},
        ]
        for change in changes:
            self.accept(self.material(change=change))
        incomplete = self.material(reply=(3,))
        self.accept(incomplete)
        self.observe()
        self.bridge.poll(limit=10)
        self.jobs.enqueue_sample.assert_called_once()
        verified = self.jobs.enqueue_sample.call_args.kwargs
        self.assertEqual(
            (verified["leaf_hash"], verified["reply"], verified["budget"]),
            (incomplete.leaf_hash, (3,), 2),
        )
        self.assertEqual(
            [v.kwargs["reason"] for v in self.jobs.sample_unavailable.call_args_list],
            ["invalid_material"] * 6,
        )

    @unittest.skipUnless(
        os.environ.get("AKASHI_RENDER_ASSETS"), "requires pinned renderer assets"
    )
    def test_chat_renders_original_and_checks_exact_display(self) -> None:
        renderer = ChatRenderer(Path(os.environ["AKASHI_RENDER_ASSETS"]))
        good = self.material(mode="chat", renderer=renderer)
        for binding in (
            good,
            self.material(
                mode="chat",
                renderer=renderer,
                change={"messages": [{"role": "user", "content": "different"}]},
            ),
            self.material(
                mode="chat", renderer=renderer, change={"reply_text": "different"}
            ),
        ):
            self.accept(binding)
        self.observe()
        SampleBridge(
            self.public.state,
            self.public.monitor,
            self.inbox,
            self.jobs,
            renderer=renderer,
        ).poll(limit=3)
        self.jobs.enqueue_sample.assert_called_once()
        self.assertEqual(
            self.jobs.enqueue_sample.call_args.kwargs["leaf_hash"], good.leaf_hash
        )
        self.assertEqual(self.jobs.sample_unavailable.call_count, 2)

    def test_refuses_selection_from_other_history_or_wrong_leaf(self) -> None:
        self.accept(self.material())
        self.observe()
        with (
            patch.object(self.public.monitor, "root_at", return_value="ff" * 32),
            self.assertRaisesRegex(ValueError, "checkpoint"),
        ):
            self.bridge.poll(limit=2)
        page = self.public.state.page(0, 2)
        page["selections"][0]["transcript_commitment"] = "ff" * 32
        with (
            patch.object(self.public.state, "page", return_value=page),
            self.assertRaisesRegex(ValueError, "signed log"),
        ):
            self.bridge.poll(limit=2)
        self.jobs.enqueue_sample.assert_not_called()
        self.jobs.sample_unavailable.assert_not_called()


if __name__ == "__main__":
    unittest.main()
