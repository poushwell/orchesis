"""Tests for the signed tracking journal (SPEC §1.9.2)."""

from __future__ import annotations

import hashlib
import threading

import pytest

from orchesis.signed_journal import (
    CURRENT_PHASE,
    JournalError,
    SignedJournal,
    _canonical,
    stamp_phase,
)


class TestAppendBasic:
    def test_first_event_links_to_genesis(self):
        j = SignedJournal()
        with stamp_phase("p1"):
            ev = j.append("hello", b"world")
        assert ev.seq == 1
        assert ev.phase_id == "p1"
        assert ev.prev_hash == bytes(32)

    def test_seq_monotonic(self):
        j = SignedJournal()
        with stamp_phase("p"):
            a = j.append("a", b"1")
            b = j.append("b", b"2")
            c = j.append("c", b"3")
        assert (a.seq, b.seq, c.seq) == (1, 2, 3)

    def test_phase_from_context_var_not_param(self):
        j = SignedJournal()
        with stamp_phase("policy"):
            ev = j.append("decision", b"pass")
        assert ev.phase_id == "policy"

    def test_unknown_phase_when_no_stamp(self):
        # Token didn't set the var.
        j = SignedJournal()
        ev = j.append("e", b"x")
        assert ev.phase_id == "unknown"

    def test_payload_types(self):
        j = SignedJournal()
        with stamp_phase("p"):
            e_bytes = j.append("b", b"hi")
            e_str = j.append("s", "hi")
            e_dict = j.append("d", {"x": 1, "y": 2})
        assert e_bytes.payload == b"hi"
        assert e_str.payload == b"hi"
        # Dict serialized with sorted keys + compact separators.
        assert e_dict.payload == b'{"x":1,"y":2}'

    def test_unsupported_payload_rejected(self):
        j = SignedJournal()
        with pytest.raises(JournalError, match="unsupported payload type"):
            j.append("e", 12345)  # type: ignore[arg-type]


class TestHashChain:
    def test_chain_links_correctly(self):
        j = SignedJournal()
        with stamp_phase("p"):
            a = j.append("a", b"1")
            b = j.append("b", b"2")
        assert b.prev_hash == a.event_hash

    def test_tail_hash_advances(self):
        j = SignedJournal()
        tail0 = j.tail_hash
        with stamp_phase("p"):
            j.append("a", b"1")
        tail1 = j.tail_hash
        assert tail0 != tail1
        with stamp_phase("p"):
            j.append("b", b"2")
        assert j.tail_hash != tail1

    def test_event_hash_matches_canonical(self):
        j = SignedJournal()
        with stamp_phase("p_x"):
            ev = j.append("hello", b"world")
        canonical = _canonical(
            ev.seq, ev.phase_id, ev.timestamp_ns,
            ev.event_type, ev.payload, ev.prev_hash,
        )
        expected = hashlib.sha256(canonical).digest()
        assert ev.event_hash == expected


class TestVerify:
    def test_clean_chain_verifies(self):
        j = SignedJournal()
        with stamp_phase("p"):
            for i in range(20):
                j.append(f"e{i}", str(i).encode())
        j.verify()  # no exception

    def test_tampered_payload_caught(self):
        j = SignedJournal()
        with stamp_phase("p"):
            j.append("a", b"1")
            j.append("b", b"2")
        # Tamper: replace the second event's payload via a new dataclass.
        # SignedJournal stores events in a private list — emulate tampering
        # by reconstructing the events tuple with a modified copy.
        from orchesis.signed_journal import JournalEvent
        events = list(j._events)  # private access ok in tests
        evil = JournalEvent(
            seq=events[1].seq,
            phase_id=events[1].phase_id,
            timestamp_ns=events[1].timestamp_ns,
            event_type=events[1].event_type,
            payload=b"tampered",
            prev_hash=events[1].prev_hash,
            event_hash=events[1].event_hash,
        )
        events[1] = evil
        j._events = events
        with pytest.raises(JournalError, match="hash mismatch"):
            j.verify()

    def test_sequence_gap_caught(self):
        j = SignedJournal()
        with stamp_phase("p"):
            j.append("a", b"1")
            j.append("b", b"2")
            j.append("c", b"3")
        # Remove the middle event.
        del j._events[1]
        with pytest.raises(JournalError, match="sequence gap"):
            j.verify()

    def test_prev_hash_mismatch_caught(self):
        from orchesis.signed_journal import JournalEvent
        j = SignedJournal()
        with stamp_phase("p"):
            j.append("a", b"1")
            j.append("b", b"2")
        events = list(j._events)
        # Corrupt the second event's prev_hash.
        evil = JournalEvent(
            seq=events[1].seq,
            phase_id=events[1].phase_id,
            timestamp_ns=events[1].timestamp_ns,
            event_type=events[1].event_type,
            payload=events[1].payload,
            prev_hash=bytes(32),
            event_hash=events[1].event_hash,
        )
        events[1] = evil
        j._events = events
        with pytest.raises(JournalError):
            j.verify()


class TestHmacCheckpoint:
    def test_checkpoint_requires_key(self):
        j = SignedJournal()
        with pytest.raises(JournalError, match="HMAC key not configured"):
            j.hmac_checkpoint()

    def test_checkpoint_changes_with_appends(self):
        j = SignedJournal(hmac_key=b"secret-key")
        with stamp_phase("p"):
            j.append("a", b"1")
        c1 = j.hmac_checkpoint()
        with stamp_phase("p"):
            j.append("b", b"2")
        c2 = j.hmac_checkpoint()
        assert c1 != c2
        # Both 32 bytes (SHA-256).
        assert len(c1) == 32
        assert len(c2) == 32


class TestStampPhase:
    def test_stamp_restores_on_exit(self):
        CURRENT_PHASE.set(None)
        with stamp_phase("outer"):
            assert CURRENT_PHASE.get() == "outer"
            with stamp_phase("inner"):
                assert CURRENT_PHASE.get() == "inner"
            assert CURRENT_PHASE.get() == "outer"
        assert CURRENT_PHASE.get() is None

    def test_stamp_isolates_across_appends(self):
        j = SignedJournal()
        with stamp_phase("alpha"):
            a = j.append("e", b"1")
        with stamp_phase("beta"):
            b = j.append("e", b"2")
        assert a.phase_id == "alpha"
        assert b.phase_id == "beta"


class TestConcurrency:
    def test_concurrent_appends_assign_unique_seqs(self):
        j = SignedJournal()
        errors: list[Exception] = []

        def worker():
            try:
                with stamp_phase("p"):
                    for _ in range(200):
                        j.append("e", b"x")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        seqs = [ev.seq for ev in j.events()]
        assert sorted(seqs) == list(range(1, len(seqs) + 1))
        j.verify()  # full chain still consistent
