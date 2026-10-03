"""A report the engine could not be given waits, in order, until it can.

After a governed write commits, the sidecar reports the sandbox's new policy
hash. Until now a report that failed was counted and lost: the engine went
on expecting the old hash, and the sandbox showed as drifted until its next
governed write.

* the report waits in a journal and is sent again until the engine takes it
  or refuses it for good;
* reports leave in the order they were made, so one made during an outage is
  never delivered after a later one for the same sandbox;
* with ``OPENSHELL_SIDECAR_JOURNAL`` the ones that wait survive a restart;
* the journal is hash-chained, and a file that does not verify is set aside
  and not replayed.
"""

from __future__ import annotations

import io
import json
import logging
import os
import stat
import sys
import threading
import urllib.error

import pytest

from artzain.openshell import journal as jn
from artzain.openshell import sidecar, transport
from artzain.openshell.journal import Journal
from artzain.openshell.state import GatewayLedger

DECISION = "01ABCDEFGHJKMNPQRSTVWXYZ0%d"


def _report(n, sandbox="sb-1"):
    return {"sandbox_id": sandbox, "policy_hash": "%064x" % n, "decision_id": DECISION % n,
            "method": "UpdateConfig"}


@pytest.fixture(autouse=True)
def _sidecar_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    for name in ("OPENSHELL_SIDECAR_JOURNAL", "OPENSHELL_SIDECAR_PROXY",
                 "OPENSHELL_SIDECAR_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_UNDELIVERED", sidecar.Counter())
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal())
    monkeypatch.setattr(sidecar, "_DELIVERING", threading.Lock())
    monkeypatch.setattr(sidecar, "_CLIENT", None)


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------


def test_entries_wait_in_order_and_leave_from_the_front():
    journal = Journal()
    assert (len(journal), journal.first(), journal.head) == (0, None, (0, jn.GENESIS))
    assert [journal.append("projection", _report(n)) for n in (1, 2, 3)] == [1, 2, 3]
    assert [entry["seq"] for entry in journal.pending()] == [1, 2, 3]
    assert journal.first()["body"] == _report(1)

    assert journal.settle(2) is False  # not the oldest: nothing changes
    assert len(journal) == 3 and journal.holds(2)
    assert journal.settle(1) is True and journal.settle(1) is False
    assert [entry["seq"] for entry in journal.pending()] == [2, 3]
    assert (journal.holds(1), journal.holds(3)) == (False, True)


def test_what_the_journal_hands_out_is_a_copy():
    journal = Journal()
    journal.append("projection", _report(1))
    journal.first()["body"]["policy_hash"] = "changed by the caller"
    journal.pending()[0]["hash"] = "changed by the caller"
    assert journal.first()["body"] == _report(1)
    assert journal.first()["hash"] == jn.entry_hash(1, journal.first()["at_ms"], "projection",
                                                    _report(1), jn.GENESIS)


def test_each_entry_is_chained_to_the_one_before():
    now = [1700000000.25]
    journal = Journal(clock=lambda: now[0])
    journal.append("projection", _report(1))
    now[0] += 60
    journal.append("projection", _report(2))
    first, second = journal.pending()
    assert first["at_ms"] == 1700000000250 and second["at_ms"] == 1700000060250
    assert first["prev"] == jn.GENESIS
    assert first["hash"] == jn.entry_hash(1, first["at_ms"], "projection", _report(1), jn.GENESIS)
    assert second["prev"] == first["hash"]
    assert second["hash"] == jn.entry_hash(2, second["at_ms"], "projection", _report(2),
                                           first["hash"])
    assert journal.head == (2, second["hash"])

    # The chain goes on from what left, so an entry cannot be slipped in before.
    journal.settle(1)
    journal.settle(2)
    assert journal.head == (2, second["hash"])
    journal.append("projection", _report(3))
    assert journal.first()["seq"] == 3 and journal.first()["prev"] == second["hash"]


def test_the_hash_covers_every_field():
    base = (7, 1700000000000, "projection", _report(1), "a" * 64)
    digest = jn.entry_hash(*base)
    assert len(digest) == 64 and digest == jn.entry_hash(*base)
    for index, other in enumerate((8, 1700000000001, "other", _report(2), "b" * 64)):
        changed = list(base)
        changed[index] = other
        assert jn.entry_hash(*changed) != digest, index
    reordered = dict(reversed(list(_report(1).items())))
    assert jn.entry_hash(7, 1700000000000, "projection", reordered, "a" * 64) == digest


def test_a_full_journal_refuses_and_takes_again_once_there_is_room():
    journal = Journal(max_pending=2)
    assert journal.append("projection", _report(1)) == 1
    assert journal.append("projection", _report(2)) == 2
    assert journal.append("projection", _report(3)) is None
    assert len(journal) == 2 and journal.head[0] == 2
    journal.settle(1)
    assert journal.append("projection", _report(3)) == 3


@pytest.mark.parametrize("body", [
    {"note": "x" * jn.MAX_BODY_BYTES}, {"when": object()}, {"n": float("nan")},
    {"n": float("inf")}, [("sandbox_id", "sb-1")][0], "a report", 7,
])
def test_only_a_small_json_object_is_journaled(body):
    journal = Journal()
    assert journal.append("projection", body) is None
    assert len(journal) == 0 and journal.head == (0, jn.GENESIS)


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "private" / "journal.json")


def test_what_waits_survives_a_restart_and_the_chain_goes_on(path):
    first = Journal(path=path, gateway_id="gw-a")
    for n in (1, 2, 3):
        first.append("projection", _report(n))
    first.settle(1)

    again = Journal(path=path, gateway_id="gw-a")
    assert again.pending() == first.pending()
    assert [entry["seq"] for entry in again.pending()] == [2, 3]
    assert again.head == first.head
    assert again.append("projection", _report(4)) == 4
    assert again.pending()[-1]["prev"] == first.head[1]

    emptied = Journal(path=path, gateway_id="gw-a")
    for seq in (2, 3, 4):
        assert emptied.settle(seq) is True
    # Nothing waits, and the next entry still follows the last one.
    assert len(Journal(path=path, gateway_id="gw-a")) == 0
    assert Journal(path=path, gateway_id="gw-a").head == emptied.head
    assert emptied.head[0] == 4


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_file_is_the_owners_alone(path):
    Journal(path=path, gateway_id="gw-a").append("projection", _report(1))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


def test_the_file_holds_what_a_report_holds_and_nothing_else(path):
    Journal(path=path, gateway_id="gw-a").append("projection", _report(1))
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    assert set(document) == {"version", "gateway_id", "base", "entries"}
    assert (document["version"], document["gateway_id"]) == (1, "gw-a")
    assert document["base"] == {"seq": 0, "hash": jn.GENESIS}
    (entry,) = document["entries"]
    assert set(entry) == {"seq", "at_ms", "kind", "body", "prev", "hash"}
    assert entry["body"] == _report(1)
    assert not os.path.exists(path + ".new")  # written whole, then renamed


def _rewrite(path, change):
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    change(document)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)


def _edit_a_hash(document):
    document["entries"][1]["body"]["policy_hash"] = "f" * 64


def _take_one_out(document):
    del document["entries"][1]


def _swap_two(document):
    document["entries"][0], document["entries"][1] = (
        document["entries"][1], document["entries"][0])


def _cut_the_front(document):
    del document["entries"][0]


def _move_the_base(document):
    document["base"]["hash"] = "e" * 64


def _renumber(document):
    for entry in document["entries"]:
        entry["seq"] += 10


def _rehash(document):
    """Recompute every hash and link, as someone rewriting the file would."""
    prev = document["base"]["hash"]
    for entry in document["entries"]:
        entry["prev"] = prev
        entry["hash"] = prev = jn.entry_hash(entry["seq"], entry["at_ms"], entry["kind"],
                                              entry["body"], prev)


def _a_gap_with_every_hash_redone(document):
    document["entries"][2]["seq"] += 1
    _rehash(document)


def _a_first_entry_that_does_not_follow_the_base(document):
    for entry in document["entries"]:
        entry["seq"] += 5
    _rehash(document)


def _backdate(document):
    document["entries"][0]["at_ms"] -= 1


def _rename_a_kind(document):
    document["entries"][0]["kind"] = "break_glass"


def _add_a_field(document):
    document["entries"][0]["note"] = "x"


def _not_an_entry(document):
    document["entries"][2] = "an entry"


def _no_base(document):
    del document["base"]


def _another_version(document):
    document["version"] = 2


def _entries_are_not_a_list(document):
    document["entries"] = {"0": document["entries"][0]}


def _a_base_that_is_not_a_hash(document):
    document["base"]["hash"] = "0" * 63 + "G"


def _a_negative_base(document):
    document["base"]["seq"] = -1


def _a_boolean_base(document):
    document["base"]["seq"] = False


@pytest.mark.parametrize("damage", [
    _edit_a_hash, _take_one_out, _swap_two, _cut_the_front, _move_the_base, _renumber,
    _a_gap_with_every_hash_redone, _a_first_entry_that_does_not_follow_the_base,
    _backdate, _rename_a_kind, _add_a_field, _not_an_entry, _no_base, _another_version,
    _entries_are_not_a_list, _a_base_that_is_not_a_hash, _a_negative_base, _a_boolean_base,
], ids=lambda damage: damage.__name__.strip("_"))
def test_a_file_that_does_not_verify_is_set_aside_and_not_replayed(path, damage, caplog):
    written = Journal(path=path, gateway_id="gw-a")
    for n in (1, 2, 3):
        written.append("projection", _report(n))
    _rewrite(path, damage)

    with caplog.at_level(logging.WARNING, logger="artzain.openshell.journal"):
        journal = Journal(path=path, gateway_id="gw-a")
    assert len(journal) == 0 and journal.head == (0, jn.GENESIS)
    assert "not replayed" in caplog.text
    assert os.path.exists(path + ".damaged") and not os.path.exists(path)
    # It works from here, in a new file.
    assert journal.append("projection", _report(4)) == 1
    assert len(Journal(path=path, gateway_id="gw-a")) == 1


@pytest.mark.parametrize("base", [
    {"seq": 3, "hash": "0" * 63 + "g"}, {"seq": 3, "hash": "A" * 64},
    {"seq": 3, "hash": "0" * 63}, {"seq": 3, "hash": "0" * 65}, {"seq": 3, "hash": 7},
    {"seq": 3, "hash": None}, {"seq": -1, "hash": "0" * 64}, {"seq": True, "hash": "0" * 64},
    {"seq": "3", "hash": "0" * 64}, {"seq": 3.0, "hash": "0" * 64}, {"seq": 3}, {},
    [3, "0" * 64], None,
], ids=repr)
def test_an_empty_journal_whose_base_is_not_one_is_set_aside(path, base):
    """With nothing waiting, the base is all the next entry has to follow."""
    written = Journal(path=path, gateway_id="gw-a")
    written.append("projection", _report(1))
    written.settle(1)
    assert Journal(path=path, gateway_id="gw-a").head == written.head  # as written, it reads

    def damage(document):
        document["base"] = base

    _rewrite(path, damage)
    journal = Journal(path=path, gateway_id="gw-a")
    assert journal.head == (0, jn.GENESIS) and os.path.exists(path + ".damaged")


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b"null", b'"journal"', b"\xff\xfe"])
def test_a_file_that_is_not_a_journal_is_set_aside(path, raw):
    os.makedirs(os.path.dirname(path))
    with open(path, "wb") as handle:
        handle.write(raw)
    assert len(Journal(path=path, gateway_id="gw-a")) == 0
    assert os.path.exists(path + ".damaged")


def test_a_file_cut_short_is_set_aside(path):
    written = Journal(path=path, gateway_id="gw-a")
    for n in (1, 2, 3):
        written.append("projection", _report(n))
    with open(path, "rb") as handle:
        whole = handle.read()
    with open(path, "wb") as handle:
        handle.write(whole[: len(whole) // 2])
    assert len(Journal(path=path, gateway_id="gw-a")) == 0
    assert os.path.exists(path + ".damaged")


def test_another_gateways_journal_is_not_read_and_not_set_aside(path, caplog):
    Journal(path=path, gateway_id="gw-b").append("projection", _report(1))
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.journal"):
        journal = Journal(path=path, gateway_id="gw-a")
    assert len(journal) == 0 and "another gateway's" in caplog.text
    assert not os.path.exists(path + ".damaged")
    assert len(Journal(path=path, gateway_id="gw-b")) == 1


def test_no_file_is_an_empty_journal_and_no_warning(path, caplog):
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.journal"):
        assert len(Journal(path=path, gateway_id="gw-a")) == 0
    assert caplog.text == "" and not os.path.exists(path)


def test_a_file_that_cannot_be_written_costs_the_restart_and_nothing_else(tmp_path, caplog):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a folder")
    journal = Journal(path=str(blocker / "journal.json"), gateway_id="gw-a")
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.journal"):
        assert journal.append("projection", _report(1)) == 1
        assert journal.append("projection", _report(2)) == 2
        assert journal.settle(1) is True
    assert len(journal) == 1
    assert caplog.text.count("report journal not written") == 1  # said once


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


class _Engine:
    """Stands in for ``_post_engine``. ``script`` is one behaviour per call:
    ``"ok"``, an HTTP status, or an exception to raise. ``sent`` is every
    report it was given, in order."""

    def __init__(self, script=()):
        self.script = list(script)
        self.sent = []

    def __call__(self, target, key, payload, *, retry_on_reset, timeout=None):
        assert target == "https://engine.example/api/v1/openshell/projections"
        assert retry_on_reset is False
        self.sent.append(dict(payload))
        step = self.script.pop(0) if self.script else "ok"
        if step == "ok":
            return {"sandbox_id": payload["sandbox_id"], "policy_hash": payload["policy_hash"]}
        if isinstance(step, int):
            raise urllib.error.HTTPError(target, step, "refused", {}, io.BytesIO(b"{}"))
        raise step


@pytest.fixture
def engine(monkeypatch):
    def start(script=()):
        eng = _Engine(script)
        monkeypatch.setattr(sidecar, "_post_engine", eng)
        return eng

    return start


def test_a_report_the_engine_takes_is_sent_at_once_and_does_not_wait(engine):
    eng = engine()
    assert sidecar.http_report_projection(_report(1)) is True
    assert eng.sent == [_report(1)]
    assert len(sidecar._JOURNAL) == 0 and sidecar._UNDELIVERED.value == 0


def test_a_report_the_engine_cannot_be_given_waits_and_is_counted_once(engine):
    eng = engine([ConnectionError("down"), TimeoutError("slow"), "ok"])
    assert sidecar.http_report_projection(_report(1)) is False
    assert len(sidecar._JOURNAL) == 1 and sidecar._UNDELIVERED.value == 1

    assert sidecar.deliver_reports() == []  # still out of reach
    assert len(sidecar._JOURNAL) == 1 and sidecar._UNDELIVERED.value == 1

    assert sidecar.deliver_reports() == [1]
    assert len(sidecar._JOURNAL) == 0 and sidecar._UNDELIVERED.value == 1
    assert eng.sent == [_report(1)] * 3


def test_reports_made_during_an_outage_are_delivered_in_the_order_they_were_made(engine):
    """The engine keeps the last hash it is told. Delivered out of order, the
    older hash would be the one it expects."""
    eng = engine([ConnectionError("down")])
    assert sidecar.http_report_projection(_report(1)) is False
    eng.script = [ConnectionError("down")] * 2
    assert sidecar.http_report_projection(_report(2)) is False
    assert sidecar.http_report_projection(_report(3, sandbox="sb-2")) is False
    # Each new report tried the oldest first, and none went ahead of it.
    assert eng.sent == [_report(1)] * 3
    assert sidecar._UNDELIVERED.value == 3

    eng.sent.clear()
    assert sidecar.http_report_projection(_report(4)) is True  # the engine is back
    assert eng.sent == [_report(1), _report(2), _report(3, sandbox="sb-2"), _report(4)]
    assert len(sidecar._JOURNAL) == 0


def test_a_report_that_waits_behind_ones_that_went_is_not_said_delivered(engine):
    eng = engine([ConnectionError("down")])
    sidecar.http_report_projection(_report(1))
    eng.script = ["ok", ConnectionError("down again")]
    assert sidecar.http_report_projection(_report(2)) is False
    assert eng.sent == [_report(1), _report(1), _report(2)]
    assert [entry["body"] for entry in sidecar._JOURNAL.pending()] == [_report(2)]
    assert sidecar._UNDELIVERED.value == 2


def test_a_report_the_engine_already_has_is_delivered(engine):
    """An earlier try landed and its answer was lost. The engine records one
    projection for a decision, and says so with 409."""
    eng = engine([409])
    assert sidecar.http_report_projection(_report(1)) is True
    assert len(sidecar._JOURNAL) == 0 and sidecar._UNDELIVERED.value == 0
    assert len(eng.sent) == 1


@pytest.mark.parametrize("status", [400, 403, 404, 410, 413, 422])
def test_a_report_refused_for_good_is_dropped_and_the_next_one_goes(engine, status, caplog):
    eng = engine([ConnectionError("down")])
    sidecar.http_report_projection(_report(1))
    eng.script = [status, "ok"]
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.sidecar"):
        assert sidecar.http_report_projection(_report(2)) is True
    assert eng.sent == [_report(1), _report(1), _report(2)]
    assert len(sidecar._JOURNAL) == 0
    assert "projection report refused: HTTP %d" % status in caplog.text
    assert sidecar._UNDELIVERED.value == 1  # counted when it first failed, and not again


def test_a_report_refused_on_its_first_try_is_counted(engine):
    engine([422])
    assert sidecar.http_report_projection(_report(1)) is False
    assert len(sidecar._JOURNAL) == 0 and sidecar._UNDELIVERED.value == 1


@pytest.mark.parametrize("failure", [401, 408, 429, 500, 502, 503, 504,
                                     ConnectionResetError(), OSError("no route"),
                                     transport.SettingsError("OPENSHELL_SIDECAR_PROXY ..."),
                                     ValueError("engine answer too large")])
def test_any_other_failure_is_tried_again_later(engine, failure):
    eng = engine([failure, failure])
    assert sidecar.http_report_projection(_report(1)) is False
    assert sidecar.deliver_reports() == []
    assert len(sidecar._JOURNAL) == 1 and len(eng.sent) == 2
    assert sidecar.deliver_reports() == [1]


def test_a_report_that_has_waited_three_days_is_given_up(engine, monkeypatch, caplog):
    now = [1_700_000_000.0]
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal(clock=lambda: now[0]))
    monkeypatch.setattr(sidecar.time, "time", lambda: now[0])
    eng = engine([503, 503, 503, "ok"])
    sidecar.http_report_projection(_report(1))
    now[0] += sidecar.REPORT_MAX_AGE_SECONDS
    assert sidecar.deliver_reports() == [] and len(sidecar._JOURNAL) == 1  # at the limit it waits
    now[0] += 1
    sidecar._JOURNAL.append("projection", _report(2))
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.sidecar"):
        assert sidecar.deliver_reports() == [2]  # given up, and the one behind it goes
    assert "given up after 72 h: HTTP 503" in caplog.text
    assert eng.sent == [_report(1)] * 3 + [_report(2)]


def test_an_old_report_the_engine_takes_is_still_delivered(engine, monkeypatch):
    now = [1_700_000_000.0]
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal(clock=lambda: now[0]))
    monkeypatch.setattr(sidecar.time, "time", lambda: now[0])
    engine([503, "ok"])
    sidecar.http_report_projection(_report(1))
    now[0] += 10 * sidecar.REPORT_MAX_AGE_SECONDS
    assert sidecar.deliver_reports() == [1]


def test_a_full_journal_drops_the_report_and_counts_it(engine, monkeypatch, caplog):
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal(max_pending=1))
    eng = engine([ConnectionError("down")] * 2)
    sidecar.http_report_projection(_report(1))
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.sidecar"):
        assert sidecar.http_report_projection(_report(2)) is False
    assert "the journal is full" in caplog.text
    assert sidecar._UNDELIVERED.value == 2 and len(eng.sent) == 1
    assert [entry["body"] for entry in sidecar._JOURNAL.pending()] == [_report(1)]


@pytest.mark.parametrize("unset", ["COGNEXUS_API_KEY", "ARTZAIN_DECISION_URL"])
def test_with_no_engine_or_no_key_nothing_is_journaled(engine, monkeypatch, unset):
    eng = engine()
    monkeypatch.delenv(unset)
    assert sidecar.http_report_projection(_report(1)) is False
    assert len(sidecar._JOURNAL) == 0 and eng.sent == []


def test_what_waits_is_kept_while_the_key_is_missing(engine, monkeypatch):
    eng = engine([ConnectionError("down")])
    sidecar.http_report_projection(_report(1))
    monkeypatch.delenv("COGNEXUS_API_KEY")
    assert sidecar.deliver_reports() == [] and len(sidecar._JOURNAL) == 1
    assert len(eng.sent) == 1  # not sent without a key
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    assert sidecar.deliver_reports() == [1]


def test_an_entry_of_a_kind_this_sidecar_does_not_send_does_not_hold_the_rest(engine):
    eng = engine()
    sidecar._JOURNAL.append("from_a_later_version", {"x": 1})
    assert sidecar.http_report_projection(_report(1)) is True
    assert eng.sent == [_report(1)] and len(sidecar._JOURNAL) == 0


def test_one_thread_delivers_at_a_time(engine):
    """A second caller does not send behind the first one's back, which is
    what would put two reports out of order."""
    eng = engine()
    sidecar._DELIVERING.acquire()
    try:
        assert sidecar.http_report_projection(_report(1)) is False
        assert sidecar.deliver_reports() == []
    finally:
        sidecar._DELIVERING.release()
    assert eng.sent == [] and len(sidecar._JOURNAL) == 1 and sidecar._UNDELIVERED.value == 1
    assert sidecar.deliver_reports() == [1]


def test_delivery_never_raises(engine, monkeypatch):
    engine()
    sidecar._JOURNAL.append("projection", _report(1))

    def broken(_entry):
        raise RuntimeError("a bug")

    monkeypatch.setattr(sidecar, "_send_report", broken)
    assert sidecar.deliver_reports() == []
    assert sidecar._DELIVERING.acquire(blocking=False)  # and the lock was let go
    sidecar._DELIVERING.release()


def test_reports_from_before_a_restart_are_delivered_first(engine, path, monkeypatch):
    """The brief's case: an outage, a restart, and the engine back."""
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal(path=path, gateway_id="gw-a"))
    eng = engine([ConnectionError("down")] * 2)
    sidecar.http_report_projection(_report(1))
    sidecar.http_report_projection(_report(2))

    # The next process.
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal(path=path, gateway_id="gw-a"))
    eng.sent.clear()
    assert sidecar.http_report_projection(_report(3)) is True
    assert eng.sent == [_report(1), _report(2), _report(3)]
    assert len(Journal(path=path, gateway_id="gw-a")) == 0


def test_main_reads_the_journal_it_is_given(path, monkeypatch, caplog):
    Journal(path=path, gateway_id="gw-a").append("projection", _report(1))
    monkeypatch.setenv("OPENSHELL_SIDECAR_JOURNAL", path)
    monkeypatch.setattr(sidecar, "warm", lambda: False)

    class Stop(Exception):
        pass

    def no_server(*_args):
        raise Stop()

    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", no_server)
    with caplog.at_level(logging.INFO, logger="artzain.openshell.sidecar"), pytest.raises(Stop):
        sidecar.main()
    assert [entry["body"] for entry in sidecar._JOURNAL.pending()] == [_report(1)]
    assert "1 report(s) from before the restart wait for the engine" in caplog.text


def test_main_keeps_house_while_it_serves_and_stops_when_it_ends(monkeypatch):
    monkeypatch.setattr(sidecar, "warm", lambda: False)
    seen = {}

    def keeping_house():
        return [t for t in threading.enumerate() if t.name == "openshell-housekeeping"]

    class Server:
        def __init__(self, address, handler):
            pass

        def serve_forever(self):
            seen["while serving"] = len(keeping_house())

    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", Server)
    monkeypatch.setattr(sidecar, "REPORT_RETRY_SECONDS", 0.5)
    before = len(keeping_house())
    sidecar.main()
    assert seen["while serving"] == before + 1
    for thread in keeping_house():
        thread.join(timeout=5)
    assert keeping_house() == []  # told to stop, and it did


# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------


def _housekeeper(now, waiting=0, warm_error=None):
    done = []

    def warm():
        done.append("warm")
        if warm_error is not None:
            raise warm_error

    keeper = sidecar.Housekeeper(clock=lambda: now[0], warm_fn=warm,
                                 deliver=lambda: done.append("deliver"),
                                 waiting=lambda: waiting)
    return keeper, done


def test_the_connection_is_renewed_every_thirty_seconds():
    now = [1000.0]
    keeper, done = _housekeeper(now)
    assert keeper.step() == 15.0 and done == []  # main() warmed it at start
    now[0] += 29.9
    keeper.step()
    assert done == []
    now[0] += 0.1
    assert keeper.step() == pytest.approx(14.9) and done == ["warm"]  # the next delivery turn
    now[0] += 30.0
    keeper.step()
    assert done == ["warm", "warm"]


def test_reports_that_wait_are_tried_every_fifteen_seconds():
    now = [1000.0]
    keeper, done = _housekeeper(now, waiting=2)
    now[0] += 14.9
    assert keeper.step() == pytest.approx(0.1) and done == []
    now[0] += 0.1
    assert keeper.step() == 15.0 and done == ["deliver"]
    now[0] += 15.0
    keeper.step()
    assert done == ["deliver", "deliver", "warm"]


def test_with_nothing_waiting_nothing_is_sent():
    now = [1000.0]
    keeper, done = _housekeeper(now, waiting=0)
    now[0] += 15.0
    keeper.step()
    assert done == []


def test_a_setting_that_went_bad_does_not_end_the_loop(caplog):
    now = [1000.0]
    keeper, done = _housekeeper(
        now, warm_error=transport.SettingsError("OPENSHELL_SIDECAR_CA_BUNDLE is not a file"))
    now[0] += 30.0
    with caplog.at_level(logging.WARNING, logger="artzain.openshell.sidecar"):
        assert keeper.step() == 15.0
    assert done == ["warm"]
    assert "engine connection settings: OPENSHELL_SIDECAR_CA_BUNDLE is not a file" in caplog.text


def test_the_loop_survives_an_error_and_stops_when_told(monkeypatch):
    stop = threading.Event()
    turns = []

    class Keeper(sidecar.Housekeeper):
        def step(self):
            turns.append(len(turns))
            if len(turns) == 1:
                raise RuntimeError("a bug")
            stop.set()
            return 0.0

    monkeypatch.setattr(sidecar, "REPORT_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(threading.Event, "wait", lambda self, timeout=None: None)
    Keeper().run(stop)
    assert turns == [0, 1]


def test_by_default_it_keeps_the_real_connection_warm_and_delivers_the_real_journal(
        engine, monkeypatch):
    eng = engine()
    warmed = []
    monkeypatch.setattr(sidecar, "warm", lambda: warmed.append(1))
    now = [1000.0]
    keeper = sidecar.Housekeeper(clock=lambda: now[0])
    sidecar._JOURNAL.append("projection", _report(1))
    now[0] += 30.0
    keeper.step()
    assert eng.sent == [_report(1)] and warmed == [1]
