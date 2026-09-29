"""A key set with ``configure()`` goes only to the host set with it.

``configure(api_key=..., base_url=...)`` sets a key and the host it goes to,
and a call reads the two when it decides where to send. A call that read them
while a ``configure()`` on another thread was changing them could take the new
key with the old host, or the old key with the new one, and send a key to a
host it was not configured for.

These tests make the two meet at every step. A trace function stops one call
before each bytecode instruction it runs in the package, one run per
instruction, and makes the other call on another thread while it waits: a
thread switch at that instruction, made to happen rather than hoped for under
load. A call that has to wait for the stopped one, for a lock it holds, is
waited for only so long and lands after it.

On Python 3.12, once a frame has asked for opcode events, every later
``sys.settrace()`` in the process gets them too, so a tracer that runs after
these tests in the same process (a coverage tool's, say) is slower. What it
reports is unaffected.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import traceback
import urllib.request
from collections.abc import Callable
from typing import Any, NamedTuple, NoReturn, Optional

import pytest

from artzain import _helpers, cloud
from artzain._helpers import load_client_policy_rules
from artzain.decide import decide

KEY_A = "cnx_configured_for_a_0123456789"
HOST_A = "https://a.example.test"
KEY_B = "cnx_configured_for_b_9876543210"
HOST_B = "https://b.example.test"
A = (KEY_A, HOST_A)
B = (KEY_B, HOST_B)
DECISIONS = "/api/v1/decisions"

#: The code whose instructions are stepped through: every module of the
#: package, so the other call lands inside a read of the settings wherever in
#: the package that read is made.
_PACKAGE_DIR = os.path.normcase(os.path.dirname(cloud.configure.__code__.co_filename)) + os.sep
#: A bound on the runs per test, so a trace that never ends fails instead.
_MAX_STEPS = 5000
#: Seconds a stopped call waits for the other call: that takes milliseconds,
#: unless it has to wait for the stopped call in turn.
_OTHER_CALL_WAIT = 2.0
#: Seconds the two calls of a run may take in all. Past that one has hung, and
#: the tests after it would wait on the locks it holds, so the session stops.
_RUN_TIMEOUT = 30.0

Pair = tuple[Optional[str], Optional[str]]

#: Which of the two configurations each key and host belongs to.
_OWNER = {KEY_A: "A", HOST_A: "A", KEY_B: "B", HOST_B: "B"}


class _Run(NamedTuple):
    """One run: what the stopped call and the other call returned, and what
    the *after* check returned once both had finished."""

    result: Any
    other: Any
    after: Any


def _configure(pair: Pair) -> None:
    cloud.configure(api_key=pair[0], base_url=pair[1])


def _resolved() -> Pair:
    creds = cloud._resolve()
    return creds.api_key, creds.base_url


def _name(pair: Pair) -> str:
    """``"A"`` or ``"B"`` for either whole pair, else whose key went with
    whose host."""
    if pair in (A, B):
        return _OWNER[str(pair[0])]
    key, host = pair
    return f"{_OWNER.get(str(key), repr(key))}'s key with {_OWNER.get(str(host), repr(host))}'s host"


def _stop_the_session(why: str) -> NoReturn:
    """A call that never finishes keeps the locks it took, and every test after
    it would wait on them: stop here, with each thread's stack."""
    stacks = "".join(
        f"\nthread {ident}:\n{''.join(traceback.format_stack(frame))}"
        for ident, frame in sys._current_frames().items()
    )
    pytest.exit(why + stacks, returncode=1)


def _run_stepped(
    call: Callable[[], Any], other_call: Callable[[], Any], step: int, wait: float
) -> tuple[Any, bool, Any]:
    """Run *call* on a thread of its own and stop it just before instruction
    number *step* (counted over the instructions it runs in the package) while
    *other_call* runs on another thread, for up to *wait* seconds. Returns
    what *call* returned, whether that instruction was reached, and what
    *other_call* returned."""
    count = 0
    other_threads: list[threading.Thread] = []
    outcomes: dict[str, dict[str, Any]] = {"call": {}, "other call": {}}

    def _record(name: str, run: Callable[[], Any]) -> None:
        try:
            outcomes[name]["result"] = run()
        except BaseException as exc:  # raised again on the test's thread
            outcomes[name]["error"] = exc

    def _opcode(frame: Any, event: str, _arg: Any) -> Any:
        nonlocal count
        if event == "opcode":
            if count == step:
                other = threading.Thread(
                    target=_record, args=("other call", other_call), daemon=True
                )
                other_threads.append(other)
                other.start()
                other.join(wait)
            count += 1
        return _opcode

    def _call(frame: Any, _event: str, _arg: Any) -> Any:
        if not os.path.normcase(frame.f_code.co_filename).startswith(_PACKAGE_DIR):
            return None
        # The frame's trace function is set before its opcode events are asked
        # for: Python 3.13 and later start them for this call only when it has
        # one.
        frame.f_trace = _opcode
        frame.f_trace_opcodes = True
        return _opcode

    def _traced() -> None:
        sys.settrace(_call)
        try:
            _record("call", call)
        finally:
            sys.settrace(None)

    # A thread of its own, so the test's thread keeps its trace function (a
    # coverage tool's, say).
    traced = threading.Thread(target=_traced, daemon=True)
    deadline = time.monotonic() + _RUN_TIMEOUT
    traced.start()
    traced.join(_RUN_TIMEOUT)
    for other in other_threads:
        other.join(max(0.0, deadline - time.monotonic()))
    if traced.is_alive() or any(other.is_alive() for other in other_threads):
        _stop_the_session(f"step {step}: a call did not finish in {_RUN_TIMEOUT:.0f}s")
    for outcome in outcomes.values():
        if "error" in outcome:
            raise outcome["error"]
    return (
        outcomes["call"].get("result"),
        bool(other_threads),
        outcomes["other call"].get("result"),
    )


def _at_every_step(
    call: Callable[[], Any],
    other_call: Callable[[], Any],
    setup: Callable[[], None],
    *,
    wait: float = _OTHER_CALL_WAIT,
    after: Callable[[], Any] = lambda: None,
) -> list[_Run]:
    """Run *call* once for each instruction it runs, after *setup*, with
    *other_call* made while it is stopped before that instruction, and
    *after* once both have finished. Returns one :class:`_Run` per run."""
    # Python 3.12 starts the opcode events a frame asks for only from the
    # next sys.settrace() on, so the first run only asks for them.
    setup()
    _run_stepped(call, other_call, -1, wait)
    runs: list[_Run] = []
    for step in range(_MAX_STEPS):
        setup()
        result, reached, other_result = _run_stepped(call, other_call, step, wait)
        if not reached:
            return runs
        runs.append(_Run(result, other_result, after()))
    pytest.fail(f"the call ran more than {_MAX_STEPS} instructions")


def _assert_each_key_went_with_its_host(read: list[Pair]) -> None:
    names = [_name(pair) for pair in read]
    split = [f"step {step}: {name}" for step, name in enumerate(names) if name not in ("A", "B")]
    assert not split, split
    # Not vacuous: the other call landed on both sides of the read.
    assert set(names) == {"A", "B"}, (
        f"every run got {names[0] if names else 'nothing'}: the other call never "
        "landed on both sides of the read"
    )


class _Answer:
    """What the decision API answers."""

    def read(self) -> bytes:
        return json.dumps(
            {
                "outcome": "allow",
                "decision_id": "d",
                "audit_block_id": "b",
                "contributing_agents": [],
                "reasons": [],
            }
        ).encode("utf-8")

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


@pytest.fixture(params=["decide", "policy_rules"])
def read(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> Callable[[], Pair]:
    """A call that reads the settings, returning the key it took and the host
    it took with it.

    * ``decide()``: the key and the host of the request it sends.
    * The policy-rules loader while the credentials profile cannot be read:
      the key and host set above the profile, which it compares with the ones
      the rules it holds were fetched with.
    """
    if request.param == "decide":
        sent: list[Pair] = []

        def _urlopen(req: urllib.request.Request, timeout: Any = None) -> _Answer:
            assert req.full_url.endswith(DECISIONS), req.full_url
            sent.append((req.get_header("X-api-key"), req.full_url[: -len(DECISIONS)]))
            return _Answer()

        monkeypatch.setattr(cloud, "_urlopen", _urlopen)

        def _decide() -> Pair:
            decide(action="send_email", target="crm:contact:1", payload="hello", kind="user_input")
            return sent[-1]

        return _decide

    profile = tmp_path / "credentials.toml"
    profile.write_bytes(b"\xff\xfe not UTF-8")
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(profile))
    # Each run is a first failed fetch, and warns.
    caplog.set_level(logging.ERROR, logger="artzain.security")
    compared: list[Pair] = []
    unreadable = _helpers._policy_rules_profile_unreadable

    def _record(generation: int, key: Optional[str], host: Optional[str]) -> Any:
        compared.append((key, host))
        return unreadable(generation, key, host)

    monkeypatch.setattr(_helpers, "_policy_rules_profile_unreadable", _record)

    def _load() -> Pair:
        _helpers._policy_rules_cache = None
        load_client_policy_rules()
        return compared[-1]

    return _load


def test_a_configure_at_any_step_of_a_read_leaves_each_key_with_its_host(
    read: Callable[[], Pair],
) -> None:
    """``configure()`` switches from A's key and host to B's between two
    instructions of the read, at each instruction in turn: the read uses A's
    pair or B's, never a key with the other one's host."""
    runs = _at_every_step(read, lambda: _configure(B), setup=lambda: _configure(A))

    _assert_each_key_went_with_its_host([run.result for run in runs])


def test_a_read_at_any_step_of_a_configure_gets_each_key_with_its_host(
    read: Callable[[], Pair],
) -> None:
    """The read is made between two instructions of a ``configure()`` that
    switches from A's key and host to B's, at each instruction in turn, and
    gets A's pair or B's."""
    runs = _at_every_step(lambda: _configure(B), read, setup=lambda: _configure(A))

    _assert_each_key_went_with_its_host([run.other for run in runs])


def test_a_read_at_any_step_of_a_configure_sees_the_new_generation_only_with_the_new_pair() -> None:
    """The policy-rules loader reads ``_credentials_generation`` before the
    settings and files the rules it fetches under that generation
    (``test_policy_rules_fetch_failure.py`` pins that order). So
    ``configure()`` bumps it only once the new pair is in place: a read made in
    that order that sees the new generation gets the new pair too."""
    generation_before: list[int] = []

    def _setup() -> None:
        _configure(A)
        generation_before[:] = [cloud._credentials_generation]

    def _read() -> str:
        bumped = cloud._credentials_generation > generation_before[0]
        return f"{'new' if bumped else 'old'} generation, {_name(_resolved())}"

    runs = _at_every_step(lambda: _configure(B), _read, setup=_setup)

    read = [run.other for run in runs]
    assert "new generation, A" not in read, read
    assert {"old generation, A", "new generation, B"} <= set(read), read


def test_two_configure_calls_at_any_step_of_each_other_keep_both_changes() -> None:
    """One ``configure()`` sets only the key while another sets only the base
    URL, at each step of the first in turn. Each replaces the pair it read, so
    were they not one at a time the later one would put back the half the
    other had just changed, and leave B's key with A's host. Both changes are
    kept."""
    runs = _at_every_step(
        lambda: cloud.configure(api_key=KEY_B),
        lambda: cloud.configure(base_url=HOST_B),
        setup=lambda: _configure(A),
        # At most steps the other call waits for configure()'s lock, so it is
        # waited for only briefly: the lock decides the outcome, not the wait.
        wait=0.05,
        after=_resolved,
    )

    kept = [_name(run.after) for run in runs]
    assert kept, "the trace saw no instruction of configure()"
    assert all(name == "B" for name in kept), [
        f"step {step}: {name}" for step, name in enumerate(kept) if name != "B"
    ]


def test_a_configure_that_raises_changes_neither_setting() -> None:
    """A value that cannot be turned into text fails the call, and neither
    setting changes: the new key is not left with the host set before."""

    class _NoText:
        def __str__(self) -> str:
            raise ValueError("no text")

    _configure(A)
    generation = cloud._credentials_generation

    with pytest.raises(ValueError):
        cloud.configure(api_key=KEY_B, base_url=_NoText())

    assert _name(_resolved()) == "A"
    assert cloud._credentials_generation == generation
