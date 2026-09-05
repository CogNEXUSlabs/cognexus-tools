"""Tests for the agent kill switch and the integrated guard helper."""

from __future__ import annotations

import threading
import time
import unittest
from collections import deque

import artzain.kill_switch as kill_switch
from artzain import (
    AgentKilledError,
    clear_global_panic,
    is_global_panic_active,
    is_killed,
    kill_record,
    raise_if_killed,
    recent_activations,
    screen_agent_action,
    set_default_on_kill,
    trip,
    trip_global,
)
from artzain.kill_switch import _reset_for_tests


class KillSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_for_tests()

    def tearDown(self) -> None:
        _reset_for_tests()

    def test_unknown_run_is_not_killed(self) -> None:
        self.assertFalse(is_killed(999))
        # Should be a no-op
        raise_if_killed(999)

    def test_trip_marks_run_killed_and_raises(self) -> None:
        with self.assertRaises(AgentKilledError) as ctx:
            trip(7, reason="testing", severity="critical")
        self.assertEqual(ctx.exception.run_id, 7)
        self.assertTrue(is_killed(7))
        rec = kill_record(7)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.reason, "testing")

    def test_trip_without_raise_does_not_propagate(self) -> None:
        rec = trip(8, reason="logged-only", raise_after_trip=False)
        self.assertEqual(rec.run_id, 8)
        self.assertTrue(is_killed(8))
        with self.assertRaises(AgentKilledError):
            raise_if_killed(8)

    def test_global_panic_kills_all_runs(self) -> None:
        trip_global(reason="systemic failure")
        self.assertTrue(is_global_panic_active())
        self.assertTrue(is_killed(1))
        self.assertTrue(is_killed(2))
        with self.assertRaises(AgentKilledError):
            raise_if_killed(1)
        cleared = clear_global_panic()
        self.assertTrue(cleared)
        self.assertFalse(is_global_panic_active())
        self.assertFalse(is_killed(1))

    def test_recent_activations_orders_newest_first(self) -> None:
        trip(1, reason="first", raise_after_trip=False)
        trip(2, reason="second", raise_after_trip=False)
        recent = recent_activations(limit=10)
        self.assertGreaterEqual(len(recent), 2)
        self.assertEqual(recent[0]["run_id"], 2)
        self.assertEqual(recent[1]["run_id"], 1)

    def test_screen_agent_action_clean(self) -> None:
        result = screen_agent_action(
            "SELECT id FROM customers LIMIT 5;",
            run_id=5,
        )
        self.assertFalse(result.is_destructive)
        self.assertFalse(is_killed(5))

    def test_screen_agent_action_critical_trips_kill_switch(self) -> None:
        with self.assertRaises(AgentKilledError):
            screen_agent_action(
                "DROP DATABASE production;",
                run_id=10,
                user_id=1,
                agent_id="my-agent",
                source="unit-test",
            )
        self.assertTrue(is_killed(10))
        rec = kill_record(10)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.severity, "critical")

    def test_screen_agent_action_high_does_not_kill(self) -> None:
        # `git clean -fd` is HIGH (not CRITICAL) — should log loudly but
        # leave the run alive so the orchestrator can decide.
        result = screen_agent_action(
            "git clean -fd",
            run_id=11,
            raise_on_critical=True,
        )
        self.assertTrue(result.is_destructive)
        self.assertFalse(is_killed(11))

    def test_screen_agent_action_does_nothing_when_already_killed(self) -> None:
        trip(20, reason="already dead", raise_after_trip=False)
        with self.assertRaises(AgentKilledError):
            screen_agent_action("anything goes", run_id=20)

    def test_auto_panic_window_is_counted_under_the_lock(self) -> None:
        # Deterministic replay of the race: this deque simulates another
        # thread appending a CRITICAL trip while the window is being
        # iterated.  The append only fires when nobody holds
        # ``_global_panic_lock`` -- i.e. when the count is computed outside
        # the lock, exactly the bug -- so under the fix the iteration is
        # never mutated.
        class _RacingWindow(deque):
            def __iter__(self):
                inner = super().__iter__()
                first = next(inner, None)
                if first is None:
                    return
                yield first
                if kill_switch._global_panic_lock.acquire(blocking=False):
                    try:
                        self.append(time.monotonic())
                    finally:
                        kill_switch._global_panic_lock.release()
                yield from inner

        original = kill_switch._panic_window
        kill_switch._panic_window = _RacingWindow(maxlen=original.maxlen)
        try:
            with self.assertRaises(AgentKilledError):
                trip(None, reason="first critical")
            with self.assertRaises(AgentKilledError):
                trip(None, reason="second critical")
        finally:
            kill_switch._panic_window = original

    def test_concurrent_critical_trips_raise_only_agent_killed_error(self) -> None:
        threshold = kill_switch._PANIC_THRESHOLD
        n_threads, per_thread = 8, max(2, threshold)
        unexpected: list[BaseException] = []
        start = threading.Barrier(n_threads)

        def worker() -> None:
            start.wait()
            for _ in range(per_thread):
                try:
                    trip(None, reason="concurrent critical")
                except AgentKilledError:
                    pass
                except BaseException as exc:  # noqa: BLE001
                    unexpected.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(unexpected, [])
        self.assertTrue(is_killed(1))
        panics = [r for r in recent_activations(limit=10_000) if r["surface"] == "global_panic"]
        self.assertEqual(len(panics), 1)


class OnKillCallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_for_tests()
        self.received: list = []
        set_default_on_kill(lambda r: self.received.append(r))

    def tearDown(self) -> None:
        set_default_on_kill(None)
        _reset_for_tests()

    def test_default_on_kill_fires_once_per_run(self) -> None:
        trip(99, reason="first", raise_after_trip=False)
        trip(99, reason="re-trip same run", raise_after_trip=False)
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0].reason, "first")

    def test_per_call_on_kill_overrides_default(self) -> None:
        captured = []
        trip(
            42, reason="custom callback",
            raise_after_trip=False,
            on_kill=lambda r: captured.append(r),
        )
        # Override fires; default does not.
        self.assertEqual(len(captured), 1)
        self.assertEqual(len(self.received), 0)

    def test_callback_failure_does_not_break_kill(self) -> None:
        def boom(_: object) -> None:
            raise RuntimeError("simulated callback failure")
        set_default_on_kill(boom)
        # Trip must still mark the run killed even though the callback raises.
        rec = trip(7, reason="callback fails", raise_after_trip=False)
        self.assertEqual(rec.run_id, 7)
        self.assertTrue(is_killed(7))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
