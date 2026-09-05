"""Agent Kill Switch — cooperative cancellation + auto-stop on critical signals.

The kill switch is the missing safety layer the PocketOS / Claude incident
exposed: a programmatic, *out-of-prompt* mechanism that stops an in-flight
agent run when any critical signal trips, and gives operators a manual
"red button" to halt a run from outside the model's reasoning loop.

The model's own promises are not trustworthy — the Cursor / Claude agent
acknowledged the rule "NEVER run destructive/irreversible git commands" and
violated it nine seconds later.  This module enforces the rule from
**outside** the LLM:

* :func:`trip` marks a specific ``run_id`` as killed and (optionally) raises
  :class:`AgentKilledError`.
* :func:`raise_if_killed` is the cooperative-cancellation poll point that
  long-running orchestrators sprinkle between tool calls.
* :func:`trip_global` flips a process-wide panic flag that aborts *every*
  in-flight and future run until cleared (use for systemic failures, e.g.
  the destructive-action guard tripping more than N times per minute).
* :func:`screen_agent_action` is the integrated "guard → kill" helper —
  callers run model output through it before executing the action.

Quick-start::

    from artzain import (
        screen_agent_action,
        raise_if_killed,
        AgentKilledError,
    )

    try:
        for step in plan:
            raise_if_killed(run_id)
            payload = render_tool_call(step)
            screen_agent_action(
                payload, run_id=run_id, user_id=user.id,
                agent_id="my-agent", source=step.tool,
            )
            execute(payload)
    except AgentKilledError as kex:
        mark_run_killed(run_id, kex.reason)
        raise

Persistence
-----------
The package is dependency-free, so the kill switch never touches your
database directly.  Provide an ``on_kill`` callback (globally via
:func:`set_default_on_kill` or per-call) to mirror trips into your own
``agent_runs`` table, monitoring queue, or PagerDuty integration.

Configuration
-------------
Two env vars tune the auto-panic detector:

``COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD`` (default ``5``)
    Number of CRITICAL trips inside the rolling window required to raise
    the process-wide panic flag automatically.
``COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS`` (default ``60``)
    Length of the rolling window in seconds.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from artzain.destructive_action_guard import (
    ActionScreenResult,
    ActionSeverity,
    screen_action,
)

logger = logging.getLogger("artzain.kill_switch")

OnKillCallback = Callable[["KillRecord"], None]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AgentKilledError(RuntimeError):
    """Raised when an agent run has been (or is being) killed.

    Catch in orchestrators to ensure the run unwinds cleanly and your
    own "agent run" record is marked terminal before the process moves on.
    """

    def __init__(
        self,
        run_id: Optional[Any],
        reason: str,
        severity: str = "critical",
    ) -> None:
        self.run_id = run_id
        self.reason = reason
        self.severity = severity
        super().__init__(f"agent run {run_id} killed: {reason}")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@dataclass
class KillRecord:
    """One entry in the kill-switch ledger."""

    run_id: Optional[Any]
    user_id: Optional[Any]
    agent_id: Optional[str]
    reason: str
    severity: str
    surface: str
    source: str
    tripped_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload_sha256: Optional[str] = None
    matches: list[dict] = field(default_factory=list)
    manual: bool = False  # True iff trip came from a REST endpoint / operator

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "reason": self.reason,
            "severity": self.severity,
            "surface": self.surface,
            "source": self.source,
            "tripped_at": self.tripped_at,
            "payload_sha256": self.payload_sha256,
            "matches": self.matches,
            "manual": self.manual,
        }


# Recent activations (bounded ring) — for ``recent_activations()``.
_recent_lock = threading.Lock()
_recent: deque[KillRecord] = deque(maxlen=200)

# Per-run kill flags.  Keyed by ``run_id``.
_killed_lock = threading.Lock()
_killed_runs: dict[Any, KillRecord] = {}

# Process-wide panic flag (rare).
_global_panic_lock = threading.Lock()
_global_panic: Optional[KillRecord] = None

# Default on_kill callback (settable via :func:`set_default_on_kill`).
_default_on_kill_lock = threading.Lock()
_default_on_kill: Optional[OnKillCallback] = None

# Auto-panic detector — if more than _PANIC_THRESHOLD critical trips happen
# in a rolling _PANIC_WINDOW_SECONDS, flip the global panic flag.
_PANIC_THRESHOLD = int(os.environ.get("COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD", "5"))
_PANIC_WINDOW_SECONDS = int(
    os.environ.get("COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS", "60")
)
_panic_window: deque[float] = deque(maxlen=max(1, _PANIC_THRESHOLD * 4))


# ---------------------------------------------------------------------------
# Pluggable callbacks
# ---------------------------------------------------------------------------


def set_default_on_kill(callback: Optional[OnKillCallback]) -> None:
    """Install a process-wide callback fired on every kill-switch trip.

    The callback receives the :class:`KillRecord` as its only argument and
    runs *after* the in-memory state and logs are written, so a slow or
    failing callback cannot prevent the run from being marked killed.
    Exceptions raised inside the callback are caught and logged.

    Pass ``None`` to clear the callback.

    Typical use::

        from artzain import set_default_on_kill

        def persist(record):
            db.execute(
                "UPDATE agent_runs SET status='killed', error_message=%s "
                "WHERE id=%s",
                (record.reason, record.run_id),
            )

        set_default_on_kill(persist)
    """
    global _default_on_kill
    with _default_on_kill_lock:
        _default_on_kill = callback


def _fire_on_kill(record: KillRecord, override: Optional[OnKillCallback]) -> None:
    cb = override or _default_on_kill
    if cb is None:
        return
    try:
        cb(record)
    except Exception as exc:
        logger.error("kill_switch on_kill callback raised: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def trip(
    run_id: Optional[Any],
    *,
    reason: str,
    severity: str = "critical",
    user_id: Optional[Any] = None,
    agent_id: Optional[str] = None,
    surface: str = "agent_action",
    source: str = "internal",
    payload_sha256: Optional[str] = None,
    matches: Optional[list[dict]] = None,
    manual: bool = False,
    raise_after_trip: bool = True,
    on_kill: Optional[OnKillCallback] = None,
) -> KillRecord:
    """Trip the kill switch for *run_id*.

    The call is idempotent — re-tripping a run with a different reason
    updates the latest record but does not double-fire side-effects.
    """
    global _global_panic
    record = KillRecord(
        run_id=run_id,
        user_id=user_id,
        agent_id=agent_id,
        reason=reason,
        severity=severity,
        surface=surface,
        source=source,
        payload_sha256=payload_sha256,
        matches=matches or [],
        manual=manual,
    )

    first_trip = True
    if run_id is not None:
        with _killed_lock:
            if run_id in _killed_runs:
                first_trip = False
            _killed_runs[run_id] = record

    with _recent_lock:
        _recent.append(record)

    logger.critical(
        "AGENT_KILL_SWITCH tripped run_id=%s user_id=%s agent_id=%s severity=%s "
        "surface=%s source=%s manual=%s reason=%s",
        run_id, user_id, agent_id, severity, surface, source, manual, reason,
    )

    if first_trip:
        _fire_on_kill(record, on_kill)

    # Auto-panic: if too many criticals fire in a short window, trip global.
    # The window append, the count and the panic decision all happen under
    # _global_panic_lock so concurrent trips cannot mutate the deque while
    # another thread iterates it; the flag is flipped in the same critical
    # section so the auto-panic fires exactly once.  Slow side effects
    # (audit ring, logging, the on_kill callback) run after the lock is
    # released.
    if severity == "critical" and not manual:
        panic_record: Optional[KillRecord] = None
        now = time.monotonic()
        with _global_panic_lock:
            _panic_window.append(now)
            recent_in_window = sum(
                1 for ts in _panic_window if now - ts <= _PANIC_WINDOW_SECONDS
            )
            if recent_in_window >= _PANIC_THRESHOLD and _global_panic is None:
                panic_record = _global_panic_record(
                    reason=(
                        f"auto-panic: {recent_in_window} critical trips in "
                        f"{_PANIC_WINDOW_SECONDS}s"
                    ),
                    source="kill_switch.auto_panic",
                    manual=False,
                )
                _global_panic = panic_record
        if panic_record is not None:
            _announce_global_panic(panic_record, on_kill)

    if raise_after_trip:
        raise AgentKilledError(run_id, reason, severity)
    return record


def _global_panic_record(*, reason: str, source: str, manual: bool) -> KillRecord:
    return KillRecord(
        run_id=None,
        user_id=None,
        agent_id=None,
        reason=reason,
        severity="critical",
        surface="global_panic",
        source=source,
        manual=manual,
    )


def _announce_global_panic(
    record: KillRecord, on_kill: Optional[OnKillCallback]
) -> None:
    """Side effects of a global panic; must be called *without* the lock held."""
    with _recent_lock:
        _recent.append(record)
    logger.critical(
        "GLOBAL_KILL_SWITCH tripped source=%s manual=%s reason=%s",
        record.source, record.manual, record.reason,
    )
    _fire_on_kill(record, on_kill)


def trip_global(
    *,
    reason: str,
    source: str = "internal",
    manual: bool = False,
    on_kill: Optional[OnKillCallback] = None,
) -> KillRecord:
    """Flip the process-wide panic flag.

    Every call to :func:`raise_if_killed` after this raises until
    :func:`clear_global_panic` is called, regardless of run id.
    """
    global _global_panic
    record = _global_panic_record(reason=reason, source=source, manual=manual)
    with _global_panic_lock:
        _global_panic = record
    _announce_global_panic(record, on_kill)
    return record


def clear_global_panic(*, source: str = "operator") -> bool:
    """Lift the global panic flag.  Per-run kills remain in effect."""
    global _global_panic
    with _global_panic_lock:
        was_set = _global_panic is not None
        _global_panic = None
    if was_set:
        logger.warning("GLOBAL_KILL_SWITCH cleared by %s", source)
    return was_set


def clear_run(run_id: Any) -> bool:
    """Clear an individual run's kill flag.

    Mostly used by tests; production code should prefer to start a new
    agent-run record rather than reuse a killed one.
    """
    with _killed_lock:
        return _killed_runs.pop(run_id, None) is not None


def is_killed(run_id: Optional[Any]) -> bool:
    """Non-raising check.  True iff the run (or the global flag) is killed."""
    if _global_panic is not None:
        return True
    if run_id is None:
        return False
    with _killed_lock:
        return run_id in _killed_runs


def kill_record(run_id: Optional[Any]) -> Optional[KillRecord]:
    """Return the kill record for *run_id* (or the global one) if killed."""
    if _global_panic is not None and run_id is None:
        return _global_panic
    if run_id is None:
        return None
    with _killed_lock:
        return _killed_runs.get(run_id) or _global_panic


def raise_if_killed(run_id: Optional[Any]) -> None:
    """Cooperative-cancellation check.  Raises :class:`AgentKilledError` if killed.

    Sprinkle this between tool calls in long-running agent orchestrators so
    a manual or auto-panic kill takes effect at the next safe stopping
    point.
    """
    if _global_panic is not None:
        raise AgentKilledError(run_id, _global_panic.reason, _global_panic.severity)
    if run_id is None:
        return
    with _killed_lock:
        rec = _killed_runs.get(run_id)
    if rec is not None:
        raise AgentKilledError(run_id, rec.reason, rec.severity)


def recent_activations(limit: int = 50) -> list[dict]:
    """Return the most-recent kill activations (newest first), capped at *limit*."""
    cap = max(1, min(int(limit), 200))
    with _recent_lock:
        snap = list(_recent)
    return [r.to_dict() for r in reversed(snap)][:cap]


def is_global_panic_active() -> bool:
    """True iff a global panic flag is currently set."""
    return _global_panic is not None


def global_panic_record() -> Optional[KillRecord]:
    """Return the active global-panic :class:`KillRecord`, or ``None``."""
    return _global_panic


# ---------------------------------------------------------------------------
# Integrated guard helper
# ---------------------------------------------------------------------------


def screen_agent_action(
    payload: str,
    *,
    run_id: Optional[Any],
    user_id: Optional[Any] = None,
    agent_id: Optional[str] = None,
    source: str = "agent.tool_call",
    raise_on_critical: bool = True,
    on_kill: Optional[OnKillCallback] = None,
) -> ActionScreenResult:
    """Run the destructive-action guard and trip the kill switch on CRITICAL.

    This is the recommended call point right before any agent-issued tool
    call (SQL execution, shell exec, git push, HTTP DELETE, etc.) actually
    fires.  Treat the return value as advisory for HIGH / MEDIUM signals
    (log, request explicit confirmation); the kill switch will already have
    raised :class:`AgentKilledError` for CRITICAL ones if
    ``raise_on_critical`` is True (the default).

    Args:
        payload: The about-to-execute model output (SQL / shell / tool args).
        run_id: The current agent-run identifier so a kill can target this run.
        user_id: Optional owner identifier for downstream callbacks.
        agent_id: Optional agent identifier (e.g. ``"context_collector"``).
        source: Free-form source label for the audit trail.
        raise_on_critical: Whether to raise :class:`AgentKilledError` after trip.
        on_kill: Per-call ``on_kill`` callback override.  Falls back to the
            default registered with :func:`set_default_on_kill`.
    """
    raise_if_killed(run_id)

    result = screen_action(payload, surface=source)

    if result.severity == ActionSeverity.CRITICAL:
        trip(
            run_id,
            reason=result.explanation,
            severity="critical",
            user_id=user_id,
            agent_id=agent_id,
            surface="agent_action",
            source=source,
            payload_sha256=result.payload_sha256,
            matches=[m.__dict__ for m in result.matches],
            manual=False,
            raise_after_trip=raise_on_critical,
            on_kill=on_kill,
        )
        _cloud_log_agent_guard(
            event_type="agent_kill_switch",
            title="Agent kill switch · TRIPPED",
            level="error",
            outcome="failed",
            reason=result.explanation,
            run_id=run_id,
            user_id=user_id,
            agent_id=agent_id,
            source=source,
            result=result,
        )
    elif result.is_destructive:
        # HIGH / MEDIUM — log loudly so SOC sees it, but do not auto-kill.
        logger.warning(
            "DESTRUCTIVE_ACTION_DETECTED severity=%s run_id=%s user_id=%s "
            "agent_id=%s source=%s rules=%s payload_sha256=%s",
            result.severity.value, run_id, user_id, agent_id, source,
            ",".join(m.rule_id for m in result.matches[:5]),
            result.payload_sha256[:16],
        )
        _cloud_log_agent_guard(
            event_type="destructive_action_guard",
            title=f"Destructive action · {result.severity.value.upper()}",
            level="warn",
            outcome="flagged",
            reason=result.explanation,
            run_id=run_id,
            user_id=user_id,
            agent_id=agent_id,
            source=source,
            result=result,
        )

    return result


def _cloud_log_agent_guard(
    *,
    event_type: str,
    title: str,
    level: str,
    outcome: str,
    reason: str,
    run_id: Optional[Any],
    user_id: Optional[Any],
    agent_id: Optional[str],
    source: str,
    result: ActionScreenResult,
) -> None:
    try:
        import uuid as _uuid

        from artzain.cloud import post_sdk_event

        rid = str(run_id) if run_id is not None else _uuid.uuid4().hex
        preview = (reason or "")[:96]
        if len(reason or "") > 96:
            preview += "…"
        post_sdk_event(
            event_type,
            source="agent_kill_switch" if event_type == "agent_kill_switch" else "pypi_sdk",
            level=level,
            title=title,
            payload={
                "defense_record_version": 1,
                "request_id": rid,
                "outcome": outcome,
                "reason": (reason or "")[:2000],
                "surface": "agent_action",
                "component_source": source,
                "policy": (
                    "Agent-Kill-Switch"
                    if event_type == "agent_kill_switch"
                    else "Destructive-Action-Guard"
                ),
                "input_sha256": result.payload_sha256,
                "preview": preview,
                "run_id": str(run_id) if run_id is not None else None,
                "user_id": user_id,
                "agent_id": agent_id,
                "severity": result.severity.value,
                "rule_ids": [m.rule_id for m in result.matches[:12]],
            },
        )
    except Exception as exc:
        logger.debug("kill_switch cloud mirror skipped: %s", exc)


# ---------------------------------------------------------------------------
# Test hooks
# ---------------------------------------------------------------------------


def _reset_for_tests() -> None:
    """Wipe all in-memory state.  Intended only for the test suite."""
    global _global_panic, _default_on_kill
    with _killed_lock:
        _killed_runs.clear()
    with _global_panic_lock:
        _global_panic = None
        _panic_window.clear()
    with _recent_lock:
        _recent.clear()
    with _default_on_kill_lock:
        _default_on_kill = None


__all__ = [
    "AgentKilledError",
    "KillRecord",
    "OnKillCallback",
    "trip",
    "trip_global",
    "clear_global_panic",
    "clear_run",
    "is_killed",
    "kill_record",
    "raise_if_killed",
    "recent_activations",
    "is_global_panic_active",
    "global_panic_record",
    "screen_agent_action",
    "set_default_on_kill",
]
