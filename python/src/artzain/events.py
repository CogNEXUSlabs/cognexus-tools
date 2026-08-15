"""Structured audit trail for prompt-injection / prompt-defense signals.

Writes **JSONL** (one JSON object per line) to disk for compliance and forensic
review.  Optionally mirrors rows into an external store (e.g. a database) via
a pluggable ``on_event`` callback so the record can appear in dashboards or
monitoring pipelines.

No raw user text is stored — only a short redacted preview and a SHA-256 hash
(privacy-by-design: logging without leakage).

Quick-start::

    from artzain.events import record_prompt_defense_event

    # Minimal — just writes to JSONL
    record_prompt_defense_event(
        kind="prompt_injection",
        surface="chat",
        source="user",
        result=detection_result,
        enforcement_action="logged",
    )

    # With a custom sink (e.g. database insert)
    def my_sink(record: dict) -> None:
        db.execute("INSERT INTO events ...", record)

    record_prompt_defense_event(..., on_event=my_sink)

Environment variables
---------------------
``COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR``
    Directory for the JSONL file. Falls back to ``REPORTS_DIR``, then ``/tmp``.
``COGNEXUS_PROMPT_DEFENSE_JSONL_PASSES``
    When ``0`` / ``false``, clean scans are not appended to JSONL (detections
    are always written). Default: include passes in JSONL.
``COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES``
    When ``1`` / ``true``, clean scans are POSTed via :func:`artzain.cloud.post_sdk_event`.
    When ``0`` / ``false``, only detections are POSTed. Default: POST passes when
    ``COGNEXUS_API_KEY`` (or ``MYAPP_API_KEY``) is set; otherwise off.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from artzain.audit_chain import get_chain
from artzain.prompt_injection import DetectionResult

_log = logging.getLogger("artzain.events")


def _events_path() -> Path:
    base = (
        os.environ.get("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR")
        or os.environ.get("REPORTS_DIR")
        or "/tmp"
    )
    root = Path(base)
    root.mkdir(parents=True, exist_ok=True)
    return root / "prompt_defense_events.jsonl"


def _redact_preview(text: str, max_len: int = 96) -> str:
    one_line = " ".join((text or "").split())[:max_len]
    return one_line + ("\u2026" if len((text or "")) > max_len else "")


def _env_falsey(name: str, *, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return not default
    return raw in ("0", "false", "no", "off")


def _jsonl_include_passes() -> bool:
    return not _env_falsey("COGNEXUS_PROMPT_DEFENSE_JSONL_PASSES", default=True)


def _cloud_include_passes() -> bool:
    raw = (os.environ.get("COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    try:
        from artzain.cloud import has_api_key

        return has_api_key()
    except Exception:
        return False


def record_prompt_defense_event(
    *,
    kind: str,
    surface: str,
    source: str,
    result: DetectionResult,
    enforcement_action: str,
    user_id: Optional[Any] = None,
    text: str = "",
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
    latency_ms: Optional[float] = None,
    model_id: Optional[str] = None,
    request_id: Optional[str] = None,
    policy: Optional[str] = None,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
) -> None:
    """Append one audit record to JSONL and optionally call *on_event*.

    *enforcement_action* is ``"blocked"``, ``"logged"`` (flagged but allowed),
    or ``"allowed"`` (clean scan).

    Args:
        kind: Logical category, e.g. ``"prompt_injection"``.
        surface: Input surface, e.g. ``"user_input"``, ``"external_content"``.
        source: Component identifier that submitted the input.
        result: The :class:`~artzain.prompt_injection.DetectionResult`.
        enforcement_action: Policy outcome applied by the caller.
        user_id: Optional identifier for the end user (any JSON-serialisable
            value). Stored in the JSONL record; useful for filtering.
        text: The original input text. Only a redacted preview and SHA-256
            hash are stored — the raw text is **never** written to disk.
        on_event: Optional callback receiving the full record dict.
        latency_ms: Detector wall time in milliseconds, if measured.
        model_id: Optional model or deployment label (not the raw prompt).
        request_id: Optional correlation id (defaults to a new UUID hex).
        policy: Human-readable defence layer label; derived when omitted.
        tokens_in: Optional input/prompt token count for this decision. Forwarded
            to the cloud event so it appears on the dashboard Leaderboard and
            Token-to-Outcome analytics.
        tokens_out: Optional output/completion token count for this decision.
    """
    is_clean = not result.is_injection
    if is_clean and not _jsonl_include_passes() and on_event is None:
        if not _cloud_include_passes():
            return

    rid = (request_id or uuid.uuid4().hex).lower()
    payload_hash = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
    lat = None if latency_ms is None else max(0.0, float(latency_ms))

    if is_clean:
        outcome = "passed"
        action = "allowed"
        threat = "none"
        injection_type = None
        patterns: list[str] = []
        confidence = 0.0
    else:
        action = enforcement_action
        outcome = "blocked" if enforcement_action == "blocked" else "flagged"
        threat = result.threat_level.value
        injection_type = result.injection_type.value if result.injection_type else None
        patterns = (result.matched_patterns or [])[:12]
        confidence = float(result.confidence)

    pol = policy or f"OWASP-LLM01-Runtime-{surface}"

    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "request_id": rid,
        "kind": kind,
        "surface": surface,
        "source": source,
        "action": action,
        "outcome": outcome,
        "user_id": user_id,
        "threat": threat,
        "injection_type": injection_type,
        "confidence": confidence,
        "patterns": patterns,
        "input_sha256": payload_hash,
        "preview": _redact_preview(text),
        "user_prompt": _redact_preview(text),
        "latency_ms": lat,
        "model_id": model_id,
        "policy": pol,
    }

    write_jsonl = (not is_clean) or _jsonl_include_passes()
    if write_jsonl:
        get_chain(_events_path()).append(record)

    if is_clean:
        _log.debug(
            "PROMPT_DEFENSE_PASS surface=%s source=%s user=%s latency_ms=%s hash=%s\u2026",
            surface,
            source,
            user_id if user_id is not None else "\u2014",
            lat,
            payload_hash[:16],
        )
    else:
        _log.warning(
            "PROMPT_DEFENSE_EVENT kind=%s surface=%s source=%s action=%s outcome=%s threat=%s "
            "type=%s user=%s hash=%s\u2026",
            kind,
            surface,
            source,
            action,
            outcome,
            threat,
            injection_type,
            user_id if user_id is not None else "\u2014",
            payload_hash[:16],
        )

    if on_event is not None:
        try:
            on_event(record)
        except Exception as exc:
            _log.debug("events: on_event callback raised: %s", exc)

    if is_clean and not _cloud_include_passes():
        return

    try:
        from artzain.cloud import post_sdk_event

        if outcome == "passed":
            level = "success"
            title = "Prompt defense · CLEARED"
        elif outcome == "blocked":
            level = "error"
            title = "Prompt defense · BLOCKED"
        else:
            level = "warn"
            title = "Prompt defense · FLAGGED"

        reason = (result.explanation or "").strip()
        if is_clean and not reason:
            reason = "No injection patterns detected"
        elif not is_clean and not reason:
            reason = (
                f"{threat} threat"
                + (f" · {injection_type}" if injection_type else "")
                + (f" · {action}" if action else "")
            )

        post_sdk_event(
            "prompt_defense",
            source="prompt_defense",
            level=level,
            title=title,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            payload={
                "defense_record_version": 1,
                "request_id": rid,
                "outcome": outcome,
                "reason": reason[:2000],
                "surface": surface,
                "component_source": source,
                "policy": pol,
                "latency_ms": lat,
                "model_id": model_id,
                "input_sha256": payload_hash,
                "preview": record.get("preview"),
                "user_prompt": record.get("preview"),
                "kind": kind,
                "action": action,
                "threat": threat,
                "injection_type": injection_type,
                "confidence": confidence,
                "patterns": patterns,
                "pattern_count": len(patterns),
                "user_id": user_id,
            },
        )
    except Exception as exc:
        _log.debug("events: cloud mirror skipped: %s", exc)


def read_recent_events(
    *,
    user_id: Any = None,
    limit: int = 50,
    events_dir: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Return recent JSONL rows (newest first).

    Args:
        user_id: When provided, only rows whose ``user_id`` field matches are
            returned. Pass ``None`` to return rows regardless of user.
        limit: Maximum number of rows to return (capped at 200).
        events_dir: Override the directory to read from. Defaults to the value
            resolved by the ``COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR`` / ``REPORTS_DIR``
            environment variables.

    Returns:
        A list of dicts, newest first.
    """
    cap = max(1, min(int(limit), 200))

    if events_dir is not None:
        path = Path(events_dir) / "prompt_defense_events.jsonl"
    else:
        path = _events_path()

    if not path.is_file():
        return []

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return []

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    out: list[dict[str, Any]] = []
    for ln in reversed(lines):
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if user_id is not None and obj.get("user_id") != user_id:
            continue
        out.append(obj)
        if len(out) >= cap:
            break
    return out


def record_policy_enforcement_event(
    *,
    surface: str,
    source: str,
    report: Any,
    enforcement_action: str,
    user_id: Optional[Any] = None,
    text: str = "",
    on_event: Optional[Callable[[dict[str, Any]], None]] = None,
    latency_ms: Optional[float] = None,
    model_id: Optional[str] = None,
    request_id: Optional[str] = None,
    rules_checked: int = 0,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
) -> None:
    """Append a client-policy enforcement audit row (JSONL + optional cloud).

    Mirrors :func:`record_prompt_defense_event` but for
    :class:`~artzain.policy_enforcement.PolicyEnforcementReport` findings.

    ``tokens_in`` / ``tokens_out`` attribute token spend for this decision to the
    dashboard Leaderboard and Token-to-Outcome analytics.
    """
    from artzain.policy_enforcement import PolicyEnforcementReport

    if not isinstance(report, PolicyEnforcementReport):
        raise TypeError("report must be a PolicyEnforcementReport")

    is_clean = not report.has_violations
    if is_clean and not _jsonl_include_passes() and on_event is None:
        if not _cloud_include_passes():
            return

    rid = (request_id or uuid.uuid4().hex).lower()
    payload_hash = hashlib.sha256((text or "").encode("utf-8")).hexdigest()
    lat = None if latency_ms is None else max(0.0, float(latency_ms))

    findings = report.findings[:12]
    rule_ids = [f.rule_id for f in findings]
    severities = [f.severity for f in findings]

    if is_clean:
        outcome = "passed"
        action = "allowed"
    else:
        action = enforcement_action
        outcome = "blocked" if enforcement_action == "blocked" else "flagged"

    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "request_id": rid,
        "kind": "policy_enforcement",
        "surface": surface,
        "source": source,
        "action": action,
        "outcome": outcome,
        "user_id": user_id,
        "violation_count": report.violation_count,
        "rule_ids": rule_ids,
        "severities": severities,
        "rules_checked": rules_checked or report.rules_checked,
        "input_sha256": payload_hash,
        "preview": _redact_preview(text),
        "user_prompt": _redact_preview(text),
        "latency_ms": lat,
        "model_id": model_id,
        "policy": "ClientPolicy-DocumentDerived",
    }

    write_jsonl = (not is_clean) or _jsonl_include_passes()
    if write_jsonl:
        get_chain(_events_path()).append(record)

    if on_event is not None:
        try:
            on_event(record)
        except Exception as exc:
            _log.debug("events: on_event callback raised: %s", exc)

    if is_clean and not _cloud_include_passes():
        return

    try:
        from artzain.cloud import post_sdk_event

        if outcome == "passed":
            level, title = "success", "Policy enforcement · CLEARED"
        elif outcome == "blocked":
            level, title = "error", "Policy enforcement · BLOCKED"
        else:
            level, title = "warn", "Policy enforcement · FLAGGED"

        reason = (
            "No client policy violations detected"
            if is_clean
            else "; ".join(f"{f.rule_title} ({f.severity})" for f in findings[:4])
        )

        post_sdk_event(
            "policy_enforcement",
            source="policy_enforcement",
            level=level,
            title=title,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            payload={
                "defense_record_version": 1,
                "request_id": rid,
                "outcome": outcome,
                "reason": reason[:2000],
                "surface": surface,
                "component_source": source,
                "policy": record["policy"],
                "latency_ms": lat,
                "model_id": model_id,
                "input_sha256": payload_hash,
                "preview": record.get("preview"),
                "user_prompt": record.get("preview"),
                "action": action,
                "violation_count": report.violation_count,
                "rule_ids": rule_ids,
                "rules_checked": record["rules_checked"],
                "user_id": user_id,
            },
        )
    except Exception as exc:
        _log.debug("events: policy cloud mirror skipped: %s", exc)


__all__ = [
    "record_prompt_defense_event",
    "record_policy_enforcement_event",
    "read_recent_events",
]
