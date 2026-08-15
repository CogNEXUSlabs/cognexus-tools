"""Decision API client — ``artzain.decide(...)`` (FR-2).

A thin, synchronous client over ``POST /api/v1/decisions``. Unlike the
fire-and-forget telemetry in :mod:`artzain.cloud`, the caller needs the
verdict back, so this blocks for the round-trip.

**Offline mode:** when no API key is configured, ``decide()`` runs the same
three guards locally (prompt-injection, destructive-action, policy-enforcement)
and synthesises the same response shape with ``audit_block_id=None`` and
``offline=True`` — so ``pip install artzain`` yields a first allowed decision
with zero server setup.

Uses only the standard library (``urllib``) — no new dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional

from artzain.cloud import (
    _api_request_headers,
    _effective_base,
    _effective_key,
)

_log = logging.getLogger("artzain.decide")

_VALID_KINDS = (
    "user_input",
    "external_content",
    "tabular",
    "model_output",
    "tool_call",
)

_VERDICT_RANK = {"allow": 0, "review": 1, "deny": 2}


class DecisionError(RuntimeError):
    """Raised when the Decision API returns a non-2xx response or is unreachable.

    Callers should treat this as fail-closed (do **not** silently proceed with
    the gated action) unless they have an explicit fallback policy.
    """

    def __init__(self, message: str, *, status: Optional[int] = None) -> None:
        self.status = status
        super().__init__(message)


def decide(
    *,
    action: str,
    target: str,
    payload: str,
    kind: str = "user_input",
    agent_did: str = "artzain-sdk",
    surface: str = "sdk",
    request_id: Optional[str] = None,
    product: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
    timeout_sec: float = 10.0,
) -> dict[str, Any]:
    """Gate a proposed agent action and return the decision.

    Args:
        action: Verb being attempted, e.g. ``"send_email"`` / ``"execute_sql"``.
        target: Target identifier, e.g. ``"crm:contact:123"`` / ``"db:prod"``.
        payload: The text / tool-call being gated.
        kind: One of ``user_input``, ``external_content``, ``tabular``,
            ``model_output``, ``tool_call``.
        agent_did: Caller's agent identity (DID or stable name).
        surface: Where the request came from.
        request_id: Optional idempotency / correlation key.
        product: FR-11 product identifier (``"name"`` or ``"name@version"``).
            Validated at the server boundary against negotiated product
            schemas — unknown products/versions are rejected with a 422.
        context: Advisory context (recorded with the decision).
        timeout_sec: HTTP timeout for the online path.

    Returns:
        A dict with ``outcome`` (``allow`` / ``deny`` / ``review``),
        ``decision_id``, ``audit_block_id`` (``None`` offline),
        ``contributing_agents``, ``reasons``, and (offline) ``offline=True``.

    Raises:
        ValueError: If *kind* is not a valid payload kind.
        DecisionError: If the online call fails (non-2xx or transport error).
    """
    if kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}, got {kind!r}")

    if not _effective_key():
        return _decide_offline(
            action=action,
            target=target,
            payload=payload,
            kind=kind,
            agent_did=agent_did,
            request_id=request_id,
        )

    body = {
        "agent_did": agent_did,
        "action": action,
        "target": target,
        "payload": payload,
        "payload_kind": kind,
        "surface": surface,
        "request_id": request_id,
        "product": product,
        "context": context or {},
    }
    url = _effective_base() + "/api/v1/decisions"
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = _api_request_headers(_effective_key())
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            parsed = json.loads(exc.read().decode("utf-8", errors="replace") or "{}")
            detail = str(parsed.get("detail") or "")
        except Exception:
            pass
        raise DecisionError(
            f"decision API returned HTTP {exc.code}{': ' + detail if detail else ''}",
            status=exc.code,
        ) from exc
    except Exception as exc:
        raise DecisionError(f"decision API unreachable: {exc}") from exc


# ---------------------------------------------------------------------------
# Offline evaluation (mirrors the server resolution policy D5)
# ---------------------------------------------------------------------------

_SEVERITY_VERDICT = {
    "critical": "deny",
    "high": "review",
    "medium": "allow",
    "low": "allow",
    "none": "allow",
}

_OUTPUT_KINDS = {"model_output", "tool_call"}
_INJECTION_PRESET = {
    "user_input": "balanced",
    "external_content": "strict",
    "model_output": "strict",
    "tabular": "permissive",
    "tool_call": "balanced",
}


def _decide_offline(
    *,
    action: str,
    target: str,
    payload: str,
    kind: str,
    agent_did: str,
    request_id: Optional[str],
) -> dict[str, Any]:
    _warn_offline_once()
    votes: list[dict[str, Any]] = []
    votes.append(_offline_injection_vote(payload, kind, agent_did))
    votes.append(_offline_destructive_vote(payload, kind, surface="sdk"))
    votes.append(_offline_policy_vote(payload))

    outcome = "allow"
    for v in votes:
        if v.get("error"):
            outcome = "deny"
            break
        if _VERDICT_RANK.get(v["verdict"], 0) > _VERDICT_RANK.get(outcome, 0):
            outcome = v["verdict"]

    reasons: list[str] = []
    if outcome != "allow":
        for v in votes:
            if v["verdict"] == "allow" and not v.get("error"):
                continue
            head = v["findings"][0] if v.get("findings") else v["severity"]
            reasons.append(f"{v['name']} ({v['severity']}): {head}")

    return {
        "outcome": outcome,
        "decision_id": (request_id or uuid.uuid4().hex),
        "audit_block_id": None,
        "contributing_agents": votes,
        "policy_bundle_version": "builtin:v0",
        "resolution_policy": "builtin/strict-v0",
        "latency_ms": 0,
        "reasons": reasons,
        "offline": True,
    }


_offline_warned = False


def _warn_offline_once() -> None:
    """R2: one line per process — decision was not sealed; point at login."""
    global _offline_warned
    if _offline_warned:
        return
    _offline_warned = True
    if (os.environ.get("COGNEXUS_QUIET") or "").strip() in ("1", "true", "yes", "on"):
        return
    try:
        if not sys.stderr.isatty():
            return
    except Exception:
        return
    print(
        "artzain: decision was not sealed (offline). "
        "Run `artzain login` (~15s) to mint a key and seal decisions.",
        file=sys.stderr,
    )


def _reset_offline_warn_for_tests() -> None:
    global _offline_warned
    _offline_warned = False


def _offline_injection_vote(payload: str, kind: str, agent_did: str) -> dict[str, Any]:
    from artzain.prompt_injection import (
        DetectionConfig,
        PromptInjectionDetector,
        ThreatLevel,
    )

    sensitivity = _INJECTION_PRESET.get(kind, "balanced")
    detector = PromptInjectionDetector(config=DetectionConfig(sensitivity=sensitivity))
    result = detector.detect(payload, source=agent_did)
    if not result.is_injection:
        return _vote("prompt-injection", "allow", "none", score=round(float(result.confidence), 3))
    severity = result.threat_level.value
    if result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
        verdict = "deny"
    elif result.threat_level == ThreatLevel.MEDIUM:
        verdict = "review"
    else:
        verdict = "allow"
    return _vote(
        "prompt-injection",
        verdict,
        severity,
        score=round(float(result.confidence), 3),
        findings=list(result.matched_patterns[:8]),
    )


def _offline_destructive_vote(payload: str, kind: str, *, surface: str) -> dict[str, Any]:
    if kind not in _OUTPUT_KINDS:
        return _vote("destructive-action", "allow", "none", findings=[f"skipped (payload_kind={kind})"])
    from artzain.destructive_action_guard import screen_action

    result = screen_action(payload, surface=surface)
    severity = result.severity.value if result.is_destructive else "none"
    verdict = _SEVERITY_VERDICT.get(severity, "allow")
    findings = [f"{m.rule_id}: {m.excerpt}" for m in result.matches[:8]]
    return _vote("destructive-action", verdict, severity, findings=findings)


def _offline_policy_vote(payload: str) -> dict[str, Any]:
    from artzain.policy_enforcement import (
        PolicyEnforcementEvaluator,
        builtin_conduct_rules,
    )

    evaluator = PolicyEnforcementEvaluator()
    # Offline has no tenant rules; the always-on conduct rules still apply.
    report = evaluator.evaluate(payload, builtin_conduct_rules())
    if not report.has_violations:
        return _vote("policy-enforcement", "allow", "none")
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    worst = "low"
    for f in report.findings:
        if rank.get(f.severity, 1) > rank.get(worst, 1):
            worst = f.severity
    if evaluator.should_block(report):
        verdict = "deny"
    elif worst in ("high", "critical"):
        verdict = "review"
    else:
        verdict = "allow"
    findings = [f"{f.rule_id}: {f.rule_title}" for f in report.findings[:8]]
    return _vote("policy-enforcement", verdict, worst, findings=findings)


def _vote(
    name: str,
    verdict: str,
    severity: str,
    *,
    score: Optional[float] = None,
    findings: Optional[list[str]] = None,
    error: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "verdict": verdict,
        "severity": severity,
        "score": score,
        "findings": findings or [],
        "error": error,
    }


__all__ = ["DecisionError", "decide"]
