"""Tool-call contract inspection (security-sentinel scope; open-items todo #1).

Structured validation of ``payload_kind="tool_call"`` payloads at the decision
boundary — the schema-level complement to the regex screens in
``prompt_injection`` / ``destructive_action_guard``. A tool call must be a
well-formed JSON object (or list of objects) of the shape::

    {"tool": "send_email", "arguments": {"to": "...", "subject": "..."}}

(``name``/``function`` and ``args``/``params``/``parameters`` are accepted
aliases.) Beyond shape, a bundle may pin per-tool contracts in
``guard_config.tool_contracts``::

    "tool_contracts": {
        "send_email": {"required_args": ["to"], "allowed_args": ["to", "subject", "body"]},
        "*": {"deny_unknown_tools": true}
    }

Findings never quote argument *values* (they may carry payload data) — only
tool names and argument key names.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["ContractReport", "inspect_tool_call"]

#: Accepted key aliases for the tool name and the argument object.
_NAME_KEYS = ("tool", "name", "function", "tool_name")
_ARG_KEYS = ("arguments", "args", "params", "parameters", "input")

#: Structural ceilings — a tool call deeper/wider than this is not a tool
#: call, it is a payload smuggled through the tool-call channel.
MAX_CALLS = 20
MAX_ARG_DEPTH = 8
MAX_ARG_KEYS = 200


@dataclass
class ContractReport:
    ok: bool
    severity: str = "none"  # none | medium | high | critical
    findings: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)


def _extract_calls(parsed: Any) -> Optional[List[Dict[str, Any]]]:
    """Normalise the parsed payload to a list of call objects, or None."""
    if isinstance(parsed, dict):
        # OpenAI-style batch: {"tool_calls": [...]}
        if isinstance(parsed.get("tool_calls"), list):
            calls = parsed["tool_calls"]
        else:
            calls = [parsed]
    elif isinstance(parsed, list):
        calls = parsed
    else:
        return None
    return calls if all(isinstance(c, dict) for c in calls) else None


def _tool_name(call: Dict[str, Any]) -> Optional[str]:
    for k in _NAME_KEYS:
        v = call.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        # Nested {"function": {"name": ..., "arguments": ...}} form.
        if k == "function" and isinstance(v, dict):
            n = v.get("name")
            if isinstance(n, str) and n.strip():
                return n.strip()
    return None


def _tool_args(call: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Return (args dict or None, present) — args may legitimately be absent."""
    fn = call.get("function")
    if isinstance(fn, dict):
        call = {**call, **fn}
    for k in _ARG_KEYS:
        if k in call:
            v = call[k]
            # Stringified-JSON arguments are common (OpenAI form) — parse them.
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except (ValueError, TypeError):
                    return None, True
            return (v, True) if isinstance(v, dict) else (None, True)
    return None, False


def _depth(obj: Any, level: int = 1) -> int:
    if isinstance(obj, dict):
        return max([level] + [_depth(v, level + 1) for v in obj.values()]) if obj else level
    if isinstance(obj, list):
        return max([level] + [_depth(v, level + 1) for v in obj]) if obj else level
    return level


def _count_keys(obj: Any) -> int:
    if isinstance(obj, dict):
        return len(obj) + sum(_count_keys(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(_count_keys(v) for v in obj)
    return 0


def inspect_tool_call(
    payload: str,
    contracts: Optional[Dict[str, Any]] = None,
) -> ContractReport:
    """Validate a tool-call payload's structure (and bundle contracts, if any).

    Severity semantics (mapped to verdicts by the enforcer):

    * ``high``   — not parseable as a structured tool call at all, structural
      ceilings exceeded, or a required argument is missing.
    * ``medium`` — unexpected argument keys outside a tool's ``allowed_args``,
      or an unknown tool when the bundle demands known tools only.
    * ``none``   — well-formed (with or without contracts).
    """
    contracts = contracts if isinstance(contracts, dict) else {}
    findings: List[str] = []

    try:
        parsed = json.loads(payload or "")
    except (ValueError, TypeError):
        return ContractReport(
            ok=False, severity="high",
            findings=["tool_call payload is not valid JSON — structured contract required"],
        )

    calls = _extract_calls(parsed)
    if calls is None:
        return ContractReport(
            ok=False, severity="high",
            findings=["tool_call payload is not a call object or list of call objects"],
        )
    if not calls:
        return ContractReport(ok=False, severity="high", findings=["tool_call payload is empty"])
    if len(calls) > MAX_CALLS:
        return ContractReport(
            ok=False, severity="high",
            findings=[f"{len(calls)} calls in one payload exceeds the {MAX_CALLS}-call ceiling"],
        )

    wildcard = contracts.get("*") if isinstance(contracts.get("*"), dict) else {}
    deny_unknown = bool(wildcard.get("deny_unknown_tools"))
    severity = "none"
    tools: List[str] = []

    def _bump(level: str) -> None:
        nonlocal severity
        order = {"none": 0, "medium": 1, "high": 2, "critical": 3}
        if order.get(level, 0) > order.get(severity, 0):
            severity = level

    for i, call in enumerate(calls):
        name = _tool_name(call)
        if not name:
            findings.append(f"call[{i}]: no tool name field ({'/'.join(_NAME_KEYS)})")
            _bump("high")
            continue
        tools.append(name)

        args, present = _tool_args(call)
        if present and args is None:
            findings.append(f"call[{i}] '{name}': arguments are not a JSON object")
            _bump("high")
            continue
        args = args or {}

        if _depth(args) > MAX_ARG_DEPTH:
            findings.append(f"call[{i}] '{name}': argument nesting exceeds depth {MAX_ARG_DEPTH}")
            _bump("high")
        if _count_keys(args) > MAX_ARG_KEYS:
            findings.append(f"call[{i}] '{name}': more than {MAX_ARG_KEYS} argument keys")
            _bump("high")

        contract = contracts.get(name)
        if not isinstance(contract, dict):
            if deny_unknown:
                findings.append(f"call[{i}] '{name}': tool not declared in bundle tool_contracts")
                _bump("medium")
            continue

        required = [str(a) for a in (contract.get("required_args") or [])]
        missing = [a for a in required if a not in args]
        if missing:
            findings.append(f"call[{i}] '{name}': missing required argument(s) {missing}")
            _bump("high")

        allowed = contract.get("allowed_args")
        if isinstance(allowed, list):
            allowed_set = {str(a) for a in allowed} | set(required)
            unexpected = sorted(k for k in args if k not in allowed_set)
            if unexpected:
                findings.append(f"call[{i}] '{name}': unexpected argument(s) {unexpected}")
                _bump("medium")

    return ContractReport(ok=severity == "none", severity=severity, findings=findings, tools=tools)
