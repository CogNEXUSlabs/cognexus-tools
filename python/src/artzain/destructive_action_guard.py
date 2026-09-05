"""Destructive Action Guard — model-output safety net.

Counterpart to :mod:`artzain.prompt_injection` (which screens **input** to the
model) and :mod:`artzain.prompt_defense` (which audits the **system prompt**).

This module screens what the **model produced** — generated SQL, shell
commands, git commands, filesystem operations, HTTP delete calls, code
patches — looking for *catastrophic, irreversible* operations that should
never execute without an explicit, in-conversation user confirmation.

Inspired by the PocketOS / Cursor / Claude incident (Guardian, Apr 2026)
where an AI coding agent ran ``git push --force`` and dropped a production
database in nine seconds despite a system prompt that explicitly forbade
destructive git commands.  Prompt-only safety failed; this is the
deterministic, regex-based safety net that **also** watches outputs.

Design properties:

* **Pure regex, no LLM.** Sub-millisecond per scan, no network, no
  external dependencies.
* **Severity-classified.** Each pattern is tagged ``low / medium / high /
  critical``; ``critical`` matches are intended to *trip the kill switch*
  (see :mod:`artzain.kill_switch`).
* **Fail-closed.** Internal exceptions raise the guard verdict to
  ``critical`` so a buggy regex does not silently allow destruction.

References:
    - OWASP LLM Top 10 (2025) — LLM06 Excessive Agency, LLM02 Insecure Output
    - OWASP Agentic ASI04 — Resource Overload / Destructive Actions
    - Guardian, "Claude-powered AI agent's confession after deleting a firm's
      entire database", 29 Apr 2026.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------


class ActionSeverity(Enum):
    """Severity assigned to a matched destructive-action pattern."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    ActionSeverity.NONE: 0,
    ActionSeverity.LOW: 1,
    ActionSeverity.MEDIUM: 2,
    ActionSeverity.HIGH: 3,
    ActionSeverity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ActionRule:
    """One destructive-action regex with a severity and human-readable name."""

    rule_id: str
    name: str
    severity: ActionSeverity
    pattern: re.Pattern[str]
    owasp: str = "LLM06"


# One character of the *current* SQL statement, for the no-WHERE rules below.
# Consumes anything except a statement terminator (";"), a comment start
# ("--" / "/*"), or a newline that begins another statement. Each character
# matches exactly one alternative, so the lazy repeats built on it cannot
# backtrack combinatorially.
_SQL_STMT_ATOM = (
    r"(?:[^;\-/\n]"
    r"|-(?!-)"
    r"|/(?!\*)"
    r"|\n(?!\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE)\b))"
)

_RULES: tuple[_ActionRule, ...] = (
    # ── SQL: irreversible schema / data destruction ──────────────────────
    _ActionRule(
        rule_id="sql.drop_database",
        name="DROP DATABASE / SCHEMA",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bDROP\s+(?:DATABASE|SCHEMA)\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="sql.drop_table",
        name="DROP TABLE",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bDROP\s+TABLE\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="sql.truncate",
        name="TRUNCATE TABLE",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bTRUNCATE\s+(?:TABLE\s+)?\w+",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        # DELETE / UPDATE without a WHERE clause = mass mutation.
        #
        # The WHERE lookahead is bounded to the *statement* being screened:
        # it stops at ";", at a comment start ("--" or "/*"), and at a line
        # that begins a new statement. An earlier version scanned to the end
        # of the whole payload (`(?![\s\S]*?\bWHERE\b)`), so any later
        # WHERE — a trailing `-- where` comment, or a second harmless
        # `SELECT … WHERE …` — switched the rule off, and the text being
        # screened is model output (open-items §9.2). A WHERE on a
        # continuation line of the same statement still counts.
        rule_id="sql.delete_no_where",
        name="DELETE FROM without WHERE",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bDELETE\s+FROM\s+\w[\w\.\"]*"
            r"(?!" + _SQL_STMT_ATOM + r"*?\bWHERE\b)"
            + _SQL_STMT_ATOM + r"*?(?:;|--|/\*|$)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    _ActionRule(
        rule_id="sql.update_no_where",
        name="UPDATE without WHERE",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bUPDATE\s+\w[\w\.\"]*\s+SET\b"
            r"(?!" + _SQL_STMT_ATOM + r"*?\bWHERE\b)"
            + _SQL_STMT_ATOM + r"*?(?:;|--|/\*|$)",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    _ActionRule(
        rule_id="sql.drop_index",
        name="DROP INDEX / VIEW / TRIGGER",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bDROP\s+(?:INDEX|VIEW|TRIGGER|MATERIALIZED\s+VIEW)\b",
            re.IGNORECASE,
        ),
    ),
    # ── git: destructive history rewrites ────────────────────────────────
    _ActionRule(
        rule_id="git.push_force",
        name="git push --force",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bgit\s+push\b[^\n;|&]*?(?:--force(?!-with-lease)|-f\b)",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.reset_hard",
        name="git reset --hard",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bgit\s+reset\s+(?:[^\n;|&]*\s)?--hard\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.clean_force",
        name="git clean -fd",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bgit\s+clean\b[^\n;|&]*?-[a-z]*f[a-z]*d?",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.branch_delete",
        name="git branch -D / push --delete",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bgit\s+(?:branch\s+-D\b|push\s+[^\n;|&]*?--delete\b)",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.filter_branch",
        name="git filter-branch / filter-repo",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bgit\s+(?:filter-branch|filter-repo)\b",
            re.IGNORECASE,
        ),
    ),
    # ── filesystem: recursive / forced removal ───────────────────────────
    _ActionRule(
        rule_id="fs.rm_rf_root",
        name="rm -rf /",
        severity=ActionSeverity.CRITICAL,
        # The target must be exactly `/`, `~` or `$HOME` (optionally
        # followed by a shell separator), or a bare/root glob `*` / `/*`.
        # A plain prefix match would rate `rm -rf /tmp/build-cache` as a
        # root wipe; that is the generic rule's job (HIGH).
        pattern=re.compile(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"
            r"[a-zA-Z]*\s+(?:--no-preserve-root\s+)?"
            r"(?:(?:/|~/?|\$HOME/?)(?=\s|$|[;&|])|/?\*\s*$)",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.rm_rf_generic",
        name="rm -rf <path>",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.shutil_rmtree",
        name="shutil.rmtree",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bshutil\s*\.\s*rmtree\s*\(",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.no_preserve_root",
        name="--no-preserve-root",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"--no-preserve-root\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.dd_to_disk",
        name="dd of=/dev/sd*",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bdd\b[^\n;|&]*?\bof\s*=\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|xvd[a-z])",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.mkfs",
        name="mkfs.* (reformat)",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bmkfs(?:\.[a-z0-9]+)?\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="fs.fork_bomb",
        name="fork bomb",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        ),
    ),
    _ActionRule(
        rule_id="fs.chmod_recursive_world",
        name="chmod -R 777 (recursive world-writable)",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bchmod\s+-R\s+0?777\b",
            re.IGNORECASE,
        ),
    ),
    # ── package / image / container destruction ──────────────────────────
    _ActionRule(
        rule_id="docker.system_prune_volumes",
        name="docker system prune --volumes",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\bdocker\s+(?:system|volume|image)\s+prune\b[^\n;|&]*?(?:--all|-a|--volumes|-f|--force)",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="kubectl.delete_all",
        name="kubectl delete all/--all",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bkubectl\s+delete\b[^\n;|&]*?(?:\ball\b|--all\b|-A\b)",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="terraform.destroy",
        name="terraform destroy --auto-approve",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bterraform\s+destroy\b[^\n;|&]*?(?:--auto-approve|-auto-approve)",
            re.IGNORECASE,
        ),
    ),
    # ── cloud control plane: delete buckets / projects ───────────────────
    _ActionRule(
        rule_id="aws.s3_rb_force",
        name="aws s3 rb --force",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\baws\s+s3\s+rb\b[^\n;|&]*?--force\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="aws.delete_bucket",
        name="aws s3api delete-bucket / delete-objects",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\baws\s+s3(?:api)?\s+(?:rb|delete-bucket|delete-objects?)\b",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="cloud.project_delete",
        name="gcloud / az project / subscription delete",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\b(?:gcloud\s+projects\s+delete|az\s+(?:account|group)\s+delete)\b",
            re.IGNORECASE,
        ),
    ),
    # ── confessional / 'I-violated' patterns from the article ────────────
    _ActionRule(
        # If the model is *narrating* that it ignored its own rules, that is
        # itself a critical signal — even if the destructive command did not
        # match a pattern above (e.g. obfuscated, novel, or wrapped in a tool
        # call we don't otherwise inspect).  This is the exact language the
        # PocketOS / Claude agent emitted right after wiping the database.
        rule_id="meta.violated_principles",
        name="agent admits it violated safety principles",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            r"\bI\s+(?:just\s+)?(?:violated|ignored|disregarded|broke)\b"
            r"[\s\S]{0,80}?\b(?:every|all|the)\s+(?:principle|rule|safeguard|"
            r"instruction|guideline|safety)\b",
            re.IGNORECASE,
        ),
        owasp="LLM06",
    ),
    _ActionRule(
        rule_id="meta.never_guess_admission",
        name="agent admits it guessed",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            r"\b(?:that[' ]?s\s+exactly\s+what\s+I\s+did|"
            r"I\s+(?:just\s+)?guessed|"
            r"I\s+should\s+not\s+have\s+(?:run|executed|guessed))\b",
            re.IGNORECASE,
        ),
        owasp="LLM06",
    ),
)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ActionMatch:
    """A single matched destructive-action pattern."""

    rule_id: str
    name: str
    severity: ActionSeverity
    owasp: str
    excerpt: str  # short snippet around the match (max 80 chars, redacted of secrets)


@dataclass
class ActionScreenResult:
    """Outcome of screening one model-generated payload."""

    is_destructive: bool
    severity: ActionSeverity
    matches: list[ActionMatch] = field(default_factory=list)
    explanation: str = ""
    payload_sha256: str = ""
    surface: str = "agent_action"

    def is_critical(self) -> bool:
        """True iff at least one match is rated CRITICAL."""
        return self.severity == ActionSeverity.CRITICAL

    def to_dict(self) -> dict[str, object]:
        return {
            "is_destructive": self.is_destructive,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "surface": self.surface,
            "payload_sha256": self.payload_sha256,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "name": m.name,
                    "severity": m.severity.value,
                    "owasp": m.owasp,
                    "excerpt": m.excerpt,
                }
                for m in self.matches
            ],
        }


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


#: Maximum window size we will scan with full regex (defense-in-depth
#: against ReDoS on adversarial inputs).  Inputs above this are still
#: hashed and reported, but only the first and the last slice of this size
#: are regex-scanned, and the truncation itself is reported as a HIGH
#: finding (``input.truncated``) so padding cannot hide an action from a
#: caller that fails on HIGH (open-items §9.81).
MAX_SCAN_BYTES = 256 * 1024

#: Rule id of the synthetic finding added whenever a payload exceeds the
#: scan window.
TRUNCATION_RULE_ID = "input.truncated"


@dataclass
class DestructiveActionGuardConfig:
    """Tunable allow/deny extensions for the guard."""

    #: Disable specific rule_ids (use sparingly — these are critical signals).
    disabled_rule_ids: tuple[str, ...] = ()
    #: Extra (rule_id, severity, regex) entries appended at runtime.
    extra_rules: tuple[tuple[str, ActionSeverity, re.Pattern[str]], ...] = ()


class DestructiveActionGuard:
    """Screen model-generated text for catastrophic / irreversible actions.

    Usage::

        guard = DestructiveActionGuard()
        result = guard.screen(model_output)
        if result.is_critical():
            kill_switch.trip(run_id, reason=result.explanation)
            raise AgentKilledError(result.explanation)
    """

    def __init__(self, config: DestructiveActionGuardConfig | None = None) -> None:
        self._config = config or DestructiveActionGuardConfig()
        self._rules = tuple(
            r for r in _RULES if r.rule_id not in self._config.disabled_rule_ids
        )

    # -- public API ---------------------------------------------------------

    def screen(self, payload: str, *, surface: str = "agent_action") -> ActionScreenResult:
        """Inspect *payload* (model output / generated tool call) for destructive intent.

        Never raises — failures are converted to a CRITICAL verdict so the caller
        always gets a definitive answer.
        """
        if not payload:
            return ActionScreenResult(
                is_destructive=False,
                severity=ActionSeverity.NONE,
                explanation="empty payload",
                payload_sha256="",
                surface=surface,
            )

        try:
            return self._screen_impl(payload, surface=surface)
        except Exception as exc:
            logger.error(
                "destructive_action_guard internal failure — failing closed: %s",
                exc, exc_info=True,
            )
            payload_hash = hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()
            return ActionScreenResult(
                is_destructive=True,
                severity=ActionSeverity.CRITICAL,
                matches=[],
                explanation=f"guard internal error — failing closed: {exc}",
                payload_sha256=payload_hash,
                surface=surface,
            )

    # -- internals ----------------------------------------------------------

    def _screen_impl(self, payload: str, *, surface: str) -> ActionScreenResult:
        encoded = payload.encode("utf-8", "ignore")
        payload_hash = hashlib.sha256(encoded).hexdigest()
        total_bytes = len(encoded)
        truncated = total_bytes > MAX_SCAN_BYTES
        # Head and tail windows. Each rule is searched window by window and
        # reported once, from the first window it hits, so a match that sits
        # in the overlap of the two windows (input under 2 * MAX_SCAN_BYTES)
        # is not double-counted.
        windows = (
            [payload] if not truncated
            else [
                encoded[:MAX_SCAN_BYTES].decode("utf-8", "ignore"),
                encoded[-MAX_SCAN_BYTES:].decode("utf-8", "ignore"),
            ]
        )

        matches: list[ActionMatch] = []

        for rule in self._rules:
            hit = _first_hit(rule.pattern, windows)
            if hit is None:
                continue
            scan_text, m = hit
            matches.append(
                ActionMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=rule.severity,
                    owasp=rule.owasp,
                    excerpt=_excerpt(scan_text, m.start(), m.end()),
                )
            )

        for rule_id, severity, pattern in self._config.extra_rules:
            hit = _first_hit(pattern, windows)
            if hit is None:
                continue
            scan_text, m = hit
            matches.append(
                ActionMatch(
                    rule_id=rule_id,
                    name=rule_id,
                    severity=severity,
                    owasp="custom",
                    excerpt=_excerpt(scan_text, m.start(), m.end()),
                )
            )

        if truncated:
            scanned_bytes = min(total_bytes, 2 * MAX_SCAN_BYTES)
            matches.append(
                ActionMatch(
                    rule_id=TRUNCATION_RULE_ID,
                    name="payload exceeds scan window (truncated)",
                    severity=ActionSeverity.HIGH,
                    owasp="LLM06",
                    excerpt=(
                        f"scanned {scanned_bytes} of {total_bytes} bytes "
                        f"(head + tail windows of {MAX_SCAN_BYTES} bytes each); "
                        "text outside them, or spanning their boundary, was not "
                        "regex-scanned"
                    ),
                )
            )

        if not matches:
            return ActionScreenResult(
                is_destructive=False,
                severity=ActionSeverity.NONE,
                matches=[],
                explanation="no destructive action patterns matched",
                payload_sha256=payload_hash,
                surface=surface,
            )

        worst = max(matches, key=lambda m_: _SEVERITY_ORDER[m_.severity])
        explanation = (
            f"Destructive action detected: {worst.name} "
            f"({worst.severity.value}, rule={worst.rule_id}); "
            f"{len(matches)} pattern(s) matched"
        )
        return ActionScreenResult(
            is_destructive=True,
            severity=worst.severity,
            matches=matches,
            explanation=explanation,
            payload_sha256=payload_hash,
            surface=surface,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_hit(
    pattern: re.Pattern[str], windows: list[str]
) -> tuple[str, re.Match[str]] | None:
    """Return ``(window_text, match)`` for the first window *pattern* hits."""
    for text in windows:
        m = pattern.search(text)
        if m:
            return text, m
    return None


# Group 1 keeps the key name, separator and surrounding whitespace so the
# rewrite works for both ``key=value`` and ``key: value`` forms.
_SECRET_REDACT_RE = re.compile(
    r"((?:api[_-]?key|secret|token|password|bearer)\s*[=:]\s*)\S{8,}",
    re.IGNORECASE,
)


def _excerpt(text: str, start: int, end: int, *, window: int = 32) -> str:
    """Return a short, secret-redacted snippet around the match."""
    s = max(0, start - window)
    e = min(len(text), end + window)
    snippet = text[s:e].replace("\n", " ⏎ ").strip()
    snippet = _SECRET_REDACT_RE.sub(r"\1[REDACTED]", snippet)
    if len(snippet) > 120:
        snippet = snippet[:117] + "…"
    return snippet


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


_default_guard: Optional[DestructiveActionGuard] = None


def _get_guard() -> DestructiveActionGuard:
    global _default_guard
    if _default_guard is None:
        _default_guard = DestructiveActionGuard()
    return _default_guard


def screen_action(payload: str, *, surface: str = "agent_action") -> ActionScreenResult:
    """Module-level helper that uses a shared default guard.

    Lightweight — keep on the hot path.  Equivalent to::

        DestructiveActionGuard().screen(payload, surface=surface)

    but reuses the compiled pattern set across calls.
    """
    return _get_guard().screen(payload, surface=surface)


def reset_guard() -> None:
    """Re-create the module-level guard.  Intended for tests."""
    global _default_guard
    _default_guard = None


def now_iso() -> str:
    """ISO 8601 UTC timestamp helper (re-exported for callers)."""
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "ActionSeverity",
    "ActionMatch",
    "ActionScreenResult",
    "DestructiveActionGuard",
    "DestructiveActionGuardConfig",
    "screen_action",
    "reset_guard",
    "MAX_SCAN_BYTES",
    "TRUNCATION_RULE_ID",
]
