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

The second half of the module lets the regex screens read a tool call the way
its tool does (:func:`screen_tool_call_action`,
:func:`detect_tool_call_injection`). JSON escaping changes the text a regex
sees: ``json.dumps`` writes a newline inside an argument as the two characters
``\\n``, so ``DROP\\nDATABASE`` has no whitespace between its words, and
``ensure_ascii`` writes Cyrillic, CJK and emoji as runs of ``\\uXXXX``, which
read as escape-sequence smuggling. The tool decodes the JSON and sees neither.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from json.decoder import scanstring
from typing import TYPE_CHECKING, Any, Collection, Deque, Dict, Iterator, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from artzain.destructive_action_guard import ActionScreenResult
    from artzain.prompt_injection import DetectionResult, PromptInjectionDetector

__all__ = [
    "ContractReport",
    "DecodedStrings",
    "MAX_NESTED_JSON",
    "MAX_SCREENED_STRINGS",
    "NESTED_TOO_DEEP_RULE_ID",
    "TOO_MANY_STRINGS_RULE_ID",
    "decode_strings",
    "detect_tool_call_injection",
    "inspect_tool_call",
    "screen_tool_call_action",
    "unescape_non_ascii",
]

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
                except (ValueError, TypeError, RecursionError):
                    return None, True
            return (v, True) if isinstance(v, dict) else (None, True)
    return None, False


def _children(obj: Any) -> List[Any]:
    if isinstance(obj, dict):
        return list(obj.values())
    if isinstance(obj, list):
        return obj
    return []


def _depth(obj: Any, limit: int = MAX_ARG_DEPTH) -> int:
    """Nesting depth of ``obj`` (a scalar is 1), capped at ``limit + 1``.

    Iterative — a hostile payload nested tens of thousands deep must produce a
    finding, not a ``RecursionError``. Anything past ``limit`` is reported as
    ``limit + 1``; callers only compare against the ceiling.
    """
    deepest = 1
    stack: List[Tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, level = stack.pop()
        if level > deepest:
            deepest = level
        if level > limit:
            return level
        stack.extend((child, level + 1) for child in _children(node))
    return deepest


def _count_keys(obj: Any) -> int:
    """Total dict keys at every nesting level of ``obj`` (iterative)."""
    total = 0
    stack: List[Any] = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            total += len(node)
        stack.extend(_children(node))
    return total


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

    Never raises on payload shape: a payload nested deep enough to exhaust
    the interpreter stack (``RecursionError`` from the JSON decoder or any
    later step) is a structural-ceiling breach and fails closed as ``high``.
    """
    try:
        return _inspect(payload, contracts)
    except RecursionError:
        return ContractReport(
            ok=False, severity="high",
            findings=["tool_call payload nesting exhausts the parser — structural ceiling exceeded"],
        )


def _inspect(payload: str, contracts: Optional[Dict[str, Any]]) -> ContractReport:
    contracts = contracts if isinstance(contracts, dict) else {}
    findings: List[str] = []

    try:
        parsed = json.loads(payload or "")
    except (ValueError, TypeError, RecursionError):
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


# ---------------------------------------------------------------------------
# Reading a tool call the way its tool does
# ---------------------------------------------------------------------------
#
# Each screen reads a tool call more than one way and takes the worst result.
#
# * The destructive-action screen reads the payload as sent, where a match can
#   span two arguments, so what it caught there it still catches. It also reads
#   each decoded string on its own: a command ends where its string ends
#   (``rm -rf /`` is followed by a quote in the serialized text), and one
#   argument's WHERE says nothing about another argument's DELETE. And it reads
#   each array of strings joined with spaces, the way an argv list runs
#   (``["rm", "-rf", "/"]``). A command a tool assembles from separate fields
#   (a ``cmd`` beside its ``args``) is not reassembled.
# * The injection screen reads the payload with ``ensure_ascii``'s escapes of
#   visible characters written out, in place of the payload as sent, so an
#   escaped greeting is judged by its characters rather than as a run of
#   escapes. It also reads the decoded strings as one text: no injection
#   pattern can be switched off by a neighbouring string (a detector allowlist
#   entry anywhere in the text still clears all of it, as for any text).
#
# The decoded strings are every JSON string in the call, keys and values from
# any shape, and the strings inside a string that is itself JSON (OpenAI's
# stringified ``arguments``, a JSON request body).

#: Most distinct decoded strings the destructive-action screen reads one at a
#: time. Past this the rest are read as one text, which still catches what
#: they carry, and the call draws a ``high`` finding: padding a call with
#: filler strings cannot buy an ``allow``, or unbounded work.
MAX_SCREENED_STRINGS = 1024

#: Levels of JSON inside strings that are decoded; a stringified ``arguments``
#: is one level. JSON found inside strings any deeper is screened as text and
#: draws a ``high`` finding.
MAX_NESTED_JSON = 3

#: Rule ids of the findings the two ceilings above add to the destructive vote.
TOO_MANY_STRINGS_RULE_ID = "input.too_many_strings"
NESTED_TOO_DEEP_RULE_ID = "input.nested_too_deep"

#: Separator between strings read as one text. The ``;`` ends a SQL statement
#: and a shell command and the newlines end a line, so no rule runs from one
#: string into the next through whitespace, and a statement-bounded lookahead
#: (DELETE without WHERE) stops at the string's end.
_JOIN = "\n;\n"

_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

#: Opens like a JSON object, array or string, after any whitespace or BOM.
_JSON_OPENING_RE = re.compile(r"[\s\ufeff]*[\[{\"]")

# One backslash escape, consumed left to right so an escaped backslash is never
# read as the start of another escape. A surrogate pair is tried first.
_ESCAPE_RE = re.compile(
    r"\\(?:u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})"
    r"|u([0-9a-fA-F]{4})"
    r"|[\s\S])"
)

#: Unicode categories whose escapes stay as written: format characters
#: (zero-width, bidi controls, tags) and C1 controls.
_KEEP_ESCAPED = ("Cf", "Cc")

#: Default-ignorable code points outside those categories, whose escapes also
#: stay as written: variation selectors (which can carry hidden bytes on an
#: emoji), Hangul fillers, the combining grapheme joiner and the rest of the
#: Unicode Default_Ignorable_Code_Point set. Like format characters they render
#: as nothing, so an escaped run of them is still read as smuggling.
_DEFAULT_IGNORABLE_RE = re.compile(
    r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    r"\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8"
    r"\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]"
)


@dataclass
class DecodedStrings:
    strings: List[str]
    too_deep: bool = False
    #: Each JSON array of two or more strings, joined with spaces: the command an
    #: argv list runs. Only the destructive-action screen reads these.
    commands: List[str] = field(default_factory=list)


_UNPARSED = object()


def _clean(value: str) -> str:
    """Lone surrogates become U+FFFD, since the screens hash what they read."""
    return _SURROGATE_RE.sub("\ufffd", value)


def _literals(text: str) -> Iterator[str]:
    """Each JSON string literal in *text*, decoded, left to right.

    In JSON a ``"`` outside a string always opens one, so reading literal by
    literal recovers every string without parsing the structure around it:
    nesting depth, duplicate keys and trailing text do not matter. Stops at the
    first literal that does not decode (never closed, or a bad escape), since
    nothing after it can be told apart from string content.
    """
    pos = 0
    while True:
        start = text.find('"', pos)
        if start < 0:
            return
        try:
            value, pos = scanstring(text, start + 1, False)
        except ValueError:
            return
        yield value


def _looks_like_json(value: str) -> bool:
    """Opens like a JSON object, array or string, and has a string to read."""
    return '"' in value and _JSON_OPENING_RE.match(value) is not None


class _Members(tuple):
    """Every ``(key, value)`` pair of a parsed JSON object, repeated keys included."""


def _parse_json(value: str) -> Any:
    """What a strict JSON parser makes of *value*, or ``_UNPARSED``.

    Objects come back as :class:`_Members` rather than dicts, so a key given
    twice keeps both values: a tool whose parser keeps the first one runs it.
    """
    try:
        return json.loads(value, object_pairs_hook=_Members)
    except (ValueError, RecursionError):
        return _UNPARSED


def _string_lists(parsed: Any) -> Iterator[List[str]]:
    """Every array of two or more strings inside a parsed JSON value."""
    stack: List[Any] = [parsed]
    while stack:
        node = stack.pop()
        if isinstance(node, _Members):
            stack.extend(member for _, member in node)
        elif isinstance(node, list):
            if len(node) > 1 and all(isinstance(item, str) for item in node):
                yield node
            else:
                stack.extend(node)


def decode_strings(payload: str) -> DecodedStrings:
    """The distinct JSON strings in *payload*, decoded, that the screens read.

    Keys and values alike, whatever the call's shape: a CrewAI ``kwargs``
    object or an envelope's message list is text a tool acts on as much as an
    ``arguments`` object is. A decoded string that looks like JSON is read
    again for its own strings, down to :data:`MAX_NESTED_JSON` levels. When a
    strict parser accepts it, its strings stand in for it, since they are all
    the tool that parses it receives; otherwise, and past the last level, it
    is kept as text as well. Every array of strings in what a strict parser
    reads is also joined into :attr:`DecodedStrings.commands`. Lone surrogates
    become U+FFFD, since the screens hash what they read.
    """
    seen: Set[str] = set()
    strings: List[str] = []
    commands: Dict[str, None] = {}
    too_deep = False

    def read_commands(parsed: Any) -> None:
        if parsed is not _UNPARSED:
            for items in _string_lists(parsed):
                commands.setdefault(_clean(" ".join(items)), None)

    read_commands(_parse_json(payload or ""))
    layers: Deque[Tuple[str, int]] = deque([(payload or "", 0)])
    while layers:
        text, level = layers.popleft()
        for value in _literals(text):
            value = _clean(value)
            if not value or value in seen:
                continue
            seen.add(value)
            if _looks_like_json(value):
                if level < MAX_NESTED_JSON:
                    layers.append((value, level + 1))
                    parsed = _parse_json(value)
                    if parsed is not _UNPARSED:
                        read_commands(parsed)
                        continue
                else:
                    too_deep = True
            strings.append(value)
    screened = set(strings)
    return DecodedStrings(strings, too_deep, [c for c in commands if c not in screened])


def _kept_if_invisible(char: str, escape: str) -> str:
    if unicodedata.category(char) in _KEEP_ESCAPED or _DEFAULT_IGNORABLE_RE.match(char):
        return escape
    return char


def _write_out(match: "re.Match[str]") -> str:
    high, low, code = match.groups()
    if high:
        pair = chr(0x10000 + ((int(high, 16) - 0xD800) << 10) + (int(low, 16) - 0xDC00))
        return _kept_if_invisible(pair, match.group(0))
    if code:
        point = int(code, 16)
        if point >= 0x80 and not 0xD800 <= point <= 0xDFFF:
            return _kept_if_invisible(chr(point), match.group(0))
    return match.group(0)


def unescape_non_ascii(text: str) -> str:
    """*text* with JSON's ``\\uXXXX`` escapes of visible non-ASCII characters written out.

    This undoes what ``ensure_ascii`` does to visible text, and nothing else.
    ASCII escapes (``\\u0041``, which ``json.dumps`` never writes), ``\\n``,
    ``\\"`` and an escaped backslash stay as written. So do escapes of
    invisible characters (format characters such as zero-width spaces, bidi
    controls and tags, and the other default-ignorable code points such as
    variation selectors), C1 controls and lone surrogates: a run of any of
    those still reads as an encoding attack. A lone surrogate character that
    is not escaped becomes U+FFFD.
    """
    text = text or ""
    if "\\u" in text:
        text = _ESCAPE_RE.sub(_write_out, text)
    return _clean(text)


def screen_tool_call_action(
    payload: str,
    *,
    surface: str = "agent_action",
    disabled_rule_ids: Collection[str] = (),
) -> "ActionScreenResult":
    """Destructive-action screen of a ``tool_call`` payload, as sent and decoded.

    The payload as sent, then each distinct decoded string and each argv-style
    array of strings joined with spaces, one at a time (the first
    :data:`MAX_SCREENED_STRINGS`), then any past that as one text. The results
    are combined by
    :func:`~artzain.destructive_action_guard.combine_screens`.
    """
    from artzain.destructive_action_guard import (
        ActionMatch,
        ActionScreenResult,
        ActionSeverity,
        combine_screens,
        screen_action,
    )

    decoded = decode_strings(payload)
    texts = decoded.strings + decoded.commands
    results = [screen_action(payload, surface=surface)]
    results.extend(screen_action(s, surface=surface) for s in texts[:MAX_SCREENED_STRINGS])
    ceilings: List[ActionMatch] = []
    rest = texts[MAX_SCREENED_STRINGS:]
    if rest:
        results.append(screen_action(_JOIN.join(rest), surface=surface))
        ceilings.append(ActionMatch(
            rule_id=TOO_MANY_STRINGS_RULE_ID,
            name="tool call carries more strings than are screened one at a time",
            severity=ActionSeverity.HIGH,
            owasp="LLM06",
            excerpt=(
                f"{len(texts)} distinct strings and string lists; the first "
                f"{MAX_SCREENED_STRINGS} were screened one at a time and the rest together"
            ),
        ))
    if decoded.too_deep:
        ceilings.append(ActionMatch(
            rule_id=NESTED_TOO_DEEP_RULE_ID,
            name="JSON nested in strings past the decode limit",
            severity=ActionSeverity.HIGH,
            owasp="LLM06",
            excerpt=(
                f"JSON nested in strings more than {MAX_NESTED_JSON} levels deep "
                "was screened as text, not decoded"
            ),
        ))
    if ceilings:
        results.append(ActionScreenResult(
            is_destructive=True, severity=ActionSeverity.HIGH, matches=ceilings, surface=surface,
        ))
    return combine_screens(results, disabled_rule_ids=disabled_rule_ids)


_THREAT_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def detect_tool_call_injection(
    detector: "PromptInjectionDetector",
    payload: str,
    *,
    source: str = "unknown",
) -> "DetectionResult":
    """Prompt-injection screen of a ``tool_call`` payload, as sent and decoded.

    *detector* reads the payload with escapes of visible non-ASCII characters
    written out (:func:`unescape_non_ascii`), then the decoded strings as one
    text, where a string kept as JSON text has them written out too. The worst
    threat wins; matched patterns are merged, the worst reading's first.
    """
    from artzain.prompt_injection import DetectionResult

    results = [detector.detect(unescape_non_ascii(payload), source=source)]
    strings = decode_strings(payload).strings
    if strings:
        text = _JOIN.join(unescape_non_ascii(s) if _looks_like_json(s) else s for s in strings)
        results.append(detector.detect(text, source=source))
    hits = [r for r in results if r.is_injection]
    if not hits:
        return results[0]
    worst = max(hits, key=lambda r: _THREAT_RANK.get(r.threat_level.value, 0))
    return DetectionResult(
        is_injection=True,
        threat_level=worst.threat_level,
        injection_type=worst.injection_type,
        confidence=max(r.confidence for r in hits),
        matched_patterns=list(dict.fromkeys(p for r in (worst, *hits) for p in r.matched_patterns)),
        explanation=worst.explanation,
    )
