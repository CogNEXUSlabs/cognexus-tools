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
:func:`detect_tool_call_injection`, :func:`decoded_texts`,
:func:`evaluate_tool_call_policy`). JSON escaping changes the text a regex sees:
``json.dumps`` writes a newline inside an argument as the two characters
``\\n``, so ``DROP\\nDATABASE`` has no whitespace between its words, and
``ensure_ascii`` writes Cyrillic, CJK and emoji as runs of ``\\uXXXX``, which
read as escape-sequence smuggling. The tool decodes the JSON and sees neither.
A ``model_output`` payload that is JSON reaches its reader through a JSON parser
too, so the destructive-action, injection, policy, PII and special-category
screens read it the same way (:func:`reads_decoded`). :func:`evaluate_tool_call_policy`
still applies only to a ``tool_call``: it sets conduct client context from the
call's values and tool name, which a reply does not have.

A tool call also names its values: an argument's name is the label that PII
detectors look for in prose, as in ``dob: 1990-01-01``. :func:`member_text`
writes each object member as such a line for :func:`scan_tool_call_pii`. A
name is not a message, though: :func:`conduct_client_context` tells the
conduct rules whether a call names a client in its values.
"""

from __future__ import annotations

import json
import re
import threading
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from json.decoder import scanstring
from typing import TYPE_CHECKING, Any, Collection, Deque, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from artzain.prompt_injection import RGI_EMOJI_TAG_SEQUENCE_RE

if TYPE_CHECKING:
    from artzain.destructive_action_guard import ActionScreenResult
    from artzain.policy_enforcement import (
        ClientPolicyRule,
        PolicyEnforcementEvaluator,
        PolicyEnforcementFinding,
        PolicyEnforcementReport,
    )
    from artzain.prompt_injection import DetectionResult, PromptInjectionDetector

__all__ = [
    "ContractReport",
    "DecodedStrings",
    "MAX_NESTED_JSON",
    "MAX_SCREENED_STRINGS",
    "NESTED_TOO_DEEP_RULE_ID",
    "TOO_MANY_STRINGS_RULE_ID",
    "combine_policy_reports",
    "conduct_client_context",
    "decode_strings",
    "decoded_texts",
    "detect_tool_call_injection",
    "evaluate_tool_call_policy",
    "inspect_tool_call",
    "tool_call_policy_readings",
    "tool_call_policy_texts",
    "member_text",
    "reads_decoded",
    "scan_tool_call_pii",
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
#   each argv-style array (two or more strings) as the command it runs, its
#   tokens joined with spaces the way an argv list runs (``["rm", "-rf", "/"]``),
#   a stray number coerced in place. A command a tool assembles from separate
#   fields (a ``cmd`` beside its ``args``) is not reassembled.
# * The injection screen reads the payload with ``ensure_ascii``'s escapes of
#   visible characters written out, in place of the payload as sent, so an
#   escaped greeting is judged by its characters rather than as a run of
#   escapes. It also reads the decoded strings as one text: no injection
#   pattern can be switched off by a neighbouring string (a detector allowlist
#   entry anywhere in the text still clears all of it, as for any text).
# * The policy screen (tenant rules and the conduct rules), and on the engine
#   the PII and special-category screens, read the payload as sent, so what
#   they caught there they still catch, and each of :func:`decoded_texts`: the
#   call with its string escapes written out where they sit, once for the
#   call's own strings and once more for each level of JSON inside strings,
#   each text judged on its own. Writing escapes out in place keeps the rest as
#   sent (keys, order, repeated strings, numbers), except that a line break
#   takes the place of the comma or bracket after each string, so a pattern
#   that stops at a line break does not run from one string value into the
#   next; a key still runs into its value, and a number into the string after
#   it, as in the call as sent. A tool may decode a string that looks like JSON
#   (a stringified ``arguments``) or use it as text (an email body that opens
#   with a bracket), and each level decoded shortens the text, so each text is
#   judged with the approval markers it holds: a marker that decoding a deeper
#   level brings near a match does not suppress the match where it already
#   shows one level up. A repeated key is also read as each parser keeps it
#   (:func:`_views_a_parser_keeps`): ``json.loads`` keeps the last value and some
#   parsers keep the first, and a marker in a value that parser drops is blanked,
#   so it cannot approve the value that parser delivers. A marker in a
#   neighbouring argument is in every reading, at the same distance. On a
#   reading that is still JSON, that distance counts each string escape as the
#   character it stands for: a hex digit of an escape is not a letter of a
#   marker, and ``ensure_ascii``'s six-character escapes do not stretch the
#   window. The conduct rules find profanity, insults and client words in each
#   text, keys included, and a text's client words count only
#   when :func:`conduct_client_context` does not rule them out: a call whose
#   only client words are its names names no client.
#
# The decoded strings are every JSON string in the call, keys and values from
# any shape, and the strings inside a string that is itself JSON (OpenAI's
# stringified ``arguments``, a JSON request body).
#
# A ``model_output`` payload that is JSON is read the same way by the
# destructive-action and injection screens (:func:`reads_decoded`): a client
# that parses a reply acts on its strings.

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

#: Destructive-action rules not read in a command reconstructed from an argv
#: array whose first element is the word ``truncate`` (see
#: :func:`screen_tool_call_action`).
_NOT_READ_IN_TRUNCATE_COMMANDS = ("sql.truncate",)

#: Opens like a JSON object, array or string, after any whitespace or BOM.
_JSON_OPENING_RE = re.compile(r"[\s\ufeff]*[\[{\"]")

# One backslash escape, consumed left to right so an escaped backslash is never
# read as the start of another escape. A black flag followed by escaped tag
# characters is tried first, then a surrogate pair.
_ESCAPE_RE = re.compile(
    r"\\(?:(u[dD]83[cC]\\u[dD][fF][fF]4(?:\\u[dD][bB]40\\u[dD][cC][0-7][0-9a-fA-F])+)"
    r"|u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})"
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
    #: Each argv-style array (two or more strings) reconstructed as the command
    #: it runs — its tokens joined with spaces, a stray scalar coerced in place.
    #: Only the destructive-action screen reads these.
    commands: List[str] = field(default_factory=list)


_UNPARSED = object()


#: JSON's one-character backslash escapes (RFC 8259).
_SIMPLE_ESCAPES = {
    '"': '"',
    '\\': '\\',
    '/': '/',
    'b': '\b',
    'f': '\f',
    'n': '\n',
    'r': '\r',
    't': '\t',
}
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

#: A JSON string's body as a lenient reader finds its end: everything up to the
#: first quote no backslash escapes. Shared with :func:`reads_decoded`.
_STRING_BODY_RE = re.compile(r'[^"\\]*(?:\\[\s\S][^"\\]*)*')


def _cut_short(text: str, pos: int) -> bool:
    """Whether ``text[pos:]`` is nothing, or the start of a ``\\uXXXX`` escape cut short."""
    rest = text[pos:pos + 6]
    if len(rest) == 6:
        return False
    if not rest:
        return True
    return rest[0] == "\\" and (
        len(rest) == 1 or (rest[1] == "u" and all(c in _HEXDIGITS for c in rest[2:]))
    )


def _decode_literal(body: str, *, incomplete_at_end: bool) -> str:
    """*body* with valid JSON escapes decoded and invalid ones kept as written.

    When *incomplete_at_end* is true, *body* runs to the end of the text (the
    literal was never closed). An incomplete escape there — a lone backslash,
    or ``\\u`` with fewer than four hex digits — is dropped, and so is a high
    surrogate whose low half the end cut off. A complete bad escape, in a
    closed literal or in this prefix, stays as written: a backslash and a
    character that is not an escape, or ``\\u`` and characters that are not
    four hex digits.
    """
    parts: List[str] = []
    i = 0
    n = len(body)
    while i < n:
        slash = body.find("\\", i)
        if slash < 0:
            parts.append(body[i:])
            break
        if slash > i:
            parts.append(body[i:slash])
        if slash + 1 >= n:
            if not incomplete_at_end:
                parts.append("\\")
            break
        esc = body[slash + 1]
        if esc == "u":
            digits = body[slash + 2:slash + 6]
            if len(digits) < 4 or any(c not in _HEXDIGITS for c in digits):
                if (
                    incomplete_at_end
                    and len(digits) < 4
                    and all(c in _HEXDIGITS for c in digits)
                ):
                    break
                if len(digits) < 4:
                    parts.append(body[slash:])
                    break
                parts.append(body[slash:slash + 6])
                i = slash + 6
                continue
            code = int(digits, 16)
            i = slash + 6
            if 0xD800 <= code <= 0xDBFF:
                if incomplete_at_end and _cut_short(body, i):
                    # The end cut off the low half: drop the high half with it.
                    break
                low_digits = body[i + 2:i + 6]
                if (
                    body[i:i + 2] == "\\u"
                    and len(low_digits) == 4
                    and all(c in _HEXDIGITS for c in low_digits)
                ):
                    low = int(low_digits, 16)
                    if 0xDC00 <= low <= 0xDFFF:
                        code = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00))
                        i += 6
            parts.append(chr(code))
            continue
        mapped = _SIMPLE_ESCAPES.get(esc)
        if mapped is None:
            parts.append(body[slash:slash + 2])
            i = slash + 2
            continue
        parts.append(mapped)
        i = slash + 2
    return "".join(parts)


def _read_literal(text: str, body: int) -> Tuple[str, int, bool]:
    """The JSON string whose body starts at *body*, where to resume, and whether it closed.

    The literal ends at the first quote no backslash escapes. A closed literal
    is decoded from that slice alone: :func:`json.decoder.scanstring` on the
    whole of *text* builds a :class:`json.JSONDecodeError`, which counts lines
    from position 0, so one rejected literal per call is quadratic. Valid
    escapes are decoded; a complete bad escape is kept as written. A literal
    that never closes yields its decoded prefix, and an incomplete escape at
    the end of *text* is dropped.
    """
    end = _STRING_BODY_RE.match(text, body).end()
    if end < len(text) and text[end] == '"':
        try:
            value, _ = scanstring(text[body - 1:end + 1], 1, False)
        except ValueError:
            value = _decode_literal(text[body:end], incomplete_at_end=False)
        return value, end + 1, True
    return _decode_literal(text[body:], incomplete_at_end=True), len(text), False


def _literals(text: str) -> Iterator[str]:
    """Each JSON string literal in *text*, decoded, left to right.

    In JSON a ``"`` outside a string always opens one, so reading literal by
    literal recovers every string without parsing the structure around it:
    nesting depth, duplicate keys and trailing text do not matter. A literal
    ends at the first quote no backslash escapes, where a lenient reader ends
    it. A strict decoder's bad escape stays as written, and the literals after
    it are still read. A literal that is never closed at the end of *text* (a
    payload cut inside a string) yields its decoded prefix; an incomplete
    trailing escape (a lone backslash, or ``\\u`` with fewer than four hex
    digits) is dropped.
    """
    pos = 0
    while True:
        start = text.find('"', pos)
        if start < 0:
            return
        value, pos, _closed = _read_literal(text, start + 1)
        yield value


def _looks_like_json(value: str) -> bool:
    """Opens like a JSON object, array or string, and has a string to read."""
    return '"' in value and _JSON_OPENING_RE.match(value) is not None


class _Members(tuple):
    """Every ``(key, value)`` pair of a parsed JSON object, repeated keys included."""


def _plain_json(value: str) -> Any:
    try:
        return json.loads(value)
    except (ValueError, RecursionError):
        return _UNPARSED


def _plain_json_fresh_stack(value: str) -> Any:
    """Plain parse on a new thread, whose stack the caller has not already used."""
    box: List[Any] = [_UNPARSED]

    def run() -> None:
        box[0] = _plain_json(value)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    return box[0]


def _parse_json(value: str) -> Any:
    """What a strict JSON parser makes of *value*, or ``_UNPARSED``.

    Objects come back as :class:`_Members` rather than dicts, so a key given
    twice keeps both values: a tool whose parser keeps the first one runs it.
    If that hooked parse cannot take the value, a plain parse is tried so
    argv-style arrays are still reconstructed; a repeated key then keeps only
    its last value. The plain parse is tried on this thread first, then on a
    new thread if this one is already out of stack.
    """
    try:
        return json.loads(value, object_pairs_hook=_Members)
    except RecursionError:
        parsed = _plain_json(value)
        return parsed if parsed is not _UNPARSED else _plain_json_fresh_stack(value)
    except ValueError:
        return _UNPARSED


def _coerce_token(item: Any) -> Optional[str]:
    """One argv element as the text a tool puts on the command line, or None.

    A JSON string is itself. A scalar — a number, ``true``/``false``, ``null`` —
    is ``str()``-ed the way a tool that builds a command line from the array
    would stringify it, so an operand typed as a number does not drop the
    command out of screening. A nested list or object is not a token: it returns
    None and is walked for arrays of its own instead (see :func:`_argv_commands`).
    """
    if isinstance(item, str):
        return item
    if item is None or isinstance(item, (int, float)):  # bool is an int subclass
        return str(item)
    return None


def _argv_commands(parsed: Any) -> Iterator[str]:
    """Every argv-style array inside *parsed*, reconstructed as the command it runs.

    An array is reconstructed when it holds at least two strings — an ``argv``
    list (``["rm", "-rf", "/"]``), or a command a tool assembles from strings and
    a stray number. Its elements are joined with a single space, the way an argv
    list runs; a scalar (number, bool, null) is ``str()``-coerced in place, so a
    non-string operand no longer makes the whole array skip screening, and a
    nested list or object is not a token — it is left out of the command but
    walked for arrays of its own.

    The join is always a space. An element that itself holds whitespace is a
    multi-word *argument value* (``["git", "push", "--force", "origin main"]``),
    not a separator between two commands, and the tool runs the array as one
    command line; joining on anything but a space would split that one command
    across the boundary and switch off every rule that reads across words
    (``git push … --force``). Two strings is the floor because a destructive
    command needs at least two tokens (``rm`` and ``-rf``), while a table row of
    one label and a number (``["cpu", 91]``) is not a command and must not be
    reconstructed. A command that lives in a single element is screened on its
    own as a decoded string; this only reassembles one split across elements.
    """
    stack: List[Any] = [parsed]
    while stack:
        node = stack.pop()
        if isinstance(node, _Members):
            stack.extend(member for _, member in node)
            continue
        if isinstance(node, dict):
            stack.extend(node.values())
            continue
        if not isinstance(node, list):
            continue
        tokens = [_coerce_token(item) for item in node]
        # A nested list/object is not a token; walk it for arrays of its own.
        stack.extend(item for item, token in zip(node, tokens, strict=True) if token is None)
        if sum(isinstance(item, str) for item in node) < 2:
            continue
        yield " ".join(token for token in tokens if token is not None)


def decode_strings(payload: str) -> DecodedStrings:
    """The distinct JSON strings in *payload*, decoded, that the screens read.

    Keys and values alike, whatever the call's shape: a CrewAI ``kwargs``
    object or an envelope's message list is text a tool acts on as much as an
    ``arguments`` object is. A decoded string that looks like JSON is read
    again for its own strings, down to :data:`MAX_NESTED_JSON` levels. When a
    strict parser accepts it, its strings stand in for it, since they are all
    the tool that parses it receives; otherwise, and past the last level, it
    is kept as text as well. Every argv-style array in what a strict parser
    reads is reconstructed into :attr:`DecodedStrings.commands`. A lone
    surrogate stays as decoded: the screens refuse text that holds one, since
    the tool may drop or replace it.
    """
    seen: Set[str] = set()
    strings: List[str] = []
    commands: Dict[str, None] = {}
    too_deep = False

    def read_commands(parsed: Any) -> None:
        if parsed is not _UNPARSED:
            for command in _argv_commands(parsed):
                commands.setdefault(command, None)

    read_commands(_parse_json(payload or ""))
    layers: Deque[Tuple[str, int]] = deque([(payload or "", 0)])
    while layers:
        text, level = layers.popleft()
        for value in _literals(text):
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


#: What may follow a JSON string: optional JSON whitespace, then ``,``, ``}`` or ``]``.
_AFTER_STRING_RE = re.compile(r"[ \t\n\r]*[,}\]]")


def decoded_texts(payload: str) -> List[str]:
    """*payload* with its JSON string escapes written out in place, once per decoding depth.

    The first text writes out the escapes in the call's own strings, keys and
    values; each next one also writes out, inside every string that looks like
    JSON, the escapes of the strings one level deeper, down to
    :data:`MAX_NESTED_JSON` levels, whether or not a strict parser accepts it.
    Each string keeps its quotes and its place. Between strings the text stays
    as sent, except that the ``,``, ``}`` or ``]`` right after a string becomes
    a line break, so a pattern that stops at a line break does not run from one
    string value into the next once escapes are written out; a key still runs
    into its value, and a number into the string after it. A payload without a
    backslash has nothing to write out and gets no text, and a text the same as
    the one before it is left out. Decoding only shortens text: no text is
    longer than *payload*, and two positions are never further apart in a text
    than in the one before it. A string a strict decoder rejects is still
    written out — valid escapes decoded, invalid ones as written — and the
    strings after it are too. A string that never closes stops the reading,
    and the rest of that text stays as it is. A lone surrogate stays as
    decoded, for the screens to refuse.
    """
    payload = payload or ""
    if "\\" not in payload:
        return []
    texts: List[str] = []
    for depth in range(1, MAX_NESTED_JSON + 2):
        text = _write_out_strings(payload, 0, depth)
        if not texts or text != texts[-1]:
            texts.append(text)
    return texts


def _write_out_strings(text: str, level: int, depth: int) -> str:
    """*text* with the strings at *level* decoded, and deeper ones while ``level + 1 < depth``.

    The ``,``, ``}`` or ``]`` right after each string becomes a line break.
    A closed string a strict decoder rejects is written out with invalid
    escapes kept as written, and the strings after it are too. A string that
    never closes stops the walk.
    """
    parts: List[str] = []
    pos = 0
    while True:
        start = text.find('"', pos)
        if start < 0:
            break
        value, end, closed = _read_literal(text, start + 1)
        if not closed:
            break
        if level + 1 < depth and _looks_like_json(value):
            value = _write_out_strings(value, level + 1, depth)
        parts.append(text[pos:start + 1])
        parts.append(value)
        parts.append('"')
        pos = end
        after = _AFTER_STRING_RE.match(text, pos)
        if after:
            parts.append(text[pos:after.end() - 1])
            parts.append("\n")
            pos = after.end()
    parts.append(text[pos:])
    return "".join(parts)


def _kept_if_invisible(char: str, escape: str) -> str:
    if unicodedata.category(char) in _KEEP_ESCAPED or _DEFAULT_IGNORABLE_RE.match(char):
        return escape
    return char


def _write_out(match: "re.Match[str]") -> str:
    flag, high, low, code = match.groups()
    if flag:
        # The England, Scotland and Wales flags, which the injection screen
        # leaves alone, are written out whole; other tag characters keep their
        # escapes. Every character here was one surrogate pair, 12 characters.
        decoded = json.loads('"' + match.group(0) + '"')
        rgi = RGI_EMOJI_TAG_SEQUENCE_RE.match(decoded)
        written = rgi.group() if rgi else decoded[0]
        return written + match.group(0)[12 * len(written):]
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
    those still reads as an encoding attack. The exception is the tag
    characters of the England, Scotland and Wales flag emoji, which are
    written out with their flag. A lone surrogate character that is not
    escaped stays too, for the screens to refuse.
    """
    text = text or ""
    if "\\u" in text:
        text = _ESCAPE_RE.sub(_write_out, text)
    return text


def screen_tool_call_action(
    payload: str,
    *,
    surface: str = "agent_action",
    disabled_rule_ids: Collection[str] = (),
) -> "ActionScreenResult":
    """Destructive-action screen of a payload :func:`reads_decoded` names, as sent and decoded.

    The payload as sent, then each distinct decoded string and each argv-style
    array reconstructed as the command it runs, one at a time (the first
    :data:`MAX_SCREENED_STRINGS`), then any past that as one text. The results
    are combined by
    :func:`~artzain.destructive_action_guard.combine_screens`. A command
    reconstructed from an array that begins with the word ``truncate`` is not
    read for the rules in :data:`_NOT_READ_IN_TRUNCATE_COMMANDS`: it is a list
    of words (`["truncate", "wrap"]`, `["TRUNCATE", "ERROR"]`) or the coreutils
    command. A TRUNCATE statement passed in an array sits in one element,
    which is read on its own, or follows the client that runs it (`["db2",
    "truncate", "table", "t"]`).
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
    results.extend(screen_action(s, surface=surface) for s in decoded.strings[:MAX_SCREENED_STRINGS])
    results.extend(
        combine_screens(
            [screen_action(c, surface=surface)],
            disabled_rule_ids=_NOT_READ_IN_TRUNCATE_COMMANDS if c.split(" ", 1)[0].lower() == "truncate" else (),
        )
        for c in decoded.commands[:max(0, MAX_SCREENED_STRINGS - len(decoded.strings))]
    )
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
    """Prompt-injection screen of a payload :func:`reads_decoded` names, as sent and decoded.

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


def _rule_key(finding: "PolicyEnforcementFinding") -> Tuple[str, str, str, str, str]:
    """What tells one rule's finding from another's: rule ids need not be unique."""
    return (finding.rule_id, finding.rule_title, finding.category, finding.severity, finding.summary)


def combine_policy_reports(reports: Sequence["PolicyEnforcementReport"]) -> "PolicyEnforcementReport":
    """One policy report for several readings of one payload, the payload as sent first.

    Every finding of the first reading is kept, and a later reading adds each
    finding whose rule no earlier reading reported. Rules are told apart by id,
    title, category, severity and summary, since a bundle can give two rules the
    same id. A rule that one reading suppresses and another reports is a
    finding: a pattern any reading reports as a finding is not also recorded as
    suppressed, and a suppression several readings make is recorded once. The
    report carries the first reading's hash and rule count; a single report
    comes back as it is.
    """
    from artzain.policy_enforcement import PolicyEnforcementReport

    first, *rest = reports
    if not rest:
        return first
    findings = list(first.findings)
    reported = {_rule_key(f) for f in findings}
    for finding in (f for report in rest for f in report.findings):
        if _rule_key(finding) not in reported:
            reported.add(_rule_key(finding))
            findings.append(finding)

    found = {(_rule_key(f), f.matched_pattern) for report in reports for f in report.findings}
    suppressed: List["PolicyEnforcementFinding"] = []
    recorded: Set[Tuple[Tuple[str, str, str, str, str], str]] = set()
    for entry in (s for report in reports for s in report.suppressed):
        key = (_rule_key(entry), entry.matched_pattern)
        if key not in found and key not in recorded:
            recorded.add(key)
            suppressed.append(entry)

    return PolicyEnforcementReport(
        violation_count=len(findings),
        findings=findings,
        rules_checked=first.rules_checked,
        text_hash=first.text_hash,
        suppressed=suppressed,
    )


_NUMBER_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i] in " \t\n\r":
        i += 1
    return i


def _raw_map(text: str, start: int, end: int) -> List[int]:
    """Raw index of each decoded character of ``text[start:end]``, plus *end*.

    *start* is the first character inside a JSON string and *end* the index of
    its closing quote. The result has one entry more than the decoded string,
    so a span ``[a, b)`` in that string is ``[raw[a], raw[b])`` in *text*.
    """
    raw_of: List[int] = []
    i = start
    while i < end:
        raw_of.append(i)
        if text[i] != "\\":
            i += 1
            continue
        if i + 1 >= end:
            raise ValueError
        esc = text[i + 1]
        if esc == "u":
            if i + 6 > end or any(c not in _HEXDIGITS for c in text[i + 2:i + 6]):
                raise ValueError
            code = int(text[i + 2:i + 6], 16)
            i += 6
            if 0xD800 <= code <= 0xDBFF and text.startswith("\\u", i) and i + 6 <= end:
                low_digits = text[i + 2:i + 6]
                if all(c in _HEXDIGITS for c in low_digits):
                    low = int(low_digits, 16)
                    if 0xDC00 <= low <= 0xDFFF:
                        i += 6
            continue
        if esc not in _SIMPLE_ESCAPES:
            raise ValueError
        i += 2
    if i != end:
        raise ValueError
    raw_of.append(end)
    return raw_of


def _parse_string(
    text: str,
    i: int,
    level: int,
    last_spans: List[Tuple[int, int]],
    first_spans: List[Tuple[int, int]],
) -> int:
    """The index after the string at *i*, recording dropped values nested inside it."""
    decoded, end = scanstring(text, i + 1, True)
    if level >= MAX_NESTED_JSON or not _looks_like_json(decoded):
        return end
    nested_last: List[Tuple[int, int]] = []
    nested_first: List[Tuple[int, int]] = []
    try:
        pos = _parse_json_value(decoded, 0, level + 1, nested_last, nested_first)
    except (ValueError, RecursionError):
        return end
    if decoded[pos:].strip() or not (nested_last or nested_first):
        return end
    try:
        raw_of = _raw_map(text, i + 1, end - 1)
    except ValueError:
        return end
    if len(raw_of) != len(decoded) + 1:
        return end
    limit = len(decoded)
    for spans, nested in ((last_spans, nested_last), (first_spans, nested_first)):
        for start, stop in nested:
            if 0 <= start <= stop <= limit:
                spans.append((raw_of[start], raw_of[stop]))
    return end


def _parse_json_value(
    text: str,
    i: int,
    level: int,
    last_spans: List[Tuple[int, int]],
    first_spans: List[Tuple[int, int]],
) -> int:
    """The index after the JSON value at *i*. Repeated keys add the spans a parser drops.

    *last_spans* collects every value but a key's last; *first_spans* every
    value but its first. Nested JSON strings are read the same way, and their
    spans are translated back into *text*.
    """
    i = _skip_ws(text, i)
    if i >= len(text):
        raise ValueError
    ch = text[i]
    if ch == '"':
        return _parse_string(text, i, level, last_spans, first_spans)
    if ch == "{":
        return _parse_object(text, i, level, last_spans, first_spans)
    if ch == "[":
        return _parse_array(text, i, level, last_spans, first_spans)
    if ch == "t":
        return _literal(text, i, "true")
    if ch == "f":
        return _literal(text, i, "false")
    if ch == "n":
        return _literal(text, i, "null")
    if text.startswith("NaN", i):
        return i + 3
    if text.startswith("Infinity", i):
        return i + 8
    if text.startswith("-Infinity", i):
        return i + 9
    matched = _NUMBER_RE.match(text, i)
    if matched is None or matched.end() == i:
        raise ValueError
    return matched.end()


def _literal(text: str, i: int, word: str) -> int:
    if not text.startswith(word, i):
        raise ValueError
    return i + len(word)


def _parse_array(
    text: str,
    i: int,
    level: int,
    last_spans: List[Tuple[int, int]],
    first_spans: List[Tuple[int, int]],
) -> int:
    i = _skip_ws(text, i + 1)
    if i < len(text) and text[i] == "]":
        return i + 1
    while True:
        i = _parse_json_value(text, i, level, last_spans, first_spans)
        i = _skip_ws(text, i)
        if i >= len(text):
            raise ValueError
        if text[i] == "]":
            return i + 1
        if text[i] != ",":
            raise ValueError
        i += 1


def _parse_object(
    text: str,
    i: int,
    level: int,
    last_spans: List[Tuple[int, int]],
    first_spans: List[Tuple[int, int]],
) -> int:
    i = _skip_ws(text, i + 1)
    members: List[Tuple[str, int, int]] = []
    if i < len(text) and text[i] == "}":
        return i + 1
    while True:
        i = _skip_ws(text, i)
        if i >= len(text) or text[i] != '"':
            raise ValueError
        key, key_end = scanstring(text, i + 1, True)
        i = _skip_ws(text, key_end)
        if i >= len(text) or text[i] != ":":
            raise ValueError
        value_start = _skip_ws(text, i + 1)
        value_end = _parse_json_value(text, value_start, level, last_spans, first_spans)
        members.append((key, value_start, value_end))
        i = _skip_ws(text, value_end)
        if i >= len(text):
            raise ValueError
        if text[i] == "}":
            break
        if text[i] != ",":
            raise ValueError
        i += 1
    grouped: Dict[str, List[Tuple[int, int]]] = {}
    for key, start, end in members:
        grouped.setdefault(key, []).append((start, end))
    for group in grouped.values():
        if len(group) < 2:
            continue
        last_spans.extend(group[:-1])
        first_spans.extend(group[1:])
    return i + 1


def _blank_spans(text: str, spans: List[Tuple[int, int]]) -> str:
    """*text* with each span replaced by the same number of spaces.

    The characters around a span stay at the same indexes, so a marker in a
    neighbouring value stays as near a match as it was, and one on the far
    side of a long dropped value stays far.
    """
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(spans):
        if start < 0 or end <= start or start >= len(text):
            continue
        end = min(end, len(text))
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    if not merged:
        return text
    parts: List[str] = []
    prev = 0
    for start, end in merged:
        parts.append(text[prev:start])
        parts.append(" " * (end - start))
        prev = end
    parts.append(text[prev:])
    return "".join(parts)


def _views_a_parser_keeps(payload: str) -> Tuple[Tuple[str, bool], ...]:
    """Readings of *payload* with the values one parser drops replaced by spaces.

    Two readings, when a key is given twice anywhere a strict parser reads,
    including inside a string that is itself JSON (stringified ``arguments``),
    down to :data:`MAX_NESTED_JSON` levels. The first keeps each key's last
    value, as ``json.loads`` does; the second keeps its first, as a first-wins
    parser does. Each dropped value becomes spaces of the same length, and
    each reading is also given with its escapes written out
    (:func:`decoded_texts`), so a match that appears only once newlines are
    written out is judged without the marker the parser did not deliver. Each
    pair is ``(text, json_string_escapes)``: true for the blanked JSON, false
    once its escapes are written out. No readings when nothing repeats or the
    payload does not parse: a parser that rejects it drops nothing. Never raises.
    """
    payload = payload or ""
    if not payload:
        return ()
    last_spans: List[Tuple[int, int]] = []
    first_spans: List[Tuple[int, int]] = []
    try:
        end = _parse_json_value(payload, 0, 0, last_spans, first_spans)
        if payload[end:].strip():
            raise ValueError
    except (ValueError, RecursionError, IndexError):
        return ()
    if not last_spans and not first_spans:
        return ()
    seen = {payload, *decoded_texts(payload)}
    views: List[Tuple[str, bool]] = []

    def add(text: str, escapes: bool) -> None:
        if text not in seen:
            seen.add(text)
            views.append((text, escapes))

    for spans in (last_spans, first_spans):
        if not spans:
            continue
        view = _blank_spans(payload, spans)
        # Still JSON, so the approval window measures escapes the way it does
        # on the call as sent. The decoded copy below has already written them out.
        add(view, True)
        for text in decoded_texts(view):
            add(text, False)
    return tuple(views)


def tool_call_policy_readings(payload: str) -> List[Tuple[str, bool]]:
    """``(text, json_string_escapes)`` pairs the policy screen reads, payload first.

    The payload as sent, then each of :func:`decoded_texts`, then each reading
    from :func:`_views_a_parser_keeps`. The boolean is the evaluator's
    ``json_string_escapes``: true for a text that is still JSON, so a hex digit
    of an escape is not a letter of a marker, and false once escapes are
    written out. An approval marker counts only in the text it is in;
    :func:`combine_policy_reports` keeps a match any one of them reports.
    """
    payload = payload or ""
    readings = [(payload, True)]
    seen = {payload}
    for text in decoded_texts(payload):
        if text not in seen:
            seen.add(text)
            readings.append((text, False))
    for text, escapes in _views_a_parser_keeps(payload):
        if text not in seen:
            seen.add(text)
            readings.append((text, escapes))
    return readings


def tool_call_policy_texts(payload: str) -> List[str]:
    """The texts of :func:`tool_call_policy_readings`, without the escape flags."""
    return [text for text, _escapes in tool_call_policy_readings(payload)]


def evaluate_tool_call_policy(
    evaluator: "PolicyEnforcementEvaluator",
    payload: str,
    rules: "Sequence[ClientPolicyRule]",
) -> "PolicyEnforcementReport":
    """Policy screen of a ``tool_call`` payload: as sent, then each of :func:`decoded_texts`.

    *evaluator* reads each text on its own, so an approval marker counts only in
    the text it is in, and :func:`combine_policy_reports` folds the reports into
    one. Readings from :func:`_views_a_parser_keeps` are included, so a marker
    in a repeated key's dropped value does not approve the value a parser
    keeps. A text that is still JSON is read with ``json_string_escapes``, so
    the approval window counts an escape as the character it stands for. In
    every text the conduct rules count client words only when
    :func:`conduct_client_context` does not rule them out; *evaluator*'s
    ``evaluate`` receives that as its ``client_context`` keyword.
    """
    context = conduct_client_context(payload)
    return combine_policy_reports([
        evaluator.evaluate(text, rules, client_context=context, json_string_escapes=escapes)
        for text, escapes in tool_call_policy_readings(payload)
    ])


# ---------------------------------------------------------------------------
# Argument names as labels
# ---------------------------------------------------------------------------
#
# Some PII detectors count a value only after its label written as prose:
# ``dob: 1990-01-01``, ``passport: X1234567``, ``password: ...``. In a tool
# call the label is an argument's name, a JSON key, and the value a separate
# string, so the call as sent never puts the two side by side. The PII screen
# also reads the call with each object member written as a ``key: value`` line.
#
# * A key is written as its words, the way a label reads in prose:
#   ``date_of_birth`` as ``date of birth``, ``passportNumber`` as ``passport
#   Number``, ``guest1_dob`` as ``guest dob``. The words are its runs of ASCII
#   letters, split where the case changes; digits, punctuation and spacing are
#   left out. A label therefore holds no digit and no ``@``, so it cannot hold
#   or complete a number or an address, and the ``: `` after it keeps it from
#   running into the value.
# * A string value is written when it has a letter or digit in it, and a number
#   when it has at least four digits. ``null``, ``true``, ``false``, ``NaN``, an
#   empty or masked string, and a number of fewer digits (a count, a flag or a
#   code) have no line, so ``{"require_password": false}`` or ``1`` is not a
#   password. A string flag still is (``"require_password": "yes"``), as the
#   same words are in prose. An object has no line of its own; its members have
#   theirs.
# * A list's values follow its key the way a list follows its label in prose:
#   the key goes before the first of its values written, and the rest stand
#   alone. Writing it before every value would repeat a long key once per
#   item.
# * A string that looks like JSON the way :func:`decode_strings` reads it (it
#   opens with a bracket, a brace or a quote, and holds a quote) is read as
#   JSON, down to :data:`MAX_NESTED_JSON` levels, like a stringified
#   ``arguments``: through its members and values when the parser reads it,
#   and they take the key the string had. A string the parser does not read
#   reaches the tool as it is, and is written as it is; each string inside it
#   that holds an escape is also written decoded, without a key. Past the last
#   level, or when it does not look like JSON, a string is written as it is.
# * A call the parser does not read, because it is not JSON or nests deeper
#   than the parser goes, is JSON the tool decodes: it is read in pieces, each
#   of its strings (keys included) as a value, decoded, and the text between
#   them as it is.
# * Lines are joined with :data:`_JOIN`. No PII pattern matches across its
#   ``;``, so no match runs from one member or list item into the next.


class _Number(str):
    """A JSON number, as the payload writes it."""


#: Fewest digits a number needs for a line of its own: a shorter one is a count,
#: a flag or a code, not an identifier or a credential.
_MIN_NUMBER_DIGITS = 4


def _no_constant(_: str) -> None:
    return None


#: :func:`_parse_json`'s parser, keeping numbers as written and ``NaN`` or
#: ``Infinity`` as ``null``. Built once: a call can hold many strings to try.
_VALUES_DECODER = json.JSONDecoder(
    object_pairs_hook=_Members,
    parse_int=_Number,
    parse_float=_Number,
    parse_constant=_no_constant,
)


def _parse_values(value: str) -> Any:
    try:
        return _VALUES_DECODER.decode(value)
    except (ValueError, RecursionError):
        return _UNPARSED


#: A word of a key: a run of ASCII letters, split where the case changes
#: (``dateOfBirth``, ``HTTPPassword``, ``userDOB``).
_KEY_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")


def _has_word(text: str) -> bool:
    return any(char.isalnum() for char in text)


def _label(key: str) -> Optional[str]:
    return " ".join(_KEY_WORD_RE.findall(key)) or None


class _Unread(str):
    """Text the parser did not read."""


class _Text(str):
    """Text written as it is, never read as JSON again."""


def _pieces(text: str) -> Iterator[str]:
    """*text* in order: the text before each JSON string literal, then the literal decoded.

    Found the way :func:`_literals` finds closed literals. A literal that never
    closes ends the walk: the rest of *text*, from where that literal opened,
    is one piece of text (its prefix is decoded by :func:`_literals` for the
    screens; this walk leaves it as surrounding text). A closed literal a
    strict decoder rejects is decoded with invalid escapes kept as written,
    and the walk continues.
    """
    pos = 0
    while True:
        start = text.find('"', pos)
        if start < 0:
            break
        value, end, closed = _read_literal(text, start + 1)
        if not closed:
            break
        yield _Text(text[pos:start])
        yield value
        pos = end
    yield _Text(text[pos:])


def _escaped_strings(text: str) -> List[str]:
    """Each closed JSON string literal in *text* that holds an escape, decoded.

    Found the way :func:`_literals` finds them. A bad escape is kept as written
    and does not stop the walk; a literal that never closes does.
    """
    found: List[str] = []
    pos = 0
    while True:
        start = text.find('"', pos)
        if start < 0:
            return found
        value, end, closed = _read_literal(text, start + 1)
        if not closed:
            return found
        if "\\" in text[start + 1:end - 1]:
            found.append(value)
        pos = end


def _read(text: str) -> Any:
    parsed = _parse_values(text)
    return _Unread(text) if parsed is _UNPARSED else parsed


def _written(value: str) -> bool:
    if isinstance(value, _Number):
        return sum(char.isdigit() for char in value) >= _MIN_NUMBER_DIGITS
    return _has_word(value)


def member_text(payload: str) -> str:
    """*payload* with each JSON object member written as a ``key: value`` line.

    The text the label-gated PII detectors read in a tool call: the call's
    argument names are their labels. A key is written as its words, a list's
    values follow its key once, JSON inside strings is read through its
    members, and the lines are joined with ``"\\n;\\n"`` (see the comment
    above). Values are written decoded, in document order, repeated keys
    included. A payload the strict parser does not read is read in pieces:
    its strings decoded and the text between them as it is. JSON inside a
    string that does not parse is written as it is, with its escaped strings
    decoded after it. The text is never more than twice as long as *payload*.
    """
    lines: List[str] = []
    # A string that repeats is read once: what the parser made of it, and the
    # escaped strings of one it did not read. The walk never changes either.
    reads: Dict[str, Any] = {}
    escaped: Dict[str, List[str]] = {}
    # A value, the one-item list holding the key its member's first written
    # value takes (emptied once taken), and its level of JSON inside strings.
    stack: List[Tuple[Any, List[Optional[str]], int]] = [(_read(payload or ""), [None], 0)]
    while stack:
        node, label, level = stack.pop()
        if isinstance(node, _Unread):
            stack.extend((piece, [None], level) for piece in reversed(list(_pieces(node))))
        elif isinstance(node, _Members):
            stack.extend((value, [_label(key)], level) for key, value in reversed(node))
        elif isinstance(node, list):
            stack.extend((item, label, level) for item in reversed(node))
        elif isinstance(node, str):
            if not isinstance(node, (_Number, _Text)) and level < MAX_NESTED_JSON and _looks_like_json(node):
                if node not in reads:
                    reads[node] = _read(node)
                if not isinstance(reads[node], _Unread):
                    stack.append((reads[node], label, level + 1))
                    continue
                # Not parsed: the tool receives it as it is, written below, and
                # each string in it that holds an escape is read decoded after it.
                if node not in escaped:
                    escaped[node] = _escaped_strings(node)
                stack.extend((_Text(value), [None], level) for value in reversed(escaped[node]))
            if _written(node):
                if label[0] is None:
                    lines.append(node)
                else:
                    lines.append(f"{label[0]}: {node}")
                    label[0] = None
    return _JOIN.join(lines)


def scan_tool_call_pii(payload: str) -> Dict[str, int]:
    """PII counts for a ``tool_call`` payload, as sent and member by member.

    :func:`~artzain.pii_detector.scan_text` reads the payload as sent and
    :func:`member_text`, and each detector keeps the larger count.
    """
    from artzain.pii_detector import scan_text

    counts = scan_text(payload)
    text = member_text(payload)
    if text:
        for detector, count in scan_text(text).items():
            counts[detector] = max(count, counts.get(detector, 0))
    return counts


# ---------------------------------------------------------------------------
# Where a call names a client, for the conduct rules
# ---------------------------------------------------------------------------
#
# ``CONDUCT-PROFANITY-CLIENT`` is a finding when profanity sits in a text that
# names a client, with a word such as ``customer``, ``client`` or ``account``.
# The words a tool sends are the call's string values. Its argument names and
# its tool name come from the tool's schema whatever a message says, so an
# ``account`` argument beside an internal message, or a tool called
# ``customer.notify``, names no client for the message. A client named in any
# value counts for the whole call, as it does in the same values sent as
# ``model_output``: a subject line that names the customer makes profanity in
# the body a finding. A key or a tool name that holds a profanity and a client
# word together, as a translation catalog keyed by its source sentences can,
# is text of its own and names a client for itself. Profanity and insults are
# still found in names and values alike: the evaluator reads the call as sent
# and as each of :func:`decoded_texts`, keys included. When the call names no
# client, the client words in those texts are ruled out; when it does, each
# text's own client words decide, so the call never makes a text name a client
# it does not show, and no text is judged stricter than before.
#
# * The tool's name is read where :func:`_tool_name` finds it: the first of
#   ``tool``, ``name``, ``function`` and ``tool_name`` that a call holds as
#   text, a ``function`` object standing for its ``name`` (its other members
#   hold values), and a key given twice read with its last value, as the
#   contract's parser reads it. A call is the payload, each object in a list
#   payload, or each object in a ``tool_calls`` list at the top. A key named
#   like those anywhere else holds a value.
# * A value that looks like JSON is read as JSON down to
#   :data:`MAX_NESTED_JSON` levels, through its keys and values when the
#   parser reads it. Past the last level it is read as the text it is, and
#   each string inside it that holds an escape is also read decoded.
# * JSON in a value that the parser does not read, such as a document cut
#   short, has no names to tell from its values. It is text, and so is each
#   string in it, keys included: decoded, and read as text in turn, down to
#   the last level. This reads such JSON as :func:`decoded_texts` writes it
#   out: its strings up to the first one that does not decode, such as the one
#   the end cuts off, and at the last level each string as the text it is, its
#   own strings not decoded. Such JSON names a client only where a text the
#   conduct rules read shows one.
# * Each string is read once at each level in each of these ways, however
#   often it repeats.
# * A payload the strict parser does not read has no names to tell from its
#   values, so the conduct rules search each text they read for a client word,
#   as for any text; on the engine, the contract vote reviews such a call.


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and not isinstance(value, _Number)


def _call_name_key(call: _Members) -> Optional[str]:
    """The key a call's tool name is read from, as :func:`_tool_name` reads it, or None.

    :func:`_tool_name` reads the call parsed without its repeated keys, so a
    key given twice counts with its last value.
    """
    last = dict(call)
    for name in _NAME_KEYS:
        value = last.get(name)
        if _is_text(value) and value.strip():
            return name
        if name == "function" and isinstance(value, _Members):
            inner = dict(value).get("name")
            if _is_text(inner) and inner.strip():
                return name
    return None


def conduct_client_context(payload: str) -> Optional[bool]:
    """Whether a ``tool_call`` payload names a client, for the conduct rules.

    True when a string value names a client, at any level, or when a key or
    the tool's name holds a profanity and a client word together; False when
    none does, and the conduct rules then read the call as naming no client.
    A value holding JSON that a strict parser does not read is text, keys
    included, read as far as :func:`decoded_texts` decodes it; JSON in a
    value past the last level is the text it is, with its escaped strings
    read decoded.
    None when a strict JSON parser does not read *payload*: the conduct rules
    then read the client words of each text, as for any text. See the comment
    above.
    """
    from artzain.policy_enforcement import _CLIENT_CONTEXT, _CONDUCT_PROFANITY

    root = _parse_values(payload or "")
    if root is _UNPARSED:
        return None

    def holds_both(text: str) -> bool:
        return bool(_CONDUCT_PROFANITY.search(text)) and bool(_CLIENT_CONTEXT.search(text))

    # A string that repeats is parsed once, and searched for escapes once.
    reads: Dict[str, Any] = {}
    escaped: Dict[str, List[str]] = {}

    def escaped_strings(text: str) -> List[str]:
        if text not in escaped:
            escaped[text] = _escaped_strings(text)
        return escaped[text]

    # Each string is read once at each level as each role, however often it repeats.
    seen: Set[Tuple[str, int, str]] = set()
    # A value, its level of JSON inside strings, and what it is read as: the
    # payload ("root"), a call, the call's function object, a value, or text (a
    # string in JSON the parser did not read, whose keys cannot be told from
    # its values).
    stack: List[Tuple[Any, int, str]] = [(root, 0, "root")]
    while stack:
        node, level, role = stack.pop()
        if isinstance(node, _Members):
            if role == "root" and not any(key == "tool_calls" and isinstance(value, list) for key, value in node):
                role = "call"
            if role == "call":
                name_key = _call_name_key(node)
            elif role == "function":
                name_key = "name"
            else:
                name_key = None
            for key, value in node:
                if holds_both(key):
                    return True
                if key == name_key and _is_text(value):
                    if holds_both(value):
                        return True
                elif role == "call" and key == name_key == "function" and isinstance(value, _Members):
                    stack.append((value, level, "function"))
                elif role == "root" and key == "tool_calls" and isinstance(value, list):
                    stack.extend((call, level, "call") for call in value)
                else:
                    stack.append((value, level, "value"))
        elif isinstance(node, list):
            stack.extend((item, level, "call" if role == "root" else "value") for item in node)
        elif _is_text(node):
            if (node, level, role) in seen:
                continue
            seen.add((node, level, role))
            if _looks_like_json(node):
                if role != "text" and level < MAX_NESTED_JSON:
                    if node not in reads:
                        reads[node] = _parse_values(node)
                    if reads[node] is not _UNPARSED:
                        stack.append((reads[node], level + 1, "value"))
                        continue
                if level < MAX_NESTED_JSON:
                    # Not parsed: text, and so is each string in it. A string
                    # without an escape reads the same in the text itself.
                    stack.extend((inner, level + 1, "text") for inner in escaped_strings(node))
                elif role != "text" and any(_CLIENT_CONTEXT.search(inner) for inner in escaped_strings(node)):
                    return True
            if _CLIENT_CONTEXT.search(node):
                return True
    return False


#: How a reply that is a JSON object or array opens, after any whitespace or
#: byte order mark: an object with its first key or its end, an array with its
#: first value or its end. ``NaN`` and ``Infinity`` are the constants Python's
#: parser also accepts.
_JSON_CONTAINER_OPENING_RE = re.compile(
    r'[\s\ufeff]*(?:\{[\s\ufeff]*["}]'
    r'|\[[\s\ufeff]*(?:["{\[\]0-9-]|(?:true|false|null|NaN|Infinity)\b))'
)

_JSON_STRING_OPENING_RE = re.compile(r'[\s\ufeff]*"')


def reads_decoded(payload_kind: str, payload: str) -> bool:
    """Whether the screens read a payload decoded as well as sent.

    Such a payload's destructive-action and injection screens are
    :func:`screen_tool_call_action` and :func:`detect_tool_call_injection`.
    The policy, privacy and special-category screens read it as sent and as
    :func:`tool_call_policy_texts`, and the privacy screen also as
    :func:`member_text`. Offline ``decide()``'s policy vote reads those texts
    without :func:`conduct_client_context`, which keys off a tool name a reply
    does not have, and without measuring the approval window in decoded
    characters, which is a tool call's as-sent reading.

    * A ``tool_call`` payload always is: a call is JSON.
    * A ``model_output`` payload is when it is JSON with a string to decode: it
      opens, after any whitespace or byte order mark, as an object with its
      first key, as an array with its first value, or as a string that is the
      whole reply. A client that parses the reply acts on its strings decoded.
      A lenient parser also reads an object or array a strict one rejects,
      such as one cut off at a token limit, so for those only the opening is
      checked.
    * Any other payload is read as written.
    """
    if payload_kind == "tool_call":
        return True
    text = payload or ""
    if payload_kind != "model_output" or '"' not in text:
        return False
    if _JSON_CONTAINER_OPENING_RE.match(text):
        return True
    opening = _JSON_STRING_OPENING_RE.match(text)
    if opening is None:
        return False
    # A string is the whole reply when nothing but whitespace follows it, or
    # when it is never closed (cut off at a token limit).
    end = _STRING_BODY_RE.match(text, opening.end()).end()
    return end >= len(text) or text[end] != '"' or not text[end + 1:].strip()
