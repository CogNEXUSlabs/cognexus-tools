"""Client-specific policy enforcement from organizational documents.

Complements :mod:`artzain.prompt_defense` (OWASP-aligned *generic* system-prompt
checks) with *tenant-specific* rules derived from HR, legal, and business policy
documents indexed by CogNEXUS Compliance Monitor / Legal Watch.

Rules are structured for deterministic regex screening at inference time — same
privacy posture as prompt defense (no raw document bodies in audit rows).
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from typing import Any, Optional, Sequence

try:  # Python 3.11 and later: the parser ``re`` compiles patterns with
    from re import _constants as _sre_constants
    from re import _parser as _sre_parse
except ImportError:  # Python 3.10, where the same parser has its older name
    import sre_constants as _sre_constants
    import sre_parse as _sre_parse

# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

_POLICY_SIGNAL = re.compile(
    r"\b("
    r"must not|shall not|may not|prohibited|forbidden|"
    r"do not|should not|cannot|will not|"
    r"required to|(?:are|is)\s+required|must|shall|"
    r"without\s+.{0,48}approval|"
    r"not exceed|no longer than|within\s+\d+|"
    r"no commitments|do not commit"
    r")\b",
    re.IGNORECASE,
)

# Half of a UTF-16 surrogate pair (U+D800-U+DFFF), which ``json.loads`` makes
# from a lone escape. No UTF-8 encoder accepts one: whoever reads the text next
# drops it, replaces it or rejects the text, so a rule match on the text as
# given cannot say what they read.
_UNPAIRED_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

#: Rule id of the critical finding for text that is not valid Unicode.
UNPAIRED_SURROGATE_RULE_ID = "INPUT-UNPAIRED-SURROGATE"


def _text_hash(text: str) -> str:
    """First 16 hex digits of SHA-256 over *text*, ``surrogatepass`` so it cannot raise."""
    return hashlib.sha256((text or "").encode("utf-8", "surrogatepass")).hexdigest()[:16]


_STOPWORDS = frozenset({
    "that", "this", "with", "from", "have", "been", "were", "will", "your",
    "their", "when", "unless", "only", "such", "into", "about", "should",
    "would", "could", "applies", "apply", "including", "accordance",
})

_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "data_retention": (
        "retention", "gdpr", "pii", "phi", "residency", "months", "delete",
        "archive", "churn", "replication", "data subject",
    ),
    "communications_legal": (
        "contract", "msa", "indemnity", "agreement", "clause", "renewal",
        "liability", "slack", "gmail", "email", "communication", "regulatory",
        "docusign", "adobe sign", "pandadoc",
    ),
    "acceptable_use": (
        "sales", "marketing", "customer", "pricing", "brand", "sla",
        "playbook", "datasheet", "commitment",
    ),
    "hr_policy": (
        "hr ", "human resources", "employee", "personnel", "hiring",
        "termination", "leave policy", "workplace", "conduct",
    ),
    "security_privacy": (
        "security policy", "privacy", "encryption", "access control",
        "incident", "breach", "soc2", "iso 27001",
    ),
}


@dataclass(frozen=True)
class ClientPolicyRule:
    """One enforceable rule derived from a client policy document."""

    rule_id: str
    title: str
    summary: str
    category: str
    agent: str
    source_refs: tuple[str, ...] = ()
    violation_patterns: tuple[str, ...] = ()
    severity: str = "medium"

    @cached_property
    def _compiled(self) -> tuple[re.Pattern[str], ...]:
        # Compiled once per rule instance (the dataclass is frozen, but
        # ``cached_property`` writes straight to ``__dict__``); invalid
        # patterns are skipped exactly as before.
        out: list[re.Pattern[str]] = []
        for raw in self.violation_patterns:
            try:
                out.append(re.compile(raw, re.IGNORECASE))
            except re.error:
                continue
        return tuple(out)

    def compiled_patterns(self) -> tuple[re.Pattern[str], ...]:
        return self._compiled

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "summary": self.summary,
            "category": self.category,
            "agent": self.agent,
            "source_refs": list(self.source_refs),
            "violation_patterns": list(self.violation_patterns),
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientPolicyRule:
        refs = data.get("source_refs") or []
        pats = data.get("violation_patterns") or []
        return cls(
            rule_id=str(data.get("rule_id") or data.get("id") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            category=str(data.get("category") or "general"),
            agent=str(data.get("agent") or "compliance_monitor"),
            source_refs=tuple(str(x) for x in refs),
            violation_patterns=tuple(str(x) for x in pats),
            severity=str(data.get("severity") or "medium"),
        )


@dataclass
class PolicyEnforcementFinding:
    rule_id: str
    rule_title: str
    category: str
    severity: str
    matched_pattern: str
    summary: str
    #: True when every match of the pattern had an approval marker near where
    #: it starts, within the limits ``approval_max_matches`` sets, which
    #: suppressed this finding. Suppressed findings live in
    #: ``PolicyEnforcementReport.suppressed`` and never count toward
    #: ``violation_count``.
    suppressed_by_approval_marker: bool = False
    #: The configured marker near where the pattern's first match starts
    #: (lower-case).
    approval_marker: str = ""


@dataclass
class PolicyEnforcementReport:
    violation_count: int
    findings: list[PolicyEnforcementFinding]
    rules_checked: int
    text_hash: str = ""
    #: Rule patterns the approval escape suppressed, kept for the audit trail:
    #: one entry per pattern whose every match had a marker near where it
    #: starts, within the limits ``approval_max_matches`` sets. A pattern with
    #: an unapproved match is a finding and is not listed here.
    suppressed: list[PolicyEnforcementFinding] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return self.violation_count > 0


@dataclass
class PolicyEnforcementConfig:
    """Runtime options for :class:`PolicyEnforcementEvaluator`."""

    block_on_high: bool = True
    block_on_critical: bool = True
    require_approval_escape: bool = True
    approval_markers: tuple[str, ...] = (
        "approved by",
        "with approval",
        "leadership approval",
        "legal approval",
        "compliance approval",
        "per policy",
    )
    #: An approval marker only approves a match when it lies within this many
    #: characters of where the match starts, before or after, however far the
    #: match runs. Every place a pattern matches is judged, a match that starts
    #: inside another match included, and a pattern is suppressed only when
    #: every one of them is approved: one approved match does not approve the
    #: others, and a marker elsewhere in the text (e.g. a trailing "per
    #: policy") does not switch the rule off. An approval written after a long
    #: commitment has to end within this distance of the commitment's first
    #: character. A pattern that opens with an open-ended repeat such as ``.*``
    #: matches from every position the repeat can start at (for ``.*``, from
    #: the start of the line up to where the rest of the pattern last
    #: matches), so each of those needs a marker within this distance. 0
    #: approves nothing.
    approval_window_chars: int = 160
    #: At most this many matches of one pattern can be approved, counted one
    #: after another without overlap: each is looked for from where the
    #: previous one ends, or one character further on after an empty match
    #: (for a pattern that can match the empty string, this count can differ
    #: from what ``re.finditer`` returns). A pattern with more is a finding,
    #: whatever markers sit near them; the escape is for an occasional
    #: approved exception. So is a pattern for which more than this many
    #: places inside its longer matches have to be checked one at a time for
    #: another match starting there: when every match of the pattern starts
    #: with at least three fixed characters, each place those occur outside
    #: the runs of approved starts, and otherwise each run of approved starts
    #: inside a longer match that holds another start.
    approval_max_matches: int = 100


# ---------------------------------------------------------------------------
# Extraction helpers (shared with CogNEXUS server guideline builder)
# ---------------------------------------------------------------------------


def _fragment_to_regex(fragment: str) -> Optional[str]:
    tokens = [
        w
        for w in re.findall(r"[a-z]{4,}", (fragment or "").lower())
        if w not in _STOPWORDS
    ]
    if len(tokens) < 2:
        return None
    return r".{0,35}".join(re.escape(t) for t in tokens[:6])


def violation_patterns_from_sentence(sentence: str) -> list[str]:
    """Build coarse violation regexes from one policy sentence."""
    s = (sentence or "").strip()
    if not s:
        return []
    patterns: list[str] = []
    for prefix in (
        "must not",
        "shall not",
        "may not",
        "prohibited",
        "forbidden",
        "do not",
        "should not",
        "cannot",
        "will not",
        "no commitments",
        "do not commit",
    ):
        m = re.search(
            rf"\b{re.escape(prefix)}\s+(.{{5,140}})",
            s,
            re.IGNORECASE,
        )
        if m:
            fragment = re.split(r"[.;]", m.group(1))[0].strip()
            pat = _fragment_to_regex(fragment)
            if pat:
                patterns.append(pat)
    if re.search(r"without\s+.{3,60}approval", s, re.IGNORECASE):
        patterns.append(
            r"(?:commit|guarantee|promise|offer).{0,90}(?:pricing|discount|sla|custom)"
        )
    if re.search(r"not exceed\s+\d+", s, re.IGNORECASE):
        m = re.search(r"not exceed\s+(\d+)\s+(\w+)", s, re.IGNORECASE)
        if m:
            patterns.append(
                rf"(?:exceed|longer than|more than)\s+{re.escape(m.group(1))}\s+{re.escape(m.group(2))}"
            )
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:6]


def _sentences_from_text(text: str) -> list[str]:
    raw = (text or "").strip()
    if not raw:
        return []
    # skip keyword-hit boilerplate from compliance snippets (before whitespace collapse)
    if raw.lower().startswith("keyword hits:"):
        parts = re.split(r"\n\s*\n", raw, maxsplit=1)
        if len(parts) > 1:
            raw = parts[1]
        else:
            raw = re.sub(r"^keyword hits:[^\n]*\n?", "", raw, count=1, flags=re.IGNORECASE)
    compact = re.sub(r"\s+", " ", raw).strip()
    if not compact:
        return []
    chunks = re.split(r"(?<=[.!?])\s+", compact)
    return [c.strip() for c in chunks if len(c.strip()) >= 24]


def infer_category(subject: str, body: str) -> str:
    blob = f"{subject} {body}".lower()
    best = "general"
    best_score = 0
    for cat, keys in _CATEGORY_KEYWORDS.items():
        score = sum(1 for k in keys if k in blob)
        if score > best_score:
            best_score = score
            best = cat
    return best


def extract_rules_from_document(
    *,
    subject: str,
    body: str,
    agent: str = "compliance_monitor",
    source_ref: Optional[str] = None,
    max_rules: int = 8,
) -> list[ClientPolicyRule]:
    """Derive enforceable rules from one indexed document snippet."""
    if contains_likely_secrets(f"{subject}\n{body}"):
        return []
    ref = (source_ref or subject or "document").strip()
    category = infer_category(subject, body)
    rules: list[ClientPolicyRule] = []
    for sent in _sentences_from_text(body):
        if not _POLICY_SIGNAL.search(sent):
            continue
        pats = violation_patterns_from_sentence(sent)
        if not pats:
            continue
        title_words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'/-]*", sent)
        title = " ".join(title_words[:10])
        if len(title) > 72:
            title = title[:69] + "…"
        rid = hashlib.sha256(f"{ref}:{sent}".encode("utf-8", "surrogatepass")).hexdigest()[:16]
        sev = "high" if re.search(
            r"\b(critical|pii|phi|personal data|indemnity|uncapped)\b", sent, re.I
        ) else "medium"
        rules.append(
            ClientPolicyRule(
                rule_id=f"CPR-{rid}",
                title=title or ref,
                summary=sent[:480],
                category=category,
                agent=agent,
                source_refs=(ref,),
                violation_patterns=tuple(pats),
                severity=sev,
            )
        )
        if len(rules) >= max_rules:
            break
    return rules


def rules_from_context_items(
    items: Sequence[dict[str, Any]],
    *,
    agent: str = "compliance_monitor",
    max_rules_per_doc: int = 6,
    max_total: int = 80,
) -> list[ClientPolicyRule]:
    """Build rules from CogNEXUS ``context_items`` rows (dashboard / API shape)."""
    all_rules: list[ClientPolicyRule] = []
    for it in items:
        subject = str(it.get("subject") or "(untitled)")
        snippet = str(it.get("snippet") or "")
        batch = extract_rules_from_document(
            subject=subject,
            body=snippet,
            agent=agent,
            source_ref=subject,
            max_rules=max_rules_per_doc,
        )
        all_rules.extend(batch)
        if len(all_rules) >= max_total:
            break
    return all_rules[:max_total]


# ---------------------------------------------------------------------------
# Secrets + professional conduct (always-on, not from document indexing)
# ---------------------------------------------------------------------------

_SECRET_BODY_RE = re.compile(
    r"(?i)(api[_-]?key|secret[_-]?key|sk_live_|pk_live_|AKIA[0-9A-Z]{16}|"
    r"password\s*[:=]|bearer\s+[a-z0-9._\-]{20,})"
)

_CONDUCT_PROFANITY = re.compile(
    r"\b("
    r"fuck(?:ing|ed|er)?|motherfucker|shit(?:ty)?|bullshit|asshole|"
    r"bitch(?:es)?|damn\s+you|cunt|wtf"
    r")\b",
    re.IGNORECASE,
)

_CLIENT_CONTEXT = re.compile(
    r"\b(client|customer|account|buyer|prospect|end[\s-]?user)\b",
    re.IGNORECASE,
)

_DIRECTED_ABUSE = re.compile(
    r"(?i)\b(you|your)\b.{0,48}\b(idiot|moron|stupid|incompetent|worthless|pathetic)\b"
)


def contains_likely_secrets(text: str) -> bool:
    if not text:
        return False
    return bool(_SECRET_BODY_RE.search(text))


def builtin_conduct_rules() -> list[ClientPolicyRule]:
    """Standard workplace / client communication rules (not document-derived)."""
    return [
        ClientPolicyRule(
            rule_id="CONDUCT-PROFANITY-CLIENT",
            title="Professional conduct with clients",
            summary=(
                "Do not use profanity, slurs, threats, or abusive language toward "
                "clients, customers, or prospects."
            ),
            category="acceptable_use",
            agent="compliance_monitor",
            source_refs=("Company conduct policy",),
            violation_patterns=(),
            severity="critical",
        ),
        ClientPolicyRule(
            rule_id="CONDUCT-HARASSMENT",
            title="Respectful communication",
            summary=(
                "Do not harass, insult, or demean colleagues, clients, or partners "
                "in business communications."
            ),
            category="hr_policy",
            agent="compliance_monitor",
            source_refs=("Company conduct policy",),
            violation_patterns=(),
            severity="high",
        ),
    ]


def evaluate_conduct(
    text: str,
    *,
    client_context: Optional[bool] = None,
) -> list[PolicyEnforcementFinding]:
    """Detect profanity / abuse directed at clients (policy infraction).

    Profanity is a client finding when the text names a client (a word such as
    customer, client or account) or aims the abuse at the reader. A caller
    that knows the client words in *text* name no client passes
    ``client_context=False``, and the text then names none: a tool call's
    argument names and tool name are part of its serialized text, and
    :func:`artzain.tool_call_contract.conduct_client_context` is False when
    they hold its only client words. ``None`` or ``True`` leave the text's own
    client words to decide; the argument never adds a client the text does
    not name.
    """
    if not text or not text.strip():
        return []
    findings: list[PolicyEnforcementFinding] = []
    profane = bool(_CONDUCT_PROFANITY.search(text))
    client_ctx = client_context is not False and bool(_CLIENT_CONTEXT.search(text))
    directed = bool(_DIRECTED_ABUSE.search(text))
    if profane and (client_ctx or directed):
        findings.append(
            PolicyEnforcementFinding(
                rule_id="CONDUCT-PROFANITY-CLIENT",
                rule_title="Professional conduct with clients",
                category="acceptable_use",
                severity="critical",
                matched_pattern="profanity_client_context",
                summary="Profanity or abusive language toward a client or customer.",
            )
        )
    elif directed:
        findings.append(
            PolicyEnforcementFinding(
                rule_id="CONDUCT-HARASSMENT",
                rule_title="Respectful communication",
                category="hr_policy",
                severity="high",
                matched_pattern="directed_insult",
                summary="Insulting or demeaning language directed at a person.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


#: Small and final small sigma. ``str.lower()`` picks one of them for a capital
#: sigma from the letters around it, so markers compare with both read as small.
_SIGMA, _FINAL_SIGMA = chr(0x3C3), chr(0x3C2)

#: One JSON string escape, the character it stands for. ``\u`` and a high
#: surrogate are handled apart: JSON spells both with a lowercase ``u``.
_JSON_SIMPLE_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/",
    "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
}
_JSON_HEX = frozenset("0123456789abcdefABCDEF")


def _json_unicode_escape(text: str, i: int) -> tuple[str, int] | None:
    """The character ``text[i:]``'s ``\\uXXXX`` stands for, and how many raw characters it uses.

    ``i`` points at the backslash. A high surrogate followed by a low one is
    the one character the pair stands for (twelve raw characters); anything
    else, including a lone surrogate, is the one character of those four hex
    digits. Incomplete or non-hex tails are not an escape.
    """
    if i + 6 > len(text) or text[i + 1] != "u":
        return None
    hex4 = text[i + 2:i + 6]
    if any(c not in _JSON_HEX for c in hex4):
        return None
    code = int(hex4, 16)
    if 0xD800 <= code <= 0xDBFF and i + 12 <= len(text) and text[i + 6:i + 8] == "\\u":
        low = text[i + 8:i + 12]
        if all(c in _JSON_HEX for c in low):
            low_code = int(low, 16)
            if 0xDC00 <= low_code <= 0xDFFF:
                point = 0x10000 + ((code - 0xD800) << 10) + (low_code - 0xDC00)
                return chr(point), 12
    return chr(code), 6


def _json_escape(text: str, i: int) -> tuple[str, int] | None:
    """The character the escape at ``text[i]`` stands for, and its raw length, or None."""
    if i + 1 >= len(text) or text[i] != "\\":
        return None
    simple = _JSON_SIMPLE_ESCAPES.get(text[i + 1])
    if simple is not None:
        return simple, 2
    if text[i + 1] == "u":
        return _json_unicode_escape(text, i)
    return None


def _json_string_escapes(text: str) -> tuple[str, list[int]]:
    """*text* with each complete JSON string escape replaced by the character it stands for.

    Returns ``(decoded, at)``. ``at[i]`` is how many decoded characters
    ``text[:i]`` holds, so every raw index of one escape shares the index of
    the character it stands for and ``at[len(text)]`` is ``len(decoded)``. An
    escape that does not complete stays as written, and so does everything
    outside a string: quotes, commas and brackets are not dropped, and a marker
    cannot move across them. A hex digit of an escape is therefore not a letter
    of a marker; the letter, when the escape stands for one, is.
    """
    at = [0] * (len(text) + 1)
    decoded: list[str] = []
    i = 0
    d = 0
    n = len(text)
    while i < n:
        at[i] = d
        ch = text[i]
        if ch != '"':
            decoded.append(ch)
            i += 1
            d += 1
            continue
        decoded.append('"')
        i += 1
        d += 1
        while i < n:
            at[i] = d
            ch = text[i]
            if ch == '"':
                decoded.append('"')
                i += 1
                d += 1
                break
            if ch == "\\":
                escape = _json_escape(text, i)
                if escape is not None:
                    chars, consumed = escape
                    for k in range(1, consumed):
                        at[i + k] = d
                    decoded.append(chars)
                    i += consumed
                    d += len(chars)
                    continue
            decoded.append(ch)
            i += 1
            d += 1
    at[n] = d
    return "".join(decoded), at

# ---------------------------------------------------------------------------
# The characters every match of a pattern starts with
# ---------------------------------------------------------------------------
#
# Inside a longer match, the approval escape looks for further matches that
# start outside the runs of starts that markers approve. When every match of a
# pattern starts with some fixed characters (``offer``, ``[Oo]ffer``, one of
# ``commit|guarantee``), only the places those characters occur can start a
# match, so only those places are tried, one ``match`` each: no match is tried
# inside the runs, and the scan for the characters reads each part of the text
# once.

_CATEGORY_SOURCES = {
    _sre_constants.CATEGORY_DIGIT: r"\d",
    _sre_constants.CATEGORY_NOT_DIGIT: r"\D",
    _sre_constants.CATEGORY_SPACE: r"\s",
    _sre_constants.CATEGORY_NOT_SPACE: r"\S",
    _sre_constants.CATEGORY_WORD: r"\w",
    _sre_constants.CATEGORY_NOT_WORD: r"\W",
}
_ZERO_WIDTH = (_sre_constants.AT, _sre_constants.ASSERT, _sre_constants.ASSERT_NOT)
_REPEATS = tuple(
    op
    for op in (
        _sre_constants.MAX_REPEAT,
        _sre_constants.MIN_REPEAT,
        getattr(_sre_constants, "POSSESSIVE_REPEAT", None),
    )
    if op is not None
)
_ATOMIC_GROUP = getattr(_sre_constants, "ATOMIC_GROUP", None)
#: The flags that decide which characters a leading character matches.
_LEAD_FLAGS = re.IGNORECASE | re.UNICODE | re.ASCII
#: Leading characters are looked for only when every match starts with at
#: least this many, in at most this many alternatives; shorter ones occur too
#: often. Without them, the places inside longer matches are found by search,
#: one per run of approved starts, and those count toward
#: ``approval_max_matches`` too.
_LEAD_MIN_CHARACTERS = 3
_LEAD_MAX_ALTERNATIVES = 128
#: A run is read to at most this many characters, and a pattern to at most
#: this many parsed items ahead: a shorter run is still a start every match
#: has, so a long pattern costs no more to read than a short one.
_LEAD_MAX_RUN = 16
_LEAD_MAX_ITEMS = 32
#: Scoped flags that change which characters a leading character matches.
_LEAD_SCOPE_FLAGS = re.ASCII | re.UNICODE | re.LOCALE


def _one_character(op: Any, av: Any) -> Optional[str]:
    """The source of a parsed item that always matches exactly one character, or None."""
    if op is _sre_constants.LITERAL:
        return re.escape(chr(av))
    if op is _sre_constants.NOT_LITERAL:
        return "[^" + re.escape(chr(av)) + "]"
    if op is _sre_constants.IN:
        parts: list[str] = []
        for item_op, item_av in av:
            if item_op is _sre_constants.NEGATE:
                parts.insert(0, "^")
            elif item_op is _sre_constants.LITERAL:
                parts.append(re.escape(chr(item_av)))
            elif item_op is _sre_constants.RANGE:
                parts.append(re.escape(chr(item_av[0])) + "-" + re.escape(chr(item_av[1])))
            elif item_op is _sre_constants.CATEGORY and item_av in _CATEGORY_SOURCES:
                parts.append(_CATEGORY_SOURCES[item_av])
            else:
                return None
        return "[" + "".join(parts) + "]"
    return None


def _followed_by(first: Any, rest: list) -> list:
    """The parsed items of *first* and then *rest*, to at most ``_LEAD_MAX_ITEMS``.

    When *first* alone is longer it is cut there and *rest* left out: reading
    stops at the cut, which only ever shortens or drops what is found.
    """
    head = list(first[:_LEAD_MAX_ITEMS + 1])
    if len(head) > _LEAD_MAX_ITEMS:
        return head[:_LEAD_MAX_ITEMS]
    return (head + rest)[:_LEAD_MAX_ITEMS]


def _run_on(run: list[str], rest: list) -> list[tuple[str, int]]:
    """*run* and the single characters that follow it in *rest*, to ``_LEAD_MAX_RUN``."""
    for op, av in rest:
        if len(run) >= _LEAD_MAX_RUN:
            break
        char = _one_character(op, av)
        if char is None:
            break
        run.append(char)
    return [("".join(run), len(run))]


def _leading_runs(items: list, flags: int, budget: list[int]) -> Optional[list[tuple[str, int]]]:
    """How every match of the parsed *items* starts: one fixed run of characters per alternative.

    Each run is ``(source, number of characters)``. None when a match can start
    some other way (empty, with any character, with a backreference, under
    scoped flags that change what a character matches) or when reading the
    pattern costs more than *budget* allows. *flags* are the pattern's own.
    """
    budget[0] -= 1
    if budget[0] < 0:
        return None
    items = items[:_LEAD_MAX_ITEMS]
    i = 0
    while i < len(items) and items[i][0] in _ZERO_WIDTH:
        i += 1
    if i == len(items):
        return None
    op, av = items[i]
    rest = items[i + 1:]
    first = _one_character(op, av)
    if first is not None:
        return _run_on([first], rest)
    if op is _sre_constants.BRANCH:
        runs: list[tuple[str, int]] = []
        for branch in av[1]:
            found = _leading_runs(_followed_by(branch, rest), flags, budget)
            if found is None:
                return None
            runs.extend(found)
            if len(runs) > _LEAD_MAX_ALTERNATIVES:
                return None
        return runs
    if op is _sre_constants.SUBPATTERN:
        _group, add_flags, del_flags, inner = av
        if (add_flags | del_flags) & _LEAD_SCOPE_FLAGS:
            return None
        # A scoped case flag that the pattern already has (or lacks) changes nothing.
        if (add_flags & re.IGNORECASE and not flags & re.IGNORECASE) or (
            del_flags & re.IGNORECASE and flags & re.IGNORECASE
        ):
            return None
        return _leading_runs(_followed_by(inner, rest), flags, budget)
    if _ATOMIC_GROUP is not None and op is _ATOMIC_GROUP:
        return _leading_runs(_followed_by(av, rest), flags, budget)
    if op in _REPEATS:
        low, high, inner = av
        head = list(inner[:2])
        if low >= 1 and len(head) == 1:
            char = _one_character(*head[0])
            if char is not None:
                # At least *low* of the one character, then the rest after an exact count.
                return _run_on([char] * min(low, _LEAD_MAX_RUN), rest if low == high else [])
        once = _leading_runs(list(inner[:_LEAD_MAX_ITEMS]), flags, budget)
        if once is None or low >= 1:
            return once
        skipped = _leading_runs(rest, flags, budget)
        if skipped is None or len(once) + len(skipped) > _LEAD_MAX_ALTERNATIVES:
            return None
        return once + skipped
    return None


@lru_cache(maxsize=1024)
def _leading_pattern(source: str, flags: int) -> Optional[re.Pattern[str]]:
    """A pattern that matches wherever a match of *source* can start, or None.

    It is the fixed characters every match of *source* starts with, one
    alternative per way a match can start, compiled with the flags that decide
    which characters match. None when some match can start otherwise, with
    fewer than ``_LEAD_MIN_CHARACTERS`` fixed characters, or in more than
    ``_LEAD_MAX_ALTERNATIVES`` ways, and when the pattern takes too long to
    read or the parser reads it differently from this module.
    """
    try:
        runs = _leading_runs(list(_sre_parse.parse(source, flags)[:_LEAD_MAX_ITEMS]), flags, [1024])
    except Exception:  # a pattern the parser reads differently from this module
        return None
    if not runs or len(runs) > _LEAD_MAX_ALTERNATIVES:
        return None
    if min(chars for _, chars in runs) < _LEAD_MIN_CHARACTERS:
        return None
    try:
        return re.compile("|".join(src for src, _ in runs), flags & _LEAD_FLAGS)
    except re.error:
        return None


class _ApprovalMarkers:
    """Where the approval markers occur in one text, found once for every match.

    Markers are compared in lower case, so they are searched for in the text
    lower-cased with every character at its own index: a position here is a
    position in the text. The one character whose lower case is longer, U+0130
    (capital I with dot above, lower case ``i`` and a combining dot), would
    move every position after it; a text holding it is lower-cased character
    by character with that character left as it is, and no lower-case marker
    contains it. The final sigma is read as the small sigma in the text and in
    the markers, since which of the two a capital sigma becomes depends on the
    letters around it. Markers that are not strings are ignored. Occurrences of
    a marker may overlap.

    A match starting at ``s`` is approved by an occurrence that lies entirely
    inside ``[s - window, s + window)``, so an occurrence approves a run of
    starts, from ``window`` characters before its end to ``window`` after its
    start. The runs of every occurrence are merged once per text, so the
    starts one run approves are passed over together.
    """

    def __init__(self, text: str, markers: Sequence[str], window: int) -> None:
        lowered = text.lower()
        if len(lowered) != len(text):
            lowered = "".join(ch if len(ch.lower()) != 1 else ch.lower() for ch in text)
        lowered = lowered.replace(_FINAL_SIGMA, _SIGMA)
        # Each distinct marker as it is searched for, with the first configured
        # marker it stands for (lower-case).
        searched: dict[str, str] = {}
        for m in markers:
            if isinstance(m, str) and m:
                searched.setdefault(m.lower().replace(_FINAL_SIGMA, _SIGMA), m.lower())
        self._window = window
        #: Each distinct marker, in configured order, with its sorted starts.
        self._by_marker: list[tuple[str, list[int]]] = []
        runs: list[tuple[int, int]] = []
        for key, marker in searched.items():
            starts: list[int] = []
            at = lowered.find(key)
            while at >= 0:
                starts.append(at)
                at = lowered.find(key, at + 1)
            self._by_marker.append((marker, starts))
            runs.extend((start + len(key) - window, start + window) for start in starts)
        runs.sort()
        #: The merged runs of approved starts, first and last start of each.
        self._run_first: list[int] = []
        self._run_last: list[int] = []
        for first, last in runs:
            if first > last:
                continue  # longer than the window is wide: approves no start
            if self._run_last and first <= self._run_last[-1] + 1:
                self._run_last[-1] = max(self._run_last[-1], last)
            else:
                self._run_first.append(first)
                self._run_last.append(last)

    def first_near(self, start: int) -> Optional[str]:
        """The first configured marker that approves a match starting at *start*."""
        lo, hi = start - self._window, start + self._window
        for marker, starts in self._by_marker:
            i = bisect_left(starts, lo)
            if i < len(starts) and starts[i] + len(marker) <= hi:
                return marker
        return None

    def approved_through(self, start: int) -> int:
        """The last start of the run of approved starts holding *start*, or -1 outside every run."""
        i = bisect_right(self._run_first, start) - 1
        if i >= 0 and self._run_last[i] >= start:
            return self._run_last[i]
        return -1

    def next_run(self, start: int) -> Optional[int]:
        """The first start of the first run of approved starts at or after *start*, if any."""
        i = bisect_left(self._run_first, start)
        return self._run_first[i] if i < len(self._run_first) else None


class PolicyEnforcementEvaluator:
    """Screen model or user text against client-specific policy rules."""

    def __init__(self, config: PolicyEnforcementConfig | None = None) -> None:
        self.config = config or PolicyEnforcementConfig()

    def evaluate(
        self,
        text: str,
        rules: Sequence[ClientPolicyRule],
        *,
        client_context: Optional[bool] = None,
        json_string_escapes: bool = False,
    ) -> PolicyEnforcementReport:
        """Screen *text* against *rules*, and against the conduct rules unless *rules* is empty.

        *client_context* is passed to :func:`evaluate_conduct`: ``False`` says
        the client words in *text* name no client.

        *json_string_escapes* is for the as-sent text of a JSON tool call. The
        pattern is still matched on *text*, so a match that runs from one
        argument into the next is still caught. Approval markers are found in
        decoded characters, and ``approval_window_chars`` is measured from
        where each match starts in those characters: a complete escape inside
        a JSON string counts as the character it stands for, so a hex digit of
        an escape is not a letter of a marker and ``ensure_ascii``'s
        six-character escapes do not stretch the window.
        Quotes and the characters between strings stay, so a marker is not
        moved next to a match.
        """
        if not text or not rules:
            return PolicyEnforcementReport(
                violation_count=0,
                findings=[],
                rules_checked=len(rules) if rules else 0,
                text_hash=_text_hash(text),
            )
        findings: list[PolicyEnforcementFinding] = []
        suppressed: list[PolicyEnforcementFinding] = []
        # Found on the first match of a rule the approval escape applies to.
        # For a JSON tool call as sent, markers live in the decoded-character
        # text and ``escape_at`` maps a match index onto it.
        markers: Optional[_ApprovalMarkers] = None
        marker_text = text
        escape_at: list[int] | None = None
        if json_string_escapes and "\\" in text:
            marker_text, escape_at = _json_string_escapes(text)
        for rule in rules:
            escapable = (
                self.config.require_approval_escape
                and "approval" in rule.summary.lower()
            )
            for pat in rule.compiled_patterns():
                m = pat.search(text)
                if m:
                    marker = None
                    if escapable:
                        if markers is None:
                            markers = _ApprovalMarkers(
                                marker_text,
                                self.config.approval_markers,
                                max(0, int(self.config.approval_window_chars)),
                            )
                        marker = self._approval_marker(markers, pat, text, m, escape_at)
                    finding = PolicyEnforcementFinding(
                        rule_id=rule.rule_id,
                        rule_title=rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        matched_pattern=pat.pattern[:120],
                        summary=rule.summary,
                    )
                    if marker is not None:
                        finding.suppressed_by_approval_marker = True
                        finding.approval_marker = marker
                        suppressed.append(finding)
                        continue
                    findings.append(finding)
                    break
        conduct = evaluate_conduct(text, client_context=client_context)
        if conduct:
            seen_ids = {f.rule_id for f in findings}
            for f in conduct:
                if f.rule_id not in seen_ids:
                    findings.append(f)
                    seen_ids.add(f.rule_id)
        surrogate = _UNPAIRED_SURROGATE_RE.search(text)
        if surrogate:
            # Reported first, whatever a rule with the same id matched.
            findings.insert(0, PolicyEnforcementFinding(
                rule_id=UNPAIRED_SURROGATE_RULE_ID,
                rule_title="Text is not valid Unicode",
                category="input_validation",
                severity="critical",
                matched_pattern="unpaired_surrogate",
                summary=(
                    f"The text holds an unpaired surrogate (U+{ord(surrogate.group()):04X}). "
                    "Whoever reads it next drops, replaces or rejects that character, "
                    "so the rules cannot say what they read; the text is blocked."
                ),
            ))
        return PolicyEnforcementReport(
            violation_count=len(findings),
            findings=findings,
            rules_checked=len(rules) + len(builtin_conduct_rules()),
            text_hash=_text_hash(text),
            suppressed=suppressed,
        )

    def _approval_marker(
        self,
        markers: _ApprovalMarkers,
        pat: re.Pattern[str],
        text: str,
        first: re.Match[str],
        at: list[int] | None = None,
    ) -> Optional[str]:
        """The marker that approves *first*, when every match of *pat* is approved.

        A marker approves a match when it lies within `approval_window_chars`
        of where the match starts, however far the match runs. *first* is the
        pattern's first match. The later matches are walked in the order they
        start: the next match one after another, looked for from where the
        previous one ends, and, since a match can also start inside another
        one, any match starting inside it outside the runs of starts that
        markers approve. There, when every match of *pat* starts with fixed
        characters, only the places those occur are checked, one `match`
        each; otherwise one search finds the next match past each run. No
        position is tried twice as a start. A match no marker approves, more
        than `approval_max_matches` matches one after another, or more than
        that many places inside longer matches checked one at a time makes
        the pattern a finding and the result `None`.

        *at*, when set, maps an index in the text the pattern matched to an
        index in the text *markers* was built on: the as-sent JSON, with each
        string escape counted as the character it stands for. The window and
        the runs of approved starts are in that text; the pattern is still
        searched in the text as sent.
        """
        def pos(index: int) -> int:
            return index if at is None else at[index]

        def raw_of(decoded: int) -> int:
            """The first index in *text* at this decoded position, or later."""
            return decoded if at is None else bisect_left(at, decoded)

        def raw_after(decoded: int) -> int:
            """The first index in *text* past this decoded position."""
            return decoded + 1 if at is None else bisect_right(at, decoded)

        limit = int(self.config.approval_max_matches)
        marker = markers.first_near(pos(first.start()))
        if marker is None or limit < 1:
            return None
        lead = _leading_pattern(pat.pattern, pat.flags)
        count, checked = 1, 0
        # The next match one after another starts at `after` or later (past
        # an empty match, one character on); every start before `beyond` is
        # approved: in a run of approved starts, or checked.
        after = max(first.end(), first.start() + 1)
        beyond = raw_after(markers.approved_through(pos(first.start())))
        lead_at = -1  # where `lead` was last found
        while min(after, beyond) <= len(text):
            if beyond < after and lead is not None:
                # Inside a match, up to the next run of approved starts: only
                # a place the leading characters are can start a match.
                run = markers.next_run(pos(beyond))
                stop = after if run is None else min(raw_of(run), after)
                while True:
                    if lead_at < beyond:
                        found = lead.search(text, beyond)
                        lead_at = found.start() if found else len(text) + 1
                    if lead_at >= stop:
                        break
                    checked += 1
                    if checked > limit or pat.match(text, lead_at):
                        return None
                    beyond = lead_at + 1
                beyond = after if stop == after else raw_after(markers.approved_through(pos(stop)))
                continue
            m = pat.search(text, min(after, beyond))
            if m is None:
                break
            last = markers.approved_through(pos(m.start()))
            if last < 0:
                return None
            if m.start() >= after:
                count += 1
                if count > limit:
                    return None
                after = max(m.end(), m.start() + 1)
            else:
                checked += 1
                if checked > limit:
                    return None
            beyond = raw_after(last)
        return marker

    def should_block(self, report: PolicyEnforcementReport) -> bool:
        if not report.has_violations:
            return False
        for f in report.findings:
            if f.severity == "critical" and self.config.block_on_critical:
                return True
            if f.severity == "high" and self.config.block_on_high:
                return True
        return False


def parse_rules_json(raw: str) -> list[ClientPolicyRule]:
    data = json.loads(raw)
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of rules or {rules: [...]}")
    return [ClientPolicyRule.from_dict(x) for x in data if isinstance(x, dict)]


__all__ = [
    "ClientPolicyRule",
    "PolicyEnforcementConfig",
    "PolicyEnforcementEvaluator",
    "PolicyEnforcementFinding",
    "PolicyEnforcementReport",
    "builtin_conduct_rules",
    "contains_likely_secrets",
    "evaluate_conduct",
    "extract_rules_from_document",
    "infer_category",
    "parse_rules_json",
    "rules_from_context_items",
    "violation_patterns_from_sentence",
]
