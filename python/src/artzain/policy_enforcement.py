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
from bisect import bisect_left
from dataclasses import dataclass, field
from functools import cached_property
from itertools import accumulate
from typing import Any, Iterator, Optional, Sequence

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
    #: True when every match of the pattern had an approval marker near it,
    #: which suppressed this finding. Suppressed findings live in
    #: ``PolicyEnforcementReport.suppressed`` and never count toward
    #: ``violation_count``.
    suppressed_by_approval_marker: bool = False
    #: The configured marker near the pattern's first match (lower-case).
    approval_marker: str = ""


@dataclass
class PolicyEnforcementReport:
    violation_count: int
    findings: list[PolicyEnforcementFinding]
    rules_checked: int
    text_hash: str = ""
    #: Rule patterns the approval escape suppressed, kept for the audit trail:
    #: one entry per pattern whose every match had a marker nearby. A pattern
    #: with an unapproved match is a finding and is not listed here.
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
    #: An approval marker only approves a match when it occurs within this
    #: many characters before or after the matched span. A marker elsewhere in
    #: the text (e.g. a trailing "per policy") no longer switches the rule off,
    #: and a pattern is suppressed only when every one of its matches is
    #: approved: one approved match does not approve the others.
    approval_window_chars: int = 160
    #: At most this many matches of one pattern can be approved. A pattern with
    #: more is a finding, whatever markers sit near them; the escape is for an
    #: occasional approved exception.
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
    """

    def __init__(self, text: str, markers: Sequence[str]) -> None:
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
        #: Each distinct marker, in configured order, with its sorted starts.
        self._by_marker: list[tuple[str, list[int]]] = []
        spans: list[tuple[int, int]] = []
        for key, marker in searched.items():
            starts: list[int] = []
            at = lowered.find(key)
            while at >= 0:
                starts.append(at)
                at = lowered.find(key, at + 1)
            self._by_marker.append((marker, starts))
            spans.extend((start, start + len(key)) for start in starts)
        spans.sort()
        self._starts = [start for start, _ in spans]
        #: ``_min_end[i]``: the earliest end among the occurrences from ``i`` on.
        self._min_end = list(accumulate(reversed([end for _, end in spans]), min))[::-1]

    def any_within(self, lo: int, hi: int) -> bool:
        """True when some marker occurs entirely inside ``[lo, hi)``."""
        i = bisect_left(self._starts, lo)
        return i < len(self._starts) and self._min_end[i] <= hi

    def first_within(self, lo: int, hi: int) -> Optional[str]:
        """The first configured marker that occurs entirely inside ``[lo, hi)``."""
        for marker, starts in self._by_marker:
            i = bisect_left(starts, lo)
            if i < len(starts) and starts[i] + len(marker) <= hi:
                return marker
        return None


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
    ) -> PolicyEnforcementReport:
        """Screen *text* against *rules*, and against the conduct rules unless *rules* is empty.

        *client_context* is passed to :func:`evaluate_conduct`: ``False`` says
        the client words in *text* name no client.
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
        markers: Optional[_ApprovalMarkers] = None
        for rule in rules:
            escapable = (
                self.config.require_approval_escape
                and "approval" in rule.summary.lower()
            )
            for pat in rule.compiled_patterns():
                matches = pat.finditer(text)
                m = next(matches, None)
                if m:
                    marker = None
                    if escapable:
                        if markers is None:
                            markers = _ApprovalMarkers(text, self.config.approval_markers)
                        marker = self._approval_marker(markers, m, matches)
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
        first: re.Match[str],
        rest: Iterator[re.Match[str]],
    ) -> Optional[str]:
        """The marker that approves *first*, when every match of its pattern is approved.

        A marker approves a match when it lies within ``approval_window_chars``
        before its start or after its end, or inside the match; a non-positive
        window leaves only inside. *first* is a pattern's first match and
        *rest* its later ones: the first match with no marker near it, or the
        first past ``approval_max_matches``, makes the pattern a finding,
        whatever markers the other matches have, and the result is ``None``.
        """
        window = max(0, int(self.config.approval_window_chars))
        limit = int(self.config.approval_max_matches)
        marker = markers.first_within(first.start() - window, first.end() + window)
        if marker is None or limit < 1:
            return None
        for count, m in enumerate(rest, start=2):
            if count > limit or not markers.any_within(m.start() - window, m.end() + window):
                return None
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
