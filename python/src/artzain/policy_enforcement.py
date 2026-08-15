# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
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
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

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

    def compiled_patterns(self) -> tuple[re.Pattern[str], ...]:
        out: list[re.Pattern[str]] = []
        for raw in self.violation_patterns:
            try:
                out.append(re.compile(raw, re.IGNORECASE))
            except re.error:
                continue
        return tuple(out)

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


@dataclass
class PolicyEnforcementReport:
    violation_count: int
    findings: list[PolicyEnforcementFinding]
    rules_checked: int
    text_hash: str = ""

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
        rid = hashlib.sha256(f"{ref}:{sent}".encode()).hexdigest()[:16]
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
        md = it.get("metadata") if isinstance(it.get("metadata"), dict) else {}
        link = md.get("web_link") or md.get("url") or ""
        ref = subject if not link else f"{subject}"
        batch = extract_rules_from_document(
            subject=subject,
            body=snippet,
            agent=agent,
            source_ref=ref,
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


def evaluate_conduct(text: str) -> list[PolicyEnforcementFinding]:
    """Detect profanity / abuse directed at clients (policy infraction)."""
    if not text or not text.strip():
        return []
    findings: list[PolicyEnforcementFinding] = []
    profane = bool(_CONDUCT_PROFANITY.search(text))
    client_ctx = bool(_CLIENT_CONTEXT.search(text))
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


class PolicyEnforcementEvaluator:
    """Screen model or user text against client-specific policy rules."""

    def __init__(self, config: PolicyEnforcementConfig | None = None) -> None:
        self.config = config or PolicyEnforcementConfig()

    def evaluate(
        self,
        text: str,
        rules: Sequence[ClientPolicyRule],
    ) -> PolicyEnforcementReport:
        if not text or not rules:
            return PolicyEnforcementReport(
                violation_count=0,
                findings=[],
                rules_checked=len(rules) if rules else 0,
                text_hash=hashlib.sha256((text or "").encode()).hexdigest()[:16],
            )
        lower = text.lower()
        has_approval = any(
            m in lower for m in self.config.approval_markers
        )
        findings: list[PolicyEnforcementFinding] = []
        for rule in rules:
            for pat in rule.compiled_patterns():
                if pat.search(text):
                    if (
                        self.config.require_approval_escape
                        and has_approval
                        and "approval" in rule.summary.lower()
                    ):
                        continue
                    findings.append(
                        PolicyEnforcementFinding(
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            category=rule.category,
                            severity=rule.severity,
                            matched_pattern=pat.pattern[:120],
                            summary=rule.summary,
                        )
                    )
                    break
        conduct = evaluate_conduct(text)
        if conduct:
            seen_ids = {f.rule_id for f in findings}
            for f in conduct:
                if f.rule_id not in seen_ids:
                    findings.append(f)
                    seen_ids.add(f.rule_id)
        return PolicyEnforcementReport(
            violation_count=len(findings),
            findings=findings,
            rules_checked=len(rules) + len(builtin_conduct_rules()),
            text_hash=hashlib.sha256(text.encode()).hexdigest()[:16],
        )

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
