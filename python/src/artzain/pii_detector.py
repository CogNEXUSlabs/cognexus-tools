"""PII exposure detection for the Security Watchdog.

Scans free text for personally identifiable / sensitive financial data and
reports **counts per detector only** — matched values are never copied into
findings, events, tickets, or audit records (same discipline as the
payload-hash rule in the decision leaves; see agent-expansion plan §3.2).

Detectors
---------
``ssn``            US Social Security numbers (hyphenated form ``AAA-GG-SSSS``,
                   with invalid area/group/serial ranges rejected).
``credit_card``    13–19 digit card numbers (separators allowed), validated
                   with the Luhn checksum and a same-digit-run rejection.
``iban``           International Bank Account Numbers, validated with the
                   ISO 13616 mod-97 checksum (kills virtually all false hits).
``email_bulk``     A *bulk* set of distinct email addresses in one text
                   (>= ``BULK_EMAIL_THRESHOLD``); one or two addresses in an
                   email body are normal, thirty are an exfil signature.
``phone_bulk``     A bulk set of distinct phone-format numbers
                   (>= ``BULK_PHONE_THRESHOLD``).
``secrets``        Credential material (API keys, private keys, passwords) via
                   :func:`artzain.policy_enforcement.contains_likely_secrets`.

Usage
-----
::

    from artzain.pii_detector import scan_text

    counts = scan_text(text)      # {"ssn": 2, "credit_card": 1} — empty if clean
    if counts:
        ...  # report counts + item reference, never the values
"""

from __future__ import annotations

import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)

__all__ = [
    "BULK_EMAIL_THRESHOLD",
    "BULK_PHONE_THRESHOLD",
    "DETECTOR_SEVERITY",
    "luhn_ok",
    "iban_ok",
    "minimize_record",
    "redact_text",
    "scan_text",
    "worst_severity",
]

#: Severity class per detector — drives Watchdog routing (high → ticket,
#: medium → event only). Aligned with the agent-expansion plan §3.2.
DETECTOR_SEVERITY: Dict[str, str] = {
    "ssn": "high",
    "credit_card": "high",
    "iban": "high",
    "uk_nino": "high",
    "passport": "medium",
    "dob": "medium",
    "ip_address": "medium",
    "email_bulk": "medium",
    "phone_bulk": "medium",
    "secrets": "medium",
}

_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

BULK_EMAIL_THRESHOLD = 5
BULK_PHONE_THRESHOLD = 5

# ── SSN ── hyphenated form only; the contiguous 9-digit form collides with
# order numbers, tax IDs, and tracking codes far too often to act on.
_SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")

# ── Credit card candidates ── 13–19 digits allowing single space/hyphen
# separators; each candidate is confirmed with Luhn before it counts.
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# ── IBAN candidates ── country code + 2 check digits + 11-30 alphanumerics;
# confirmed with the mod-97 checksum before they count.
_IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Phone-format numbers: international or US formats with enough structure
# (separators / parens / leading +) that bare integers don't match.
_PHONE_RE = re.compile(
    r"(?<![\d-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]\d{3,4}[ .-]?\d{0,4}(?![\d-])"
)

# ── Extended identifier classes (todo #5 — privacy-guardian minimization) ──
# The same precision-first discipline as the checksum detectors: structural
# validation (IP octets, NINO prefix rules) or a *label gate* (passport / DOB
# only count next to their label) so bare numbers and dates never match.

# UK National Insurance number: two letters (with invalid prefixes rejected),
# six digits, suffix A–D. Case-insensitive; optional space groups.
_NINO_RE = re.compile(
    r"\b([A-CEGHJ-PR-TW-Z]{2})\s?(\d{2})\s?(\d{2})\s?(\d{2})\s?([A-D])\b",
    re.IGNORECASE,
)
_NINO_INVALID_PREFIXES = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}

# Label-gated passport number: the word "passport" within a few tokens of a
# 6–9 char alphanumeric identifier.
_PASSPORT_RE = re.compile(
    r"\bpassport(?:\s+(?:no|num|number|#))?\s*[:#]?\s*([A-Z0-9]{6,9})\b",
    re.IGNORECASE,
)

# Label-gated date of birth: "dob" / "date of birth" / "born (on)" + a date.
_DOB_RE = re.compile(
    r"\b(?:dob|date\s+of\s+birth|born(?:\s+on)?)\s*[:#]?\s*"
    r"(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4})\b",
    re.IGNORECASE,
)

# IPv4 with octet validation (0-255); loopback/unspecified filtered below.
_IPV4_RE = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def _nino_valid(m: "re.Match[str]") -> bool:
    prefix = m.group(1).upper()
    if prefix in _NINO_INVALID_PREFIXES:
        return False
    # Second letter O is never issued.
    return prefix[1] != "O"


def _ip_significant(candidate: str) -> bool:
    return candidate not in ("0.0.0.0", "127.0.0.1") and not candidate.startswith("127.")


def luhn_ok(digits: str) -> bool:
    """Return True when *digits* (numeric string) passes the Luhn checksum."""
    if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(candidate: str) -> bool:
    """Return True when *candidate* passes the ISO 13616 mod-97 check."""
    s = candidate.strip().upper()
    if len(s) < 15 or len(s) > 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(
            str(int(ch, 36)) for ch in rearranged
        )  # A→10 … Z→35, digits unchanged
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def _ssn_valid(area: str, group: str, serial: str) -> bool:
    """Reject never-issued SSN ranges (000/666/9xx areas, 00 group, 0000 serial)."""
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _count_ssn(text: str) -> int:
    return sum(1 for m in _SSN_RE.finditer(text) if _ssn_valid(*m.groups()))


def _count_cards(text: str) -> int:
    count = 0
    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        # A long run of one repeated digit passes Luhn but is filler, not a PAN.
        if len(set(digits)) <= 1:
            continue
        if luhn_ok(digits):
            count += 1
    return count


def _count_ibans(text: str) -> int:
    return sum(1 for m in _IBAN_CANDIDATE_RE.finditer(text) if iban_ok(m.group(0)))


def scan_text(text: str) -> Dict[str, int]:
    """Scan *text* and return non-zero counts per detector.

    Returns an empty dict for clean (or empty) text. Never returns matched
    values — callers must only propagate the counts and their own item refs.
    """
    if not text or not text.strip():
        return {}

    counts: Dict[str, int] = {}

    n = _count_ssn(text)
    if n:
        counts["ssn"] = n
    n = _count_cards(text)
    if n:
        counts["credit_card"] = n
    n = _count_ibans(text)
    if n:
        counts["iban"] = n
    n = sum(1 for m in _NINO_RE.finditer(text) if _nino_valid(m))
    if n:
        counts["uk_nino"] = n
    n = len(_PASSPORT_RE.findall(text))
    if n:
        counts["passport"] = n
    n = len(_DOB_RE.findall(text))
    if n:
        counts["dob"] = n
    n = sum(1 for m in _IPV4_RE.finditer(text) if _ip_significant(m.group(0)))
    if n:
        counts["ip_address"] = n

    emails = {m.group(0).lower() for m in _EMAIL_RE.finditer(text)}
    if len(emails) >= BULK_EMAIL_THRESHOLD:
        counts["email_bulk"] = len(emails)
    phones = {re.sub(r"\D", "", m.group(0)) for m in _PHONE_RE.finditer(text)}
    phones = {p for p in phones if 7 <= len(p) <= 15}
    if len(phones) >= BULK_PHONE_THRESHOLD:
        counts["phone_bulk"] = len(phones)

    try:
        from artzain.policy_enforcement import contains_likely_secrets

        if contains_likely_secrets(text):
            counts["secrets"] = 1
    except Exception:  # noqa: BLE001 - secrets check is best-effort
        logger.debug("secrets check skipped", exc_info=True)

    return counts


def worst_severity(counts: Dict[str, int]) -> str:
    """Highest severity class across the detectors present in *counts*."""
    worst = "none"
    for detector in counts:
        sev = DETECTOR_SEVERITY.get(detector, "low")
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(worst, 0):
            worst = sev
    return worst


# ---------------------------------------------------------------------------
# Redaction (privacy-guardian boundary — README top-10 item 7)
# ---------------------------------------------------------------------------

def redact_text(text: str) -> "tuple[str, Dict[str, int]]":
    """Replace high-severity identifiers with type tokens; return (text, counts).

    Only the checksum-validated identifier detectors redact (SSN, card, IBAN)
    — bulk contact lists and secrets are *detection* signals, not stored-data
    hazards of the same class, and redacting every email address would destroy
    the corpus. Idempotent: already-redacted text has no matches left.
    """
    if not text:
        return text or "", {}

    counts: Dict[str, int] = {}

    def _sub_ssn(m: "re.Match[str]") -> str:
        if _ssn_valid(*m.groups()):
            counts["ssn"] = counts.get("ssn", 0) + 1
            return "[REDACTED-SSN]"
        return m.group(0)

    def _sub_card(m: "re.Match[str]") -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if len(set(digits)) > 1 and luhn_ok(digits):
            counts["credit_card"] = counts.get("credit_card", 0) + 1
            return "[REDACTED-CARD]"
        return m.group(0)

    def _sub_iban(m: "re.Match[str]") -> str:
        if iban_ok(m.group(0)):
            counts["iban"] = counts.get("iban", 0) + 1
            return "[REDACTED-IBAN]"
        return m.group(0)

    def _sub_nino(m: "re.Match[str]") -> str:
        if _nino_valid(m):
            counts["uk_nino"] = counts.get("uk_nino", 0) + 1
            return "[REDACTED-NINO]"
        return m.group(0)

    out = _SSN_RE.sub(_sub_ssn, text)
    out = _CARD_CANDIDATE_RE.sub(_sub_card, out)
    out = _IBAN_CANDIDATE_RE.sub(_sub_iban, out)
    out = _NINO_RE.sub(_sub_nino, out)
    return out, counts


# ---------------------------------------------------------------------------
# Field-level minimization (todo #5 — beyond identifier redaction)
# ---------------------------------------------------------------------------

#: Actions a minimization policy may assign to a field.
_MINIMIZE_ACTIONS = ("drop", "hash", "redact", "keep")


def minimize_record(
    record: Dict[str, object],
    policy: Dict[str, str],
    *,
    default: str = "keep",
) -> "tuple[Dict[str, object], Dict[str, str]]":
    """Apply a field-level data-minimization policy to *record*.

    *policy* maps field names to an action: ``drop`` removes the field,
    ``hash`` replaces the value with a SHA-256 digest (correlatable, not
    readable), ``redact`` runs :func:`redact_text` over string values, and
    ``keep`` passes through. ``truncate:N`` keeps the first N characters.
    Unknown actions are treated as ``keep``. Returns
    ``(minimized_record, actions_applied)`` — applied actions only, so callers
    can record what happened (never the values) alongside the row.
    """
    import hashlib

    out: Dict[str, object] = {}
    applied: Dict[str, str] = {}
    for field, value in record.items():
        action = policy.get(field, default) or default
        if action == "drop":
            applied[field] = "drop"
            continue
        if action == "hash":
            digest = hashlib.sha256(
                str(value).encode("utf-8", "ignore")
            ).hexdigest()
            out[field] = f"sha256:{digest}"
            applied[field] = "hash"
            continue
        if action == "redact" and isinstance(value, str):
            redacted, counts = redact_text(value)
            out[field] = redacted
            if counts:
                applied[field] = "redact"
            continue
        if action.startswith("truncate:") and isinstance(value, str):
            try:
                n = max(0, int(action.split(":", 1)[1]))
            except ValueError:
                n = len(value)
            if len(value) > n:
                out[field] = value[:n]
                applied[field] = action
            else:
                out[field] = value
            continue
        out[field] = value
    return out, applied
