"""Agent Skill supply-chain scan (``artzain skills scan``).

An Agent Skill is a folder: a ``SKILL.md`` and the files beside it. An agent
that loads the skill follows what it says, so a step written there is a step
the agent takes with the user's access. This module reads a skill folder,
offline, and lists what a reviewer should see before the skill is installed
or after it changed:

``skill.drift``
    A file changed, was added or was removed since the baseline a reviewer
    accepted (``--write-baseline``, ``--baseline``).
``skill.fetch_and_run``
    A code block or bundled shell script that downloads something and runs
    it, or prose that says to.
``skill.risky_command``
    A code block that matches another destructive-action rule
    (:mod:`artzain.destructive_action_guard`), named in the finding.
``skill.external_url``
    A host the skill names, once per host, unless ``--allow-host`` lists it.
``skill.signin_handoff``
    A line that sends the user to sign in, asks for a password, key or code,
    or hands the work off to a portal.
``skill.concealed_step``
    A line that says to skip a confirmation, hide a step, or not mention it.
``skill.hidden_markup``
    An HTML or Markdown comment, or characters that do not show: text a
    reviewer reading the rendered page does not see and the agent does.
``skill.binary_file``, ``skill.unread_file``, ``skill.symlink``
    A file that was fingerprinted but not read.

The rules are patterns over text. They list what a skill says, with the file
and line, for a person to judge; a finding is not a verdict on the skill, and
a skill with no findings has not been shown to be safe. Nothing is fetched,
run or sent anywhere.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

__all__ = [
    "BASELINE_FORMAT",
    "MAX_FILES",
    "MAX_TEXT_BYTES",
    "REPORT_FORMAT",
    "SkillFinding",
    "SkillScan",
    "SkillScanError",
    "baseline_of",
    "report_of",
    "scan_path",
]

BASELINE_FORMAT = "artzain-skill-baseline-v1"
REPORT_FORMAT = "artzain-skill-scan-v1"

#: A text file past this size is fingerprinted and named, not read.
MAX_TEXT_BYTES = 2 * 1024 * 1024
#: Files one skill is read for. Past it the scan stops with an error.
MAX_FILES = 2000
#: How far below the scanned folder a ``SKILL.md`` is looked for.
_MAX_SKILL_DEPTH = 4

_SKIPPED_DIRS = frozenset({".git", "node_modules", "__pycache__"})
_PROSE_SUFFIXES = frozenset({".md", ".markdown", ".mdx", ".txt", ".rst", ""})
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh", ".ps1", ".bat", ".cmd"})
_SHEBANG_SHELL_RE = re.compile(r"#!\s*\S*(?:sh|bash|zsh|ksh|pwsh)\b")


class SkillScanError(Exception):
    """The path could not be scanned at all."""


@dataclass(frozen=True)
class SkillFinding:
    """One finding. ``rule_id`` is stable; ``line`` is None for a finding
    about a whole file."""

    rule_id: str
    path: str
    line: Optional[int]
    detail: str

    def key(self) -> list[Any]:
        return [self.rule_id, self.path, self.line, self.detail]


@dataclass
class SkillScan:
    """One skill: its files' digests, its fingerprint and its findings."""

    root: str
    name: str
    files: dict[str, str] = field(default_factory=dict)
    fingerprint: str = ""
    findings: list[SkillFinding] = field(default_factory=list)
    accepted: int = 0


# -- what the rules look for -----------------------------------------------------

_FETCH_RE = re.compile(
    r"(?i)(?:^|[\s;&|(])(curl|wget|aria2c|invoke-webrequest|iwr|invoke-restmethod|irm|"
    r"start-bitstransfer|git\s+clone|scp)(?=\s)")
_PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|python3?|node|pwsh|powershell|iex|"
    r"invoke-expression)\b")
_EXPRESSION_OF_FETCH_RE = re.compile(
    r"(?i)\b(?:iex|invoke-expression|eval|source)\b[^\n]{0,40}"
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b")
_INSTALL_URL_RE = re.compile(
    r"(?i)(?:^|[\s;&|(])(?:pip3?|pipx|uv|uvx|npm|npx|pnpm|yarn|bunx?|gem|cargo|go)\s"
    r"[^\n|;&]{0,200}?(?:https?|git\+https?|git\+ssh|ssh)://")
_RUN_RE = re.compile(
    r"(?i)(?:^|[\s;&|(])(?:\./\S|(?:sh|bash|zsh|ksh|python3?|node|pwsh|powershell)\s+\S|"
    r"chmod\s+\+x\s|start-process\s|source\s+\S)")
_PROSE_FETCH_RUN_RE = re.compile(
    r"(?i)\b(?:download|fetch|clone|pull\s+down|curl|wget)\b[^.\n]{0,120}?"
    r"\b(?:run|execute|launch|install|installer|invoke)\b")

_SECRET_WORDS = (r"(?:password|passcode|passphrase|credentials?|api[ -]?key|access[ -]?key|"
                 r"tokens?|verification\s+code|one[- ]time\s+(?:code|password)|otp|"
                 r"(?:2fa|mfa)\s+code|recovery\s+(?:code|phrase)|seed\s+phrase|secret)")
_SIGNIN_RES = tuple(re.compile(p, re.IGNORECASE) for p in (
    # The verb, two words: "login" and "sign-in" as nouns are not a step.
    r"\b(?:sign|log) in (?:at|to|on|with|using|via|through|here)\b",
    r"\b(?:ask|have|tell|prompt|direct|instruct|send|get)\b[^.\n]{0,30}?\buser\b[^.\n]{0,30}?"
    r"\b(?:sign|log) in\b",
    r"\buser (?:must|should|needs to|has to|will need to) (?:sign|log) in\b",
    r"\bauthenticate\s+(?:with|using)\s+(?:the\s+user'?s?|their|your)\b",
    r"\b(?:enter|paste|submit|type\s+in)\b[^.\n]{0,60}?\b" + _SECRET_WORDS + r"\b",
    r"\bhand(?:s|ed|ing)?[ -]?off\s+to\s+[^.\n]{0,40}?"
    r"\b(?:portal|site|website|page|link|url|service|operator|support)\b",
))

_CONCEALED_RES = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t)\s+"
    r"(?:tell|mention|inform|notify|alert|warn)\s+"
    r"(?:(?:the\s+user|them|anyone)(?!\s+to\b)|this|that|it|about|the\s+(?:step|upload|"
    r"command|call|sync|change|action)\b)",
    r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:reveal|disclose)\s+"
    r"(?:this|these|that|the\s+(?:instructions?|steps?|commands?|prompt))\b",
    r"\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:log|record|report|show|include|display)\s+"
    r"(?:this|that|it|the\s+(?:step|call|command|action|upload|output))\b",
    r"\b(?:run|execute|do|perform|send|upload|install|apply|proceed|continue|call|make|add|"
    r"write|delete|commit|push)\b[^.,;:\n]{0,30}?\b(?:silently|quietly)\b",
    r"\bwithout\s+(?:asking|telling|informing|notifying|mentioning|prompting|confirm\w*|"
    r"approval|permission|consent|the\s+user'?s?\s+(?:knowledge|knowing|approval|consent|"
    r"permission))\b",
    r"\bskip\s+(?:the\s+|any\s+|all\s+)?(?:confirmation|approval|review|verification|"
    r"permission|consent|safety|security)\b",
    r"\b(?:omit|exclude|leave\s+out)\b[^.\n]{0,60}?\bfrom\s+(?:the\s+|your\s+)?(?:final\s+)?"
    r"(?:summary|report|reply|response|output|answer|log|transcript)\b",
    r"\bleave\s+(?:it|this|that|them|these)\s+out\s+of\s+(?:the\s+|your\s+)?(?:final\s+)?"
    r"(?:summary|report|reply|response|output|answer|log|transcript)\b",
    r"\bhide\b[^.\n]{0,60}?\b(?:from|step|output|command|call|action)\b",
))

_URL_RE = re.compile(
    r"(?i)(?<![a-z0-9+.-])(?:https?|wss?|s?ftp|ssh|git(?:\+ssh|\+https?)?)://"
    r"([^\s/?#\"'<>`)\]]+)")
_HOST_RE = re.compile(r"[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?")

#: Characters a rendered page does not show: zero width, soft hyphen, word
#: joiner and invisible operators, direction marks and overrides, tags.
_INVISIBLE = frozenset(
    [0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063,
     0x2064, 0xFEFF]
    + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
    + list(range(0xE0000, 0xE0080)))


def _html_comments(text: str) -> Iterator[tuple[int, str]]:
    """Each ``<!-- ... -->`` as (offset, body), left to right in one pass."""
    start = 0
    while True:
        opener = text.find("<!--", start)
        if opener < 0:
            return
        closer = text.find("-->", opener + 4)
        if closer < 0:
            return
        yield opener, text[opener + 4:closer]
        start = closer + 3


def _markdown_comments(text: str) -> Iterator[tuple[int, str]]:
    """Each ``[//]: # (...)`` as (offset, body), left to right in one pass."""
    start = 0
    length = len(text)
    while True:
        opener = text.find("[//]:", start)
        if opener < 0:
            return
        at = opener + 5
        while at < length and text[at] in " \t":
            at += 1
        if at < length and text[at] == "#":
            at += 1
            while at < length and text[at] in " \t":
                at += 1
            if at < length and text[at] == "(":
                closer = text.find(")", at + 1)
                if closer < 0:
                    return
                yield opener, text[at + 1:closer]
                start = closer + 1
                continue
        start = opener + 1


def _host_allowed(host: str, allow_hosts: Sequence[str]) -> bool:
    for glob in allow_hosts:
        text = glob.strip().lower().rstrip(".")
        if text == "*" or text == host or (text.startswith("*.") and host.endswith(text[1:])):
            return True
    return False


def _hosts(line: str) -> Iterator[str]:
    for match in _URL_RE.finditer(line):
        authority = match.group(1).rsplit("@", 1)[-1]
        if authority.startswith("["):
            host = authority.split("]", 1)[0] + "]"
        else:
            host = authority.split(":", 1)[0]
        host = host.lower().rstrip(".,;:!?*_~")
        if host and (host.startswith("[") or _HOST_RE.fullmatch(host)):
            yield host


def _code_blocks(lines: list[str]) -> Iterator[tuple[int, list[str]]]:
    """Fenced code blocks of a Markdown file: (line number of the first
    line inside, the lines inside). A fence left open runs to the end."""
    fence = ""
    start = 0
    block: list[str] = []
    for number, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if not fence:
            if stripped.startswith("```") or stripped.startswith("~~~"):
                fence = stripped[:3]
                start = number + 1
                block = []
        elif stripped.startswith(fence):
            yield start, block
            fence = ""
        else:
            block.append(line)
    if fence and block:
        yield start, block


def _block_findings(path: str, start: int, block: list[str]) -> list[SkillFinding]:
    found: list[SkillFinding] = []
    fetched: Optional[tuple[int, str]] = None
    run_line: Optional[int] = None
    for offset, line in enumerate(block):
        number = start + offset
        if _INSTALL_URL_RE.search(line):
            found.append(SkillFinding(
                "skill.fetch_and_run", path, number,
                "installs from a URL, which downloads code and runs it"))
            continue
        fetch = _FETCH_RE.search(line)
        if fetch and (_PIPE_TO_SHELL_RE.search(line) or _EXPRESSION_OF_FETCH_RE.search(line)):
            found.append(SkillFinding(
                "skill.fetch_and_run", path, number,
                "downloads and runs in one command"))
            continue
        if _EXPRESSION_OF_FETCH_RE.search(line):
            found.append(SkillFinding(
                "skill.fetch_and_run", path, number,
                "downloads and runs in one command"))
            continue
        if fetch and fetched is None:
            fetched = (number, re.sub(r"\s+", " ", fetch.group(1).lower()))
        if fetched is not None and run_line is None and _RUN_RE.search(
                line if fetch is None else line[fetch.end():]):
            run_line = number
    if fetched is not None and run_line is not None:
        found.append(SkillFinding(
            "skill.fetch_and_run", path, fetched[0],
            f"downloads with {fetched[1]} and then runs a command (line {run_line})"))
    try:
        from artzain.destructive_action_guard import screen_action

        matches = screen_action("\n".join(block)).matches
    except Exception:  # noqa: BLE001 - the guard is a second reading, not the scan
        matches = []
    for match in matches:
        if match.rule_id == "exec.fetch_and_run":
            if not any(f.rule_id == "skill.fetch_and_run" for f in found):
                found.append(SkillFinding(
                    "skill.fetch_and_run", path, start,
                    "downloads something and runs it (destructive-action rule "
                    "exec.fetch_and_run)"))
        else:
            found.append(SkillFinding(
                "skill.risky_command", path, start,
                f"matches the destructive-action rule {match.rule_id} ({match.name})"))
    return found


def _line_of(starts: list[int], offset: int) -> int:
    return bisect.bisect_right(starts, offset)


def _prose_findings(path: str, text: str, lines: list[str]) -> list[SkillFinding]:
    found: list[SkillFinding] = []
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    for offset, body in _html_comments(text):
        if body.strip():
            found.append(SkillFinding(
                "skill.hidden_markup", path, _line_of(starts, offset),
                "an HTML comment, which a rendered page does not show"))
    for offset, body in _markdown_comments(text):
        if body.strip():
            found.append(SkillFinding(
                "skill.hidden_markup", path, _line_of(starts, offset),
                "a Markdown comment, which a rendered page does not show"))
    for number, line in enumerate(lines, start=1):
        hidden = [ord(ch) for ch in line if ord(ch) in _INVISIBLE]
        if number == 1 and hidden[:1] == [0xFEFF] and line.startswith("﻿"):
            hidden = hidden[1:]  # a byte order mark opens the file
        if hidden:
            names = ", ".join(f"U+{code:04X}" for code in sorted(set(hidden)))
            count = len(hidden)
            found.append(SkillFinding(
                "skill.hidden_markup", path, number,
                f"{count} character{'s' if count != 1 else ''} that do not show ({names})"))
        if any(pattern.search(line) for pattern in _SIGNIN_RES):
            found.append(SkillFinding(
                "skill.signin_handoff", path, number,
                "sends the user to sign in, asks for a secret, or hands off to a portal"))
        if any(pattern.search(line) for pattern in _CONCEALED_RES):
            found.append(SkillFinding(
                "skill.concealed_step", path, number,
                "says to skip, hide or not mention a step"))
    return found


def _prose_fetch_run(path: str, lines: list[str], in_code: set[int]) -> list[SkillFinding]:
    return [
        SkillFinding("skill.fetch_and_run", path, number,
                     "says to download something and run it")
        for number, line in enumerate(lines, start=1)
        if number not in in_code and _PROSE_FETCH_RUN_RE.search(line)
    ]


# -- reading a folder ----------------------------------------------------------


def _skill_roots(path: Path) -> list[Path]:
    def has_skill(folder: Path) -> bool:
        try:
            return any(entry.is_file() and entry.name.lower() == "skill.md"
                       for entry in folder.iterdir())
        except OSError:
            return False

    if has_skill(path):
        return [path]
    roots: list[Path] = []
    stack = [(path, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            children = sorted(p for p in folder.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            continue
        for child in children:
            if child.name in _SKIPPED_DIRS:
                continue
            if has_skill(child):
                roots.append(child)
            elif depth + 1 < _MAX_SKILL_DEPTH:
                stack.append((child, depth + 1))
    return sorted(roots)


def _files(root: Path) -> list[Path]:
    found: list[Path] = []
    for folder, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIPPED_DIRS)
        for name in sorted(names):
            found.append(Path(folder) / name)
            if len(found) > MAX_FILES:
                raise SkillScanError(
                    f"{root} holds more than {MAX_FILES} files; scan a smaller folder")
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def _skill_name(text: str, fallback: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        for line in lines[1:40]:
            if line.strip() == "---":
                break
            key, _, value = line.partition(":")
            if key.strip().lower() == "name" and value.strip():
                return value.strip().strip("\"'")[:120]
    return fallback


def _scan_skill(root: Path, shown_root: str, allow_hosts: Sequence[str]) -> SkillScan:
    scan = SkillScan(root=shown_root, name=root.name)
    hosts_seen: set[str] = set()
    for file in _files(root):
        rel = file.relative_to(root).as_posix()
        if file.is_symlink():
            scan.files[rel] = "symlink"
            scan.findings.append(SkillFinding(
                "skill.symlink", rel, None, "is a link and was not followed"))
            continue
        try:
            data = file.read_bytes()
        except OSError as exc:
            raise SkillScanError(f"{file} could not be read: {exc.strerror or exc}") from exc
        scan.files[rel] = hashlib.sha256(data).hexdigest()
        if len(data) > MAX_TEXT_BYTES:
            scan.findings.append(SkillFinding(
                "skill.unread_file", rel, None,
                f"is larger than {MAX_TEXT_BYTES} bytes and was not read"))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
            binary = True
        else:
            binary = "\x00" in text
        if binary:
            scan.findings.append(SkillFinding(
                "skill.binary_file", rel, None, "is not text and was not read"))
            continue
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        suffix = file.suffix.lower()
        if file.name.lower() == "skill.md":
            scan.name = _skill_name(text, root.name)
        if suffix in _PROSE_SUFFIXES:
            in_code: set[int] = set()
            for start, block in _code_blocks(lines):
                in_code.update(range(start, start + len(block)))
                scan.findings.extend(_block_findings(rel, start, block))
            scan.findings.extend(_prose_fetch_run(rel, lines, in_code))
            scan.findings.extend(_prose_findings(rel, text, lines))
        elif suffix in _SHELL_SUFFIXES or _SHEBANG_SHELL_RE.match(lines[0] if lines else ""):
            scan.findings.extend(_block_findings(rel, 1, lines))
        for number, line in enumerate(lines, start=1):
            for host in _hosts(line):
                if host not in hosts_seen and not _host_allowed(host, allow_hosts):
                    hosts_seen.add(host)
                    scan.findings.append(SkillFinding(
                        "skill.external_url", rel, number, f"names the host {host}"))
    pairs = sorted(scan.files.items())
    scan.fingerprint = hashlib.sha256(
        json.dumps(pairs, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    scan.findings = list(dict.fromkeys(scan.findings))
    scan.findings.sort(key=lambda f: (f.path, f.line or 0, f.rule_id, f.detail))
    return scan


def _apply_baseline(scan: SkillScan, baseline: dict[str, Any]) -> None:
    entry = (baseline.get("skills") or {}).get(scan.root)
    if not isinstance(entry, dict) or not isinstance(entry.get("files"), dict):
        scan.findings.insert(0, SkillFinding(
            "skill.drift", "SKILL.md", None, "this skill is not in the accepted baseline"))
        return
    accepted = {json.dumps(item) for item in entry.get("accepted") or []}
    kept = [f for f in scan.findings if json.dumps(f.key()) not in accepted]
    scan.accepted = len(scan.findings) - len(kept)
    old: dict[str, str] = entry["files"]
    drift: list[SkillFinding] = []
    for rel in sorted(set(old) | set(scan.files)):
        if rel not in old:
            drift.append(SkillFinding("skill.drift", rel, None,
                                      "added since the accepted baseline"))
        elif rel not in scan.files:
            drift.append(SkillFinding("skill.drift", rel, None,
                                      "removed since the accepted baseline"))
        elif old[rel] != scan.files[rel]:
            drift.append(SkillFinding("skill.drift", rel, None,
                                      "changed since the accepted baseline"))
    scan.findings = sorted([*kept, *drift],
                           key=lambda f: (f.path, f.line or 0, f.rule_id, f.detail))


def scan_path(path: Any, *, baseline: Optional[dict[str, Any]] = None,
              allow_hosts: Iterable[str] = ()) -> list[SkillScan]:
    """Scan the skill at *path*, or each skill below it.

    *baseline* is what :func:`baseline_of` returned for a scan of the same
    path that a reviewer accepted: a file that differs from it is
    ``skill.drift``, and a finding the reviewer accepted with it is not
    listed again while its file is unchanged. Raises :class:`SkillScanError`
    when there is nothing to scan.
    """
    root = Path(path)
    if not root.is_dir():
        raise SkillScanError(f"{root} is not a folder")
    if baseline is not None and (not isinstance(baseline, dict)
                                 or baseline.get("format") != BASELINE_FORMAT):
        raise SkillScanError(f"the baseline is not an artzain skill baseline ({BASELINE_FORMAT})")
    roots = _skill_roots(root)
    if not roots:
        raise SkillScanError(f"no SKILL.md in {root} or the folders below it")
    allowed = [str(h) for h in allow_hosts]
    scans = []
    for skill_root in roots:
        shown = "." if skill_root == root else skill_root.relative_to(root).as_posix()
        scan = _scan_skill(skill_root, shown, allowed)
        if baseline is not None:
            _apply_baseline(scan, baseline)
        scans.append(scan)
    return scans


def baseline_of(scans: Sequence[SkillScan]) -> dict[str, Any]:
    """The baseline that accepts *scans* as they are: each file's digest, and
    the findings a reviewer accepted with them."""
    return {
        "format": BASELINE_FORMAT,
        "skills": {
            scan.root: {
                "name": scan.name,
                "fingerprint": scan.fingerprint,
                "files": dict(sorted(scan.files.items())),
                "accepted": [f.key() for f in scan.findings if f.rule_id != "skill.drift"],
            }
            for scan in scans
        },
    }


def report_of(path: Any, scans: Sequence[SkillScan]) -> dict[str, Any]:
    """The ``--json`` report."""
    return {
        "format": REPORT_FORMAT,
        "path": str(path),
        "findings": sum(len(scan.findings) for scan in scans),
        "skills": [
            {
                "root": scan.root,
                "name": scan.name,
                "fingerprint": scan.fingerprint,
                "files": dict(sorted(scan.files.items())),
                "accepted": scan.accepted,
                "findings": [
                    {"rule_id": f.rule_id, "path": f.path, "line": f.line, "detail": f.detail}
                    for f in scan.findings
                ],
            }
            for scan in scans
        ],
    }
