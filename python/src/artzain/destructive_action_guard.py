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
  external dependencies. The SQL rules add a linear-time walk over keyword
  chains, so a comment between two keywords reads as the separator it is to
  a SQL engine (see "SQL statements" below).
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
from bisect import bisect_left
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from itertools import chain
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


def _to_first(argument: str, command: str) -> str:
    """Regex that skips ahead to where *argument* or another *command* first starts.

    Consumes the rest of the shell segment (no newline, ``;``, ``|`` or ``&``)
    up to the first position where *argument* or *command* matches. The caller
    matches *argument* next, which fails when *command* came first. The scan is
    a lazy single-character repeat inside a lookahead; Python does not backtrack
    into a lookahead once it has matched, so the backreference consumes exactly
    the stretch the scan found. The named group ``gap`` is part of the pattern:
    the guard reads only a match's span, but ``findall`` or ``split`` on these
    patterns would return the group.

    These rules used to scan the rest of the segment again from every repeat
    of the command, which took time quadratic in the length of the text.
    Stopping at the next repeat keeps the scan linear and matches the same
    strings: that repeat reaches every argument the earlier one would have,
    provided a *command* match cannot cover the first character of the
    argument. That holds for every ``_command_with`` rule; git.reset_hard
    handles its one exception. The match can now start at a later repeat.
    Repeating a group that checks for *command* before each character would
    also be linear, but Python keeps a backtracking frame for every repetition.
    """
    return r"(?=(?P<gap>[^\n;|&]*?)(?:" + argument + r"|" + command + r"))(?P=gap)"


def _command_with(command: str, argument: str) -> str:
    """Regex for *command* followed, later in the same shell segment, by *argument*."""
    return command + _to_first(argument, command) + argument


#: The rest of the segment up to its last `--hard`, so git.reset_hard's match
#: ends where the old greedy scan's did.
_LAST_HARD = r"(?:[^\n;|&]*\s--hard\b)?"


@dataclass(frozen=True)
class _ActionRule:
    """One destructive-action regex with a severity and human-readable name."""

    rule_id: str
    name: str
    severity: ActionSeverity
    pattern: re.Pattern[str] | _SqlPattern
    owasp: str = "LLM06"
    #: Named group the finding's excerpt starts at (with the usual context
    #: either side), for a pattern whose match starts well before what it found
    #: (the ``rm`` rules match from the start of the command). ``None``: the
    #: whole match.
    excerpt_group: str | None = None


# ---------------------------------------------------------------------------
# SQL statements
# ---------------------------------------------------------------------------
#
# SQL engines read a comment as a token separator, so the SQL rules accept a
# comment wherever they accept whitespace: `DROP/**/TABLE`, `DELETE -- x` and
# a newline before `FROM`. One regex cannot do that in linear time. A comment
# can hold the next keyword, and a search restarts at every keyword inside
# it, so `DROP /* DROP /* DROP ...` would be rescanned from each one. The SQL
# rules therefore walk keyword chains over indexes built once per scan window
# (sorted delimiter positions; memoized gap, name and quote ends). Every
# keyword is judged on its own, so a comment opener inside a string literal
# (`SELECT '/*'`) cannot hide the statement after it.
#
# A gap between two keywords is whitespace and comments. Engines disagree on
# what a comment is, so each gap is read three ways, and any reading that
# reaches the next keyword counts:
#
# * MySQL and MariaDB: a block comment ends at the first `*/`, a line comment
#   (`--` or `#`) at `\n`. `/*!50000` and `/*M!100100` open an executable
#   comment whose body is code, so they and the `*/` that closes one read as
#   whitespace.
# * SQLite: the same, except that `/*!...*/` is an ordinary comment.
# * PostgreSQL and SQL Server: block comments nest, and a line comment also
#   ends at `\r`.
#
# `#` starts a line comment in all three readings. Only MySQL has such
# comments, but an extra reading can only add matches. Where a table name is
# expected, `#` is also read as the start of the name, since `#staging` names
# a SQL Server temporary table.

_SQL_STATEMENT_KEYWORDS = (
    r"SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE"
)
_SQL_MYSQL, _SQL_SQLITE, _SQL_NESTED = range(3)
# Whitespace, with the openers of MySQL executable comments. Their digits are
# taken whole, so a pattern cannot end the gap inside them. The `*/` that
# closes such a comment is accepted only by the walk, which can see the opener.
_SQL_EXECUTABLE_GAP = r"(?:(?:\s*/\*(?-i:M)?![0-9]*(?![0-9]))+\s*|\s+)"
_SQL_EXECUTABLE_GAP_RE = re.compile(_SQL_EXECUTABLE_GAP)
_SQL_SPACE_RE = re.compile(r"\s+")
_SQL_QUOTE_CLOSERS = {"\"": "\"", "`": "`", "[": "]"}
# A plain identifier in quotes, the only quoted name that may be glued to its
# keyword: `"Run TRUNCATE", "table"` is the end of one string and the start
# of the next, not TRUNCATE and a name.
_SQL_IDENTIFIER = r"[A-Za-z_#@][\w#@$]*"
_SQL_GLUED_NAME = re.compile(
    r"\"" + _SQL_IDENTIFIER + r"\"|`" + _SQL_IDENTIFIER + r"`|\[" + _SQL_IDENTIFIER + r"\]"
)
_SQL_BARE_NAME = re.compile(r"[\w#@$]+")
_SQL_WORD = re.compile(r"\w+")
# Where a no-WHERE rule stops looking for WHERE: a statement terminator, a
# comment start, or a line break before a line that begins another statement.
_SQL_STOP = re.compile(
    r";|-(?=-)|/(?=\*)|\n(?=[^\S\n]*(?:" + _SQL_STATEMENT_KEYWORDS + r")\b)",
    re.IGNORECASE,
)
_SQL_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
_SQL_EXECUTABLE_OPENER = re.compile(r"/\*M?![0-9]*")
_SQL_TERMINATOR = re.compile(r";|--|/\*|$", re.MULTILINE)


def _sql_keyword(word: str) -> str:
    """*word* after a word boundary or a MySQL / MariaDB executable-comment opener.

    The literal comes first so a search keeps its fast literal prefix; the
    boundary is checked behind it, once for each length of the version.
    """
    openers = "".join(
        r"|(?<=/\*" + marker + "![0-9]{" + str(digits) + "}" + word + ")"
        for marker in ("", "(?-i:M)")
        for digits in range(1, 7)
    )
    return word + r"(?:(?<=\b" + word + ")" + openers + ")"


def _has_sql_comment(text: str) -> bool:
    return "/*" in text or "--" in text or "#" in text


def _positions(text: str, needle: str) -> list[int]:
    found, i = [], text.find(needle)
    while i != -1:
        found.append(i)
        i = text.find(needle, i + 1)
    return found


def _next_position(positions: list[int], at: int) -> int | None:
    i = bisect_left(positions, at)
    return positions[i] if i < len(positions) else None


class _SqlMatch:
    """The span a SQL rule matched; stands in for :class:`re.Match`."""

    __slots__ = ("_start", "_end")

    def __init__(self, start: int, end: int) -> None:
        self._start, self._end = start, end

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end


class _SqlWindow:
    """Indexes over one scan window, built on demand and shared by the SQL rules."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._indexes: dict[str, list[int]] = {}
        self._breaks: list[int] | None = None
        self._nested: dict[int, int | None] = {}
        self._gaps: dict[tuple[int, bool], dict[int, tuple[int, bool]]] = {
            (reading, hashes): {}
            for reading in (_SQL_MYSQL, _SQL_SQLITE, _SQL_NESTED)
            for hashes in (False, True)
        }
        self._gap_maps: dict[str, dict[int, int]] = {}
        self._has_hash: bool | None = None
        self._names: dict[int, int | None] = {}
        self._quote_ends: dict[tuple[str, int], int | None] = {}
        self._line_comments: list[int] | None = None
        self._escapes: dict[int, bool] = {}
        self._string_ends: dict[tuple[str, bool, int], int | None] = {}
        self._body_starts: list[int] | None = None
        self._executable_closes: dict[bool, dict[int, int | None]] = {True: {}, False: {}}
        self._executable_closers: set[int] | None = None
        self._wheres: list[int] | None = None
        self._stops: list[int] | None = None

    def _index(self, needle: str) -> list[int]:
        found = self._indexes.get(needle)
        if found is None:
            found = self._indexes[needle] = _positions(self.text, needle)
        return found

    def _line_break(self, pos: int, nested: bool) -> int | None:
        if not nested:
            return _next_position(self._index("\n"), pos)
        if self._breaks is None:
            self._breaks = sorted(self._index("\n") + self._index("\r"))
        return _next_position(self._breaks, pos)

    def _nested_end(self, pos: int) -> int | None:
        """End of the nesting block comment opened at *pos*; None if unclosed."""
        memo = self._nested
        if pos in memo:
            return memo[pos]
        closes, opens = self._index("*/"), self._index("/*")
        stack, at, ci, oi = [pos], pos + 2, 0, 0
        while stack:
            # *at* only grows, so each search resumes where the last one ended.
            ci = bisect_left(closes, at, ci)
            oi = bisect_left(opens, at, oi)
            close = closes[ci] if ci < len(closes) else None
            opener = opens[oi] if oi < len(opens) else None
            if close is not None and (opener is None or close < opener):
                at = close + 2
                memo[stack.pop()] = at
                continue
            inner = memo.get(opener, 0) if close is not None else None
            if inner is None:
                for p in stack:
                    memo[p] = None
                return None
            if inner:
                at = inner
            else:
                stack.append(opener)
                at = opener + 2
        return memo[pos]

    def _mysql_line_comments(self) -> list[int]:
        """Starts of MySQL line comments: `#`, and `--` before a space, a control character or the end."""
        if self._line_comments is None:
            text = self.text
            dashes = [
                i for i in self._index("--")
                if text[i + 2 : i + 3] <= " " or text[i + 2] == "\x7f"
            ]
            self._line_comments = sorted(dashes + self._index("#"))
        return self._line_comments

    def _escaped(self, pos: int) -> bool:
        """True when an odd run of backslashes ends right before *pos*."""
        found = self._escapes.get(pos)
        if found is None:
            start = pos
            while start and self.text[start - 1] == "\\":
                start -= 1
            found = self._escapes[pos] = (pos - start) % 2 == 1
        return found

    def _string_end(self, pos: int, backslashes: bool) -> int | None:
        """End of the string or identifier quoted at *pos* in an executable body.

        A doubled quote stands for one; with *backslashes* (MySQL's default
        mode), a backslash also escapes a string quote, though not a backtick.
        Ends are memoized by search position.
        """
        text = self.text
        quote = text[pos]
        escapes = backslashes and quote != "`"
        positions, memo = self._index(quote), self._string_ends
        path, at = [], pos + 1
        while True:
            key = (quote, escapes, at)
            if key in memo:
                end = memo[key]
                break
            path.append(key)
            close = _next_position(positions, at)
            if close is None:
                end = None
                break
            if escapes and self._escaped(close):
                at = close + 1
            elif text.startswith(quote, close + 1):
                at = close + 2
            else:
                end = close + 1
                break
        for key in path:
            memo[key] = end
        return end

    def _executable_close(self, pos: int, backslashes: bool) -> int | None:
        """The `*/` that closes the executable comment whose body continues at *pos*.

        MySQL reads the body as SQL, so a `*/` inside a line comment, a block
        comment, a string or a quoted identifier does not end it. Results are
        memoized by body position, so overlapping bodies are read once.
        """
        memo, path = self._executable_closes[backslashes], []
        closes = self._index("*/")
        if self._body_starts is None:
            self._body_starts = sorted(
                self._index("/*") + self._mysql_line_comments()
                + self._index("'") + self._index("\"") + self._index("`")
            )
        while True:
            if pos in memo:
                end = memo[pos]
                break
            path.append(pos)
            close = _next_position(closes, pos)
            if close is None:
                end = None
                break
            first = _next_position(self._body_starts, pos)
            if first is None or first > close:
                end = close
                break
            if self.text.startswith("/*", first):
                inner = _next_position(closes, first + 2)
                resume = None if inner is None else inner + 2
            elif self.text[first] in "'\"`":
                resume = self._string_end(first, backslashes)
            else:
                brk = _next_position(self._index("\n"), first)
                resume = None if brk is None else brk + 1
            if resume is None:
                end = None
                break
            pos = resume
        for p in path:
            memo[p] = end
        return end

    def _closes_executable(self, pos: int) -> bool:
        """True when the `*/` at *pos* closes a MySQL executable comment.

        Either escape mode counts: with or without backslash escapes.
        """
        if self._executable_closers is None:
            closers = set()
            modes = (False, True) if "\\" in self.text else (False,)
            for m in _SQL_EXECUTABLE_OPENER.finditer(self.text):
                for backslashes in modes:
                    close = self._executable_close(m.end(), backslashes)
                    if close is not None:
                        closers.add(close)
            self._executable_closers = closers
        return pos in self._executable_closers

    def _walk_gap(self, pos: int, reading: int, hashes: bool) -> tuple[int, bool]:
        """``(end, another reading may end elsewhere)`` for the gap at *pos*.

        The flag is meaningful for the MySQL reading. It is set wherever the
        other two readings read an item differently, except at the close of an
        executable comment, where they stop and no keyword can start. Every
        item boundary on the way is memoized, so a run of comments that
        follows many keywords is walked once.
        """
        memo = self._gaps[(reading, hashes)]
        text, path = self.text, []
        while True:
            known = memo.get(pos)
            if known is not None:
                end, differs = known
                break
            item_differs, nxt = False, None
            space = (
                _SQL_EXECUTABLE_GAP_RE if reading == _SQL_MYSQL else _SQL_SPACE_RE
            ).match(text, pos)
            if space:
                nxt = space.end()
                item_differs = text.find("/*", pos, nxt) != -1
            elif text.startswith("*/", pos):
                # The other readings stop here, where no keyword can start.
                if reading == _SQL_MYSQL and self._closes_executable(pos):
                    nxt = pos + 2
            elif text.startswith("/*", pos):
                close = _next_position(self._index("*/"), pos + 2)
                if close is not None and reading == _SQL_NESTED:
                    nxt = self._nested_end(pos)
                elif close is not None:
                    nxt = close + 2
                    inner = _next_position(self._index("/*"), pos + 2)
                    item_differs = inner is not None and inner < close
            elif text.startswith("--", pos) or (hashes and text.startswith("#", pos)):
                brk = self._line_break(pos, reading == _SQL_NESTED)
                ret = _next_position(self._index("\r"), pos)
                item_differs = ret is not None and (brk is None or ret < brk)
                nxt = None if brk is None else brk + 1
            if nxt is None:
                end, differs = pos, item_differs
                memo[pos] = (end, differs)
                break
            path.append((pos, item_differs))
            pos = nxt
        for p, item_differs in reversed(path):
            differs = differs or item_differs
            memo[p] = (end, differs)
        return end, differs

    def gap_ends(self, pos: int, hashes: bool) -> list[int]:
        """Where the gap at *pos* ends in each reading, without repeats."""
        end, differs = self._walk_gap(pos, _SQL_MYSQL, hashes)
        if not differs:
            return [end]
        others = {self._walk_gap(pos, reading, hashes)[0] for reading in (_SQL_SQLITE, _SQL_NESTED)}
        return sorted(others | {end})

    def name_gap_ends(self, pos: int) -> list[int]:
        """Where the gap before a table name ends, with `#` read both ways.

        To MySQL `#` starts a comment; to SQL Server `#staging` is a table.
        """
        if self._has_hash is None:
            self._has_hash = "#" in self.text
        if not self._has_hash:
            return self.gap_ends(pos, False)
        return sorted(set(self.gap_ends(pos, False) + self.gap_ends(pos, True)))

    def gap_map(self, pattern: _SqlPattern) -> dict[int, int]:
        """``{gap end: keyword start}`` over every non-empty gap after the keyword."""
        found = self._gap_maps.get(pattern.keyword)
        if found is None:
            found = {}
            for m in pattern.keyword_re.finditer(self.text):
                start, end = m.span()
                for gap in self.gap_ends(end, True):
                    if gap > end:
                        found.setdefault(gap, start)
            self._gap_maps[pattern.keyword] = found
        return found

    def quote_end(self, pos: int) -> int | None:
        """End of the quoted name part opened at *pos*; None if it never closes.

        A doubled closing quote stands for one. Ends are memoized by search
        position, so parts that share a closing quote are searched once.
        """
        text = self.text
        closer = _SQL_QUOTE_CLOSERS[text[pos]]
        positions, memo = self._index(closer), self._quote_ends
        path, at = [], pos + 1
        while True:
            key = (closer, at)
            if key in memo:
                end = memo[key]
                break
            path.append(key)
            close = _next_position(positions, at)
            if close is None:
                end = None
                break
            if not text.startswith(closer, close + 1):
                end = close + 1
                break
            at = close + 2
        for key in path:
            memo[key] = end
        return end

    def _name_part_end(self, pos: int) -> int | None:
        text = self.text
        if pos >= len(text):
            return None
        if text[pos] in _SQL_QUOTE_CLOSERS:
            return self.quote_end(pos)
        m = _SQL_BARE_NAME.match(text, pos)
        return m.end() if m else None

    def _chain_end(self, pos: int) -> int | None:
        """End of the name parts that start at *pos*, or None.

        Parts join across a dot, or where a quoted part follows directly: a
        name glued to a quoted one is aliased by it (`a"WHERE"`). Memoized at
        every part start along the chain, so names that share a tail (a
        keyword inside a quoted part starts another name) read it once.
        """
        memo, text, path, start = self._names, self.text, [], pos
        while True:
            if pos in memo:
                tail = memo[pos]
                break
            part = self._name_part_end(pos)
            if part is None:
                memo[pos] = tail = None
                break
            path.append((pos, part))
            if text.startswith(".", part):
                pos = part + 1
            elif part < len(text) and text[part] in _SQL_QUOTE_CLOSERS:
                pos = part
            else:
                tail = None
                break
        for part_start, part in reversed(path):
            tail = memo[part_start] = part if tail is None else tail
        return memo[start]

    def name_end(self, pos: int) -> int | None:
        """End of the dot-separated table name at *pos*, or None.

        A bare WHERE is not a name: reading `#staging` as a comment in
        `DELETE FROM #staging`, newline, `WHERE ...` finds no table there.
        """
        end = self._chain_end(pos)
        if end is not None and end - pos == 5 and self.text[pos:end].upper() == "WHERE":
            return None
        return end

    def lacks_where(self, pos: int) -> bool:
        """True when no WHERE follows *pos* before the statement ends.

        The lookahead is bounded to the statement being screened: it stops at
        ";", at a comment start ("--" or "/*"), and at a line that begins a
        new statement. An earlier version scanned to the end of the whole
        payload, so any later WHERE (a trailing `-- where` comment, or a
        second harmless `SELECT ... WHERE ...`) switched the rule off, and the
        text being screened is model output (open-items section 9.2). A WHERE
        on a continuation line of the same statement still counts.
        """
        if self._wheres is None or self._stops is None:
            self._wheres = [m.start() for m in _SQL_WHERE.finditer(self.text)]
            self._stops = [m.start() for m in _SQL_STOP.finditer(self.text)]
        where = _next_position(self._wheres, pos)
        if where is None:
            return True
        stop = _next_position(self._stops, pos)
        return stop is not None and where >= stop


class _SqlPattern:
    """Matcher for one SQL rule; :meth:`search` works like a compiled pattern's."""

    def __init__(
        self,
        keyword: str,
        finish: Callable[[_SqlWindow, _SqlPattern], _SqlMatch | None],
        plain: str | None = None,
    ) -> None:
        self.keyword = keyword
        self.keyword_re = re.compile(_sql_keyword(keyword), re.IGNORECASE)
        self._finish = finish
        # *plain* matches the rule when no gap holds a comment, in one regex
        # pass; the walk runs only when that fails and the text has a comment.
        self._plain = (
            re.compile(_sql_keyword(keyword) + plain, re.IGNORECASE) if plain else None
        )

    def search(
        self, text: str, window: _SqlWindow | None = None
    ) -> re.Match[str] | _SqlMatch | None:
        if self._plain is not None:
            hit = self._plain.search(text)
            if hit is not None or not _has_sql_comment(text):
                return hit
        return self._finish(window if window is not None else _SqlWindow(text), self)


def _sql_then(tail: str) -> Callable[[_SqlWindow, _SqlPattern], _SqlMatch | None]:
    """Finish a rule whose keyword is followed by a gap and *tail*."""
    tail_re = re.compile(tail, re.IGNORECASE)

    def finish(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
        tails = tail_re.finditer(window.text)
        first = next(tails, None)
        if first is None:
            return None
        gaps = window.gap_map(pattern)
        for m in chain((first,), tails):
            start = gaps.get(m.start())
            if start is not None:
                return _SqlMatch(start, m.end())
        return None

    return finish


_SQL_DROP_OBJECT = _sql_then(r"(?:INDEX|VIEW|TRIGGER)\b")
_SQL_MATERIALIZED = re.compile(r"MATERIALIZED", re.IGNORECASE)
_SQL_VIEW = re.compile(r"VIEW\b", re.IGNORECASE)
_SQL_FROM = re.compile(r"FROM", re.IGNORECASE)
_SQL_SET = re.compile(r"SET\b", re.IGNORECASE)


def _sql_drop_index(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    hit = _SQL_DROP_OBJECT(window, pattern)
    if hit is not None or not _SQL_VIEW.search(window.text):
        return hit
    text, gaps = window.text, window.gap_map(pattern)
    for m in _SQL_MATERIALIZED.finditer(text):
        start = gaps.get(m.start())
        if start is None:
            continue
        for gap in window.gap_ends(m.end(), True):
            view = _SQL_VIEW.match(text, gap) if gap > m.end() else None
            if view:
                return _SqlMatch(start, view.end())
    return None


def _sql_name_follows(text: str, keyword_end: int, pos: int, *, brackets: bool = True) -> bool:
    """True when a table name may start at *pos*, the end of the gap after a keyword.

    A bare name needs a gap. A quoted plain identifier does not
    (`DELETE FROM"orders"`). Anything else glued on is text around the
    keyword: the quote closing the string it sits in (`{"mode": "TRUNCATE"}`),
    the next JSON string, or a regex (`DELETE FROM[ \\t]+`). A glued `[` is
    refused where *brackets* is false.
    """
    if pos > keyword_end:
        return True
    if pos >= len(text) or (text[pos] == "[" and not brackets):
        return False
    return _SQL_GLUED_NAME.match(text, pos) is not None


def _sql_truncate_target(window: _SqlWindow, pos: int) -> int | None:
    """End of the word or quoted name at *pos* that TRUNCATE acts on, or None."""
    text = window.text
    if pos >= len(text):
        return None
    if text[pos] in _SQL_QUOTE_CLOSERS:
        return window.quote_end(pos) or pos + 1
    m = _SQL_WORD.match(text, pos)
    return m.end() if m else None


def _sql_truncate(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    text = window.text
    for m in pattern.keyword_re.finditer(text):
        for gap in window.gap_ends(m.end(), True):
            # SQL Server takes `[name]` only after TRUNCATE TABLE, so a `[`
            # glued to TRUNCATE is a subscript (`TRUNCATE[idx]`), not a name.
            follows = _sql_name_follows(text, m.end(), gap, brackets=False)
            end = _sql_truncate_target(window, gap) if follows else None
            if end is None:
                continue
            # Like `TRUNCATE\s+(?:TABLE\s+)?\w+`, the match takes the name
            # after TABLE, so the excerpt around it keeps its length.
            if end - gap == 5 and text[gap:end].upper() == "TABLE":
                for gap2 in window.gap_ends(end, True):
                    name = _sql_truncate_target(window, gap2) if gap2 > end else None
                    if name is not None:
                        end = name
                        break
            return _SqlMatch(m.start(), end)
    return None


def _sql_delete_no_where(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    text = window.text
    if not _SQL_FROM.search(text):
        return None
    gaps = window.gap_map(pattern)
    for m in _SQL_FROM.finditer(text):
        start = gaps.get(m.start())
        if start is None:
            continue
        for gap in window.name_gap_ends(m.end()):
            follows = _sql_name_follows(text, m.end(), gap)
            name = window.name_end(gap) if follows else None
            if name is not None and window.lacks_where(name):
                return _SqlMatch(start, _SQL_TERMINATOR.search(text, name).end())
    return None


def _sql_update_no_where(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    text = window.text
    if not _SQL_SET.search(text):
        return None
    for m in pattern.keyword_re.finditer(text):
        for gap in window.name_gap_ends(m.end()):
            follows = _sql_name_follows(text, m.end(), gap)
            name = window.name_end(gap) if follows else None
            if name is None:
                continue
            for gap2 in window.gap_ends(name, True):
                # With no gap, SET can only follow a closing quote (`"users"SET`):
                # a bare name would have taken its letters.
                set_m = _SQL_SET.match(text, gap2)
                if set_m and window.lacks_where(set_m.end()):
                    return _SqlMatch(
                        m.start(), _SQL_TERMINATOR.search(text, set_m.end()).end()
                    )
    return None


# The rm rules read one shell command at a time. A command runs until a
# separator: a line break, ";", "&", "|", "(", ")", a backtick, a quote or a
# backslash. Quotes matter because the screened text is often a tool call
# serialized as JSON, where each argument is a quoted string: a word in a
# neighbouring field (a ``description`` beside a ``command``) is a different
# command, not one of rm's operands. A backslash ends the command for the same
# reason — a newline inside a JSON string is written ``\n`` (a backslash then
# ``n``), so the backslash stands where the real newline does. So the options
# and operands of another command, another line or another field are not taken
# for rm's. A "#" also ends the command (a trailing comment) but, unlike the
# rest, does not begin one: the text after it is the comment, not a command.
_CMD_BREAK = "\\n\\r\\x0b\\x0c\\x85\\u2028\\u2029;&|()`\"'\\\\"
_CMD_CHAR = r"[^" + _CMD_BREAK + r"#]"
_CMD_START = r"(?:^|(?<=[" + _CMD_BREAK + r"]))"
# Up to a command's first ``rm`` word: ``rm`` on its own, not inside a longer
# word or a flag, and not the ``rm`` subcommand of a version-control tool
# (``git``/``svn``/``hg``/``bzr`` ``rm`` only touches tracked files, not the
# filesystem). A following whitespace, quote or redirection (``rm>log -rf /``
# runs rm with its output redirected) ends the word. The match starts where
# the command does. The lookahead finds the shortest prefix ending at such a
# word and, once it has matched, is never re-entered; ``(?P=before)`` then
# consumes exactly that prefix. So a command holding many ``rm`` words is read
# a fixed number of times, not once per word, and the words after the first
# ``rm`` are read by the lookaheads below. Words of the *enclosing* command
# that follow the ``rm`` word do count as rm's (``ssh host "rm -f x" -R ...``),
# and the boundary approximates a shell's rather than parsing it.
# Reject the ``rm`` when it is the ``rm`` subcommand of a version-control tool.
# The VCS word must be a whole word at a real boundary — the start of the text
# or a character that is neither a word character nor ``/`` — so ``git`` inside
# ``legit`` or after a path (``/git``) does not disable the rule. One space or
# tab may sit between it and ``rm`` (fixed-width lookbehinds cannot span a
# variable run, so an unusual double space leaves the real ``rm`` matched, which
# is safe). ``\b`` alone would treat ``/`` as a boundary and miss ``X=/git rm``.
_VCS_RM = "".join(
    r"(?<![^\w/]" + name + r"[ \t]rm)(?<!\A" + name + r"[ \t]rm)"
    for name in ("git", "svn", "hg", "bzr")
)
_RM_COMMAND_START = (
    _CMD_START
    + r"(?=(?P<before>" + _CMD_CHAR + r"*?)rm(?<![-\w]rm)" + _VCS_RM + r"(?=[\s\"'<>]))"
    + r"(?P=before)"
)
# From the ``rm`` word to the end of the command. This whole group is the
# finding's excerpt, shown with no surrounding context (see the screen loop),
# so a secret in a neighbouring JSON field cannot ride along into an audit
# leaf or kill record; secret redaction covers a value inside the command.
_RM_COMMAND = r"(?P<rm_command>rm" + _CMD_CHAR + r"*)"

#: rm's own short options across GNU coreutils and BSD/macOS: -d -f -i -I -r -R
#: -v (GNU) and -P -W -x (BSD). IGNORECASE covers I/R/P/W/X. A cluster is read
#: as recursive/force only if it is made of these, so a word like ``-Force`` or
#: ``-print`` — which merely contains r and f but has other letters — is not
#: (the cluster must also end at a non-word character).
_RM_SHORT_FLAGS = "dfiprvwx"


def _rm_option(letter: str, long_name: str) -> str:
    """An option word: a cluster of rm's short options holding *letter*, or
    ``--long_name`` or a prefix of it (GNU getopt accepts any unambiguous one).

    The lookahead finds the letter and the cluster is then read once more, so a
    long cluster costs a few passes over its length, not its length squared.
    """
    prefixes = "|".join(long_name[:n] for n in range(len(long_name), 0, -1))
    return (
        r"(?:-(?=[" + _RM_SHORT_FLAGS + r"]*" + letter + r")[" + _RM_SHORT_FLAGS + r"]+(?!\w)"
        r"|--(?:" + prefixes + r")(?![\w-]))"
    )


def _rm_argument(word: str) -> str:
    """Lookahead from an ``rm`` word: a word matching *word* follows it in the
    same command."""
    return r"(?=" + _CMD_CHAR + r"*?(?<=\s)" + word + r")"


_RM_RECURSIVE = _rm_argument(_rm_option("r", "recursive"))
_RM_FORCE = _rm_argument(_rm_option("f", "force"))
# A whole-word root or glob target, matched as a literal path token. ``/``, a
# glob of root (``/*``, ``//``, ``/*/``), ``~``, ``~/``, ``$HOME`` or ``$HOME/``
# count wherever they stand among the operands. A bare ``*`` (a glob of the
# working directory) counts as the last operand, or when another operand (a
# word that is not an option) follows it — ``rm -r * .git`` wipes the directory
# just as ``rm -r *`` does. It does not count when an option follows, so a
# ``*`` that is the value of an option, such as
# ``aws s3 rm --recursive --exclude * --include ...``, is not a root wipe. A
# ``/`` or ``*`` followed by a name is a narrower path (``/etc``, ``/tmp/*``,
# ``*.pyc``), left to the generic rule.
_AFTER_TARGET = r"(?=[\s\"';&|()`\\#]|$)"
_RM_ROOT_TARGET = _rm_argument(
    r"(?:(?:/[/*]*|~/?|\$HOME/?)" + _AFTER_TARGET
    + r"|\*(?=\s*(?:[" + _CMD_BREAK + r"#]|$)|\s+[^-\s" + _CMD_BREAK + r"#]))"
)

_RULES: tuple[_ActionRule, ...] = (
    # ── SQL: irreversible schema / data destruction ──────────────────────
    # Gaps between keywords may hold comments; see "SQL statements" above.
    _ActionRule(
        rule_id="sql.drop_database",
        name="DROP DATABASE / SCHEMA",
        severity=ActionSeverity.CRITICAL,
        pattern=_SqlPattern(
            "DROP",
            _sql_then(r"(?:DATABASE|SCHEMA)\b"),
            plain=_SQL_EXECUTABLE_GAP + r"(?:DATABASE|SCHEMA)\b",
        ),
    ),
    _ActionRule(
        rule_id="sql.drop_table",
        name="DROP TABLE",
        severity=ActionSeverity.CRITICAL,
        pattern=_SqlPattern(
            "DROP",
            _sql_then(r"TABLE\b"),
            plain=_SQL_EXECUTABLE_GAP + r"TABLE\b",
        ),
    ),
    _ActionRule(
        rule_id="sql.truncate",
        name="TRUNCATE TABLE",
        severity=ActionSeverity.CRITICAL,
        # TRUNCATE, a gap, then a word (TABLE or the name) or a quoted name. A
        # quoted name may be glued on, as _sql_name_follows describes.
        pattern=_SqlPattern(
            "TRUNCATE",
            _sql_truncate,
            plain=r"(?:" + _SQL_EXECUTABLE_GAP
            + r"(?:(?:TABLE" + _SQL_EXECUTABLE_GAP + r")?\w+|[\"`\[])"
            + r"|\"(?=" + _SQL_IDENTIFIER + r"\")|`(?=" + _SQL_IDENTIFIER + r"`))",
        ),
    ),
    _ActionRule(
        # DELETE / UPDATE without a WHERE clause = mass mutation. The WHERE
        # search is bounded to the statement; see _SqlWindow.lacks_where.
        rule_id="sql.delete_no_where",
        name="DELETE FROM without WHERE",
        severity=ActionSeverity.CRITICAL,
        pattern=_SqlPattern("DELETE", _sql_delete_no_where),
    ),
    _ActionRule(
        rule_id="sql.update_no_where",
        name="UPDATE without WHERE",
        severity=ActionSeverity.HIGH,
        pattern=_SqlPattern("UPDATE", _sql_update_no_where),
    ),
    _ActionRule(
        rule_id="sql.drop_index",
        name="DROP INDEX / VIEW / TRIGGER",
        severity=ActionSeverity.HIGH,
        pattern=_SqlPattern(
            "DROP",
            _sql_drop_index,
            plain=_SQL_EXECUTABLE_GAP
            + r"(?:INDEX|VIEW|TRIGGER|MATERIALIZED" + _SQL_EXECUTABLE_GAP + r"VIEW)\b",
        ),
    ),
    # ── git: destructive history rewrites ────────────────────────────────
    _ActionRule(
        rule_id="git.push_force",
        name="git push --force",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            _command_with(r"\bgit\s+push\b", r"(?:--force(?!-with-lease)|-f\b)"),
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.reset_hard",
        name="git reset --hard",
        severity=ActionSeverity.CRITICAL,
        # `(?!\s)` takes the blanks after `reset` whole: giving them back one
        # at a time re-ran the scan from each blank, and a shorter run cannot
        # match where the whole one does not. The blank before `--hard` can be
        # the end of a later `git reset` (the exception in `_to_first`); that
        # repeat then has `--hard` right after it, which the first branch
        # takes. After a `--hard`, `_LAST_HARD` runs on to the last one in the
        # segment; a `--hard` after a newline is already the last.
        pattern=re.compile(
            r"\bgit\s+reset\s+(?!\s)(?:--hard\b" + _LAST_HARD + r"|"
            + _to_first(r"\s--hard\b", r"\bgit\s+reset\s")
            + r"(?:\n--hard\b|\s--hard\b" + _LAST_HARD + r"))",
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.clean_force",
        name="git clean -fd",
        severity=ActionSeverity.HIGH,
        pattern=re.compile(
            _command_with(r"\bgit\s+clean\b", r"-[a-z]*f[a-z]*d?"),
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="git.branch_delete",
        name="git branch -D / push --delete",
        severity=ActionSeverity.HIGH,
        # `(?!\s)` as in git.reset_hard.
        pattern=re.compile(
            r"\bgit\s+(?:branch\s+-D\b|push\s+(?!\s)"
            + _to_first(r"--delete\b", r"\bgit\s+push\s")
            + r"--delete\b)",
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
        # Recursive removal of `/`, a glob of root (`/*`, `//`, `/*/`), `~` or
        # `$HOME`, each a literal path token among the operands, or a bare `*`
        # (a glob of the working directory) as the last operand,
        # with or without force. Without force, rm prompts for a write-protected
        # file only when its input is a terminal (checked: GNU coreutils `rm -r`
        # removed a read-only file with stdin from `/dev/null`); writable files
        # go either way, so force does not change what a recursive removal takes
        # with it, and `--preserve-root` protects `/` either way. (`-i`/`-I` do
        # change it, but a rule cannot assume they are absent.) A longer path is
        # the generic rule's job (HIGH): `rm -rf /tmp/build-cache` is not a root
        # wipe. This also fires on prose or a comment that spells such a command.
        pattern=re.compile(
            _RM_COMMAND_START + _RM_RECURSIVE + _RM_ROOT_TARGET + _RM_COMMAND,
            re.IGNORECASE,
        ),
        excerpt_group="rm_command",
    ),
    _ActionRule(
        rule_id="fs.rm_rf_generic",
        name="rm -rf <path>",
        severity=ActionSeverity.HIGH,
        # Recursive and force, whatever the operands, as short options alone or
        # in one cluster, or as long options, in any order.
        pattern=re.compile(
            _RM_COMMAND_START + _RM_RECURSIVE + _RM_FORCE + _RM_COMMAND,
            re.IGNORECASE,
        ),
        excerpt_group="rm_command",
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
            _command_with(r"\bdd\b", r"\bof\s*=\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|xvd[a-z])"),
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
            _command_with(
                r"\bdocker\s+(?:system|volume|image)\s+prune\b",
                r"(?:--all|-a|--volumes|-f|--force)",
            ),
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="kubectl.delete_all",
        name="kubectl delete all/--all",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            _command_with(r"\bkubectl\s+delete\b", r"(?:\ball\b|--all\b|-A\b)"),
            re.IGNORECASE,
        ),
    ),
    _ActionRule(
        rule_id="terraform.destroy",
        name="terraform destroy --auto-approve",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            _command_with(r"\bterraform\s+destroy\b", r"(?:--auto-approve|-auto-approve)"),
            re.IGNORECASE,
        ),
    ),
    # ── cloud control plane: delete buckets / projects ───────────────────
    _ActionRule(
        rule_id="aws.s3_rb_force",
        name="aws s3 rb --force",
        severity=ActionSeverity.CRITICAL,
        pattern=re.compile(
            _command_with(r"\baws\s+s3\s+rb\b", r"--force\b"),
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

#: Rule id of the synthetic CRITICAL finding for a payload that is not valid
#: Unicode. It holds half of a UTF-16 surrogate pair (U+D800-U+DFFF), which
#: ``json.loads`` makes from a lone escape. No UTF-8 encoder accepts one, so a
#: tool drops it, replaces it or rejects the payload, and the rules, which read
#: the payload as given, cannot say what the tool runs.
UNPAIRED_SURROGATE_RULE_ID = "input.unpaired_surrogate"

_UNPAIRED_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")


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
        always gets a definitive answer. A payload holding an unpaired surrogate
        is CRITICAL too (:data:`UNPAIRED_SURROGATE_RULE_ID`).
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
            payload_hash = (
                hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()
                if isinstance(payload, str) else ""
            )
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
        # surrogatepass: strict UTF-8's bytes for valid text, and distinct bytes
        # (so a distinct hash) for each unpaired surrogate, where "ignore" dropped
        # them. The truncated windows below still decode those bytes away.
        encoded = payload.encode("utf-8", "surrogatepass")
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
        # Built on first use and shared by the SQL rules, one per window.
        sql_windows: list[_SqlWindow | None] = [None] * len(windows)

        for rule in self._rules:
            hit = _first_hit(rule.pattern, windows, sql_windows)
            if hit is None:
                continue
            scan_text, m = hit
            if rule.excerpt_group:
                # The group is the whole command (rm to the first break). Show
                # exactly it, with no surrounding context, so a neighbouring
                # field — a secret in an adjacent JSON key — cannot ride along.
                start, end = m.span(rule.excerpt_group)
                excerpt = _excerpt(scan_text, start, end, window=0)
            else:
                excerpt = _excerpt(scan_text, m.start(), m.end())
            matches.append(
                ActionMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=rule.severity,
                    owasp=rule.owasp,
                    excerpt=excerpt,
                )
            )

        for rule_id, severity, pattern in self._config.extra_rules:
            hit = _first_hit(pattern, windows, sql_windows)
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

        surrogate = _UNPAIRED_SURROGATE_RE.search(payload)
        if surrogate:
            matches.append(
                ActionMatch(
                    rule_id=UNPAIRED_SURROGATE_RULE_ID,
                    name="payload is not valid Unicode (unpaired surrogate)",
                    severity=ActionSeverity.CRITICAL,
                    owasp="LLM06",
                    excerpt=(
                        f"U+{ord(surrogate.group()):04X} at character {surrogate.start()}; "
                        "a tool may drop or replace it, so the rules cannot say what runs"
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
    pattern: re.Pattern[str] | _SqlPattern,
    windows: list[str],
    sql_windows: list[_SqlWindow | None],
) -> tuple[str, re.Match[str] | _SqlMatch] | None:
    """Return ``(window_text, match)`` for the first window *pattern* hits."""
    for i, text in enumerate(windows):
        if isinstance(pattern, _SqlPattern):
            window = sql_windows[i]
            if window is None:
                window = sql_windows[i] = _SqlWindow(text)
            m = pattern.search(text, window)
        else:
            m = pattern.search(text)
        if m:
            return text, m
    return None


# Group 1 keeps the key name, separator and surrounding whitespace so the
# rewrite works for ``key=value``, ``key: value`` and the JSON ``"key": "value"``
# form (an optional quote may sit between the key and the separator, and before
# the value). The excerpt can span into a neighbouring JSON field, so redacting
# that form keeps a secret out of the audit leaf and kill record.
_SECRET_REDACT_RE = re.compile(
    r"((?:api[_-]?key|secret|token|password|bearer)[\"']?\s*[=:]\s*[\"']?)\S{8,}",
    re.IGNORECASE,
)


def _excerpt(text: str, start: int, end: int, *, window: int = 32) -> str:
    """Return a short, secret-redacted snippet around the match."""
    s = max(0, start - window)
    e = min(len(text), end + window)
    snippet = text[s:e].replace("\n", " ⏎ ").strip()
    snippet = _SECRET_REDACT_RE.sub(r"\1[REDACTED]", snippet)
    # An excerpt goes into results, events and audit leaves as UTF-8.
    snippet = _UNPAIRED_SURROGATE_RE.sub("\ufffd", snippet)
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


# ---------------------------------------------------------------------------
# Combining screens of one payload
# ---------------------------------------------------------------------------


#: Rule id of the match that stands for a screen which failed internally, once
#: screens are combined. No ``disabled_rule_ids`` entry removes it.
GUARD_ERROR_RULE_ID = "guard.error"


def combine_screens(
    results: Sequence[ActionScreenResult],
    *,
    disabled_rule_ids: Collection[str] = (),
) -> ActionScreenResult:
    """Fold several screens of the same payload into one result; the worst wins.

    A caller that reads a payload more than one way (a tool call as sent, and
    each string in it decoded) screens every reading and combines them here.
    Matches are merged by rule id, keeping the first excerpt; rules named in
    *disabled_rule_ids* are dropped **before** the severity is taken, so a
    disabled rule cannot set it. A screen that failed internally (destructive
    with no matches, see :meth:`DestructiveActionGuard.screen`) becomes a
    ``critical`` :data:`GUARD_ERROR_RULE_ID` match: disabling rules must not
    turn fail-closed into allow.
    """
    merged: dict[str, ActionMatch] = {}
    failed = False
    for result in results:
        if result.is_destructive and not result.matches:
            failed = True
        for match in result.matches:
            if match.rule_id == GUARD_ERROR_RULE_ID:
                failed = True
            elif match.rule_id not in disabled_rule_ids:
                merged.setdefault(match.rule_id, match)
    matches = sorted(merged.values(), key=lambda m: -_SEVERITY_ORDER[m.severity])
    if failed:
        matches.insert(0, ActionMatch(
            rule_id=GUARD_ERROR_RULE_ID,
            name="guard internal error",
            severity=ActionSeverity.CRITICAL,
            owasp="LLM06",
            excerpt="a screen failed internally; failing closed",
        ))
    first = results[0] if results else None
    payload_hash = first.payload_sha256 if first else ""
    surface = first.surface if first else "agent_action"
    if not matches:
        return ActionScreenResult(
            is_destructive=False,
            severity=ActionSeverity.NONE,
            explanation="no destructive action patterns matched",
            payload_sha256=payload_hash,
            surface=surface,
        )
    worst = matches[0]
    return ActionScreenResult(
        is_destructive=True,
        severity=worst.severity,
        matches=matches,
        explanation=(
            f"Destructive action detected: {worst.name} "
            f"({worst.severity.value}, rule={worst.rule_id}); "
            f"{len(matches)} pattern(s) matched"
        ),
        payload_sha256=payload_hash,
        surface=surface,
    )


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
    "combine_screens",
    "MAX_SCAN_BYTES",
    "TRUNCATION_RULE_ID",
    "GUARD_ERROR_RULE_ID",
    "UNPAIRED_SURROGATE_RULE_ID",
]
