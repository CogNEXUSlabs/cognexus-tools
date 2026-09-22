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
  a SQL engine (see "SQL statements" below), and they read a statement to
  its end, so English that holds the keywords is not one (see "SQL
  statements read to their end").
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
from collections.abc import Callable, Collection, Iterator, Sequence
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
    #: Also scan a shell-normalized reading of the text (see ``_shell_normalize``)
    #: — for the ``rm``/``find`` rules, where a quote, command substitution,
    #: ``${IFS}`` token or fd redirection can hide a flag or target from the
    #: plain command boundary. The normalized reading is scanned *after* the raw
    #: text, so it can only add a finding, never drop one.
    normalize: bool = False


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
#
# SQL often travels in a JSON or code string, where a line break or tab is
# written as an escape: a backslash, then `n`, `r` or `t`. The letter is glued
# to the keyword that begins the next line, so a statement, and a WHERE, may
# also start right after such an escape. An escape counts only when its
# backslash is not itself escaped: after an even run of backslashes the
# letter begins the next word.

_SQL_STATEMENT_KEYWORDS = (
    r"SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE"
)
# A line break or tab written as an escape: a backslash, then `n`, `r` or `t`
# in lower case (the rules match under IGNORECASE).
_SQL_ESCAPE_BEFORE = r"\\(?-i:[nrt])"
_SQL_BACKSLASHES = "\\" * 64


def _escape_refused(text: str, pos: int) -> bool:
    """True when the word at *pos* follows a backslash and n, r or t, and the backslash is escaped.

    `_sql_keyword` and `_SQL_WHERE` accept a word right after such an escape,
    but a lookbehind cannot count the run of backslashes before it. After an
    even run the letter begins the word, and no word starts at *pos*. Any
    other boundary they accept leaves no n, r or t before *pos*. The run is
    read 64 characters at a time.
    """
    if text[pos - 1 : pos] not in ("n", "r", "t"):
        return False
    end = start = pos - 1
    while start >= 64 and text[start - 64 : start] == _SQL_BACKSLASHES:
        start -= 64
    while start and text[start - 1] == "\\":
        start -= 1
    return (end - start) % 2 == 0


class _KeywordRe:
    """A compiled SQL regex that drops the matches :func:`_escape_refused` refuses.

    Every regex whose match starts at a keyword, and so may start right after
    an escape, is read through this wrapper. It has only the methods the rules
    use, so a reader cannot reach an unfiltered match. A refused match moves a
    search on by one character, so every position is still tried once.
    """

    __slots__ = ("pattern",)

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern

    def search(self, text: str, pos: int = 0) -> re.Match[str] | None:
        m = self.pattern.search(text, pos)
        while m is not None and _escape_refused(text, m.start()):
            m = self.pattern.search(text, m.start() + 1)
        return m

    def finditer(self, text: str, pos: int = 0) -> Iterator[re.Match[str]]:
        m = self.search(text, pos)
        while m is not None:
            yield m
            m = self.search(text, max(m.end(), m.start() + 1))


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
# Where a no-WHERE rule stops looking for WHERE: a statement terminator, a
# comment start, or a line break before a line that begins another statement.
_SQL_STOP = re.compile(
    r";|-(?=-)|/(?=\*)|\n(?=[^\S\n]*(?:" + _SQL_STATEMENT_KEYWORDS + r")\b)",
    re.IGNORECASE,
)
_SQL_WHERE = _KeywordRe(re.compile(
    r"WHERE(?:(?<=\bWHERE)|(?<=" + _SQL_ESCAPE_BEFORE + r"WHERE))\b", re.IGNORECASE
))
_SQL_EXECUTABLE_OPENER = re.compile(r"/\*M?![0-9]*")
_SQL_TERMINATOR = re.compile(r";|--|/\*|$", re.MULTILINE)


def _sql_keyword(word: str) -> str:
    """*word* after a word boundary, a MySQL / MariaDB executable-comment opener or an escape.

    The escape is a line break or tab written as one (`_SQL_ESCAPE_BEFORE`).
    A lookbehind cannot count the backslashes before it, so a pattern built
    on this is read through :class:`_KeywordRe`, which drops a match right
    after an escaped backslash. The literal comes first so a search rejects
    most positions on their first character; the boundary is checked behind
    it, once for each length of the version.
    """
    openers = "".join(
        r"|(?<=/\*" + marker + "![0-9]{" + str(digits) + "}" + word + ")"
        for marker in ("", "(?-i:M)")
        for digits in range(1, 7)
    )
    return (
        word + r"(?:(?<=\b" + word + ")" + openers
        + r"|(?<=" + _SQL_ESCAPE_BEFORE + word + "))"
    )


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
        self._has_hash: bool | None = None
        self._quote_ends: dict[tuple[str, int], int | None] = {}
        self._line_comments: list[int] | None = None
        self._escapes: dict[int, bool] = {}
        self._string_ends: dict[tuple[str, bool, int], int | None] = {}
        self._body_starts: list[int] | None = None
        self._executable_closes: dict[bool, dict[int, int | None]] = {True: {}, False: {}}
        self._executable_closers: set[int] | None = None
        self._wheres: list[int] | None = None
        self._stops: list[int] | None = None
        self._readers: dict[str, _SqlStatementReader] = {}

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

    def quote_end(self, pos: int) -> int | None:
        """End of the quoted name part opened at *pos*; None if it never closes.

        The part is quoted as an identifier, or as a string where SQLite reads
        one as a name. A doubled closing quote stands for one. Ends are
        memoized by search position, so parts that share a closing quote are
        searched once.
        """
        text = self.text
        closer = _SQL_QUOTE_CLOSERS.get(text[pos], "'")
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
        return self.where_ahead(pos) is None

    def where_ahead(self, pos: int) -> int | None:
        """Where the WHERE that follows *pos* before the statement ends starts, or None (see lacks_where)."""
        if self._wheres is None or self._stops is None:
            self._wheres = [m.start() for m in _SQL_WHERE.finditer(self.text)]
            self._stops = [m.start() for m in _SQL_STOP.finditer(self.text)]
        where = _next_position(self._wheres, pos)
        if where is None:
            return None
        stop = _next_position(self._stops, pos)
        return where if stop is None or where < stop else None

    def breaks_between(self, start: int, end: int) -> bool:
        """True when a line break lies in ``text[start:end]``."""
        brk = self._line_break(start, True)
        return brk is not None and brk < end

    def statement_reader(
        self, rule_id: str, build: Callable[[_SqlWindow], _SqlStatementReader]
    ) -> _SqlStatementReader:
        """The statement reader of rule *rule_id* for this window, built on first use."""
        reader = self._readers.get(rule_id)
        if reader is None:
            reader = self._readers[rule_id] = build(self)
        return reader


class _SqlPattern:
    """Matcher for one SQL rule; :meth:`search` works like a compiled pattern's."""

    def __init__(
        self,
        keyword: str,
        finish: Callable[[_SqlWindow, _SqlPattern], _SqlMatch | None],
    ) -> None:
        self.keyword = keyword
        self.keyword_re = _KeywordRe(re.compile(_sql_keyword(keyword), re.IGNORECASE))
        self._finish = finish

    def search(
        self, text: str, window: _SqlWindow | None = None
    ) -> re.Match[str] | _SqlMatch | None:
        return self._finish(window if window is not None else _SqlWindow(text), self)


# ---------------------------------------------------------------------------
# SQL statements read to their end
# ---------------------------------------------------------------------------
#
# A statement's keyword can also be an English word, a CSS class or a function
# name ("truncate the log"), so a rule can read the statement rather than the
# keyword and a word. After the keyword come the words the statement reads
# before its tables (such as TABLE or IF EXISTS), one or more tables separated
# by commas, any of the statement's own options (such as CASCADE), and then
# the end of the statement. A table is a name: dotted parts, each bare or
# quoted, including the escaped or doubled quotes a string in code writes
# (`\"Users\"`, `""Users""`). A template placeholder can stand for a name or a
# part of one (`{prefix}logs`, `${table}`, `%s`, `%TABLE%`, `&table`, `:table`,
# `?`, `<table_name>`), and so can a string that closes where the name belongs
# and is joined to it (`"TRUNCATE TABLE " + name`, `CONCAT('TRUNCATE TABLE ',
# name)`).
#
# How the statement ends decides how much more it needs. A semicolon on the
# same line as the last table or option, or an option followed by any ending,
# marks SQL wherever the statement stands. A line break, a quote, a backslash
# (a JSON escape), a comment, `$$`, `{%`, `**`, `|`, the end of an XML element,
# the upper-case keyword of the next statement on the same line (`TRUNCATE
# TABLE t COMMIT`, unless prose follows it) or the end of the text also ends
# English. There the statement must also begin where statements begin (see
# _SqlStatementReader.statement_start) or carry the mark of SQL that its rule
# reads: TABLE after TRUNCATE; for DROP and DELETE, capitals or a name that no
# English word is. UPDATE is read to SET and an assignment instead (see
# "DELETE and UPDATE statements").

# Read over the reversed text: spaces, tabs, a byte order mark or another
# invisible separator, and MySQL executable-comment openers (`/*!50000`,
# reversed), whose body is code.
_SQL_BEFORE_KEYWORD = re.compile(
    r"(?:[^\S\n\r]|[\N{BYTE ORDER MARK}\N{ZERO WIDTH SPACE}\N{ZERO WIDTH NON-JOINER}\N{ZERO WIDTH JOINER}"
    r"\N{WORD JOINER}]|[0-9]*!M?\*/)*"
)
_SQL_STATEMENT_OPENERS = ";\n\r\"'`"
# Reversed: the `*/` that closes a comment and the `$$` before a function body.
_SQL_REVERSED_OPENERS = ("/*", "$$")
# Reversed: a dbt `{% call statement(...) %}` block, whose body is the statement.
_SQL_CALL_BLOCK_BEFORE = re.compile(r"}%-?[^%]{0,300}?\sllac[ \t]*-?%{")
# Before a keyword written in capitals, read over the reversed text: a line
# break written as a JSON escape; the `:` or `=` after a key that names SQL or
# a command (`query:`, `Action Input:`, `RESET_SQL=`, `Executing:`); a SQL
# shell's prompt (`app=>`, `app=#`, `mysql>`, `SQL>`, `1>`); or a tag that holds
# code or a statement (`<code>`, `<pre>`, `<sql>`, a MyBatis `<update id=...>`).
_SQL_CAPITALS_OPENER_BEFORE = re.compile(
    r"[nr]\\"
    r"|[:=][ \t]*(?:lqs|yreuq|tnemetats|tmts|dnammoc|dmc|tupni|tpircs|gnitucexe|gninnur|nur|etucexe|cexe)"
    r"|#=(?=\w)|>(?:=(?=\w)|(?:lqs-kraps|bdairam|lqsym|etilqs|lqsp|evih|lqs|[0-9]+)(?![\w-])"
    r"|(?:[^<>]{0,300}\s)?(?:edoc|erp|lqs|etadpu|eteled|tresni|tceles|tnemetats|yreuq|lqs_etucexe)<)",
    re.IGNORECASE,
)
# A `;` that begins its line, or a doubled one, read over the reversed text: a
# comment in INI files and Lisp, not the end of a statement.
_SQL_LINE_START_SEMICOLON = re.compile(r";(?:;|[^\S\n\r]*(?:[\n\r]|\Z))")
# Stand-ins in a phrase of a grammar: a table's name, a number and a value.
_SQL_NAME_TOKEN, _SQL_NUMBER_TOKEN, _SQL_VALUE_TOKEN = "<name>", "<number>", "<value>"
#: Phrase tokens that stand in for something matched, not a literal word.
_SQL_TOKEN_STANDINS = frozenset({_SQL_NAME_TOKEN, _SQL_NUMBER_TOKEN, _SQL_VALUE_TOKEN})
_SQL_PUNCTUATION = frozenset("(=,)")
# Reserved words that English puts between words (`TRUNCATE with care`,
# `truncate and sync`), which cannot name a table without quotes.
_SQL_RESERVED_NAMES = frozenset(
    "AND OR NOT WITH ON IN IS AS TO FROM FOR INTO THEN WHEN ELSE END BY OF USING WHERE "
    "SELECT CASE NULL TRUE FALSE DO BOTH SOME ANY UNION EXCEPT INTERSECT ORDER GROUP "
    "HAVING LIMIT OFFSET JOIN LEFT RIGHT INNER OUTER CROSS NATURAL BETWEEN LIKE DISTINCT "
    "DEFAULT CHECK PRIMARY FOREIGN REFERENCES UNIQUE CONSTRAINT CREATE GRANT INSERT "
    "UPDATE DELETE DROP ALTER TRUNCATE REVOKE VALUES RETURNING DESC ASC VS VERSUS".split()
)
# A number is not a table name either (`truncate $fh, 0;`, `truncate #123`).
_SQL_NUMBER_NAME = r"#?[0-9]+(?:\.[0-9]+)*"
_SQL_NUMBER_NAME_RE = re.compile(_SQL_NUMBER_NAME)


def _sql_named_words(words: Collection[str]) -> re.Pattern[str]:
    """One of *words*, matched without regard to case, in a group named after it.

    The group name is the key: a case-insensitive match can differ from the
    word by more than its case (the Kelvin sign matches K). With no words,
    nothing matches.
    """
    if not words:
        return re.compile(r"(?!)")
    return re.compile(
        "(?:" + "|".join(f"(?P<{word}>{word})" for word in sorted(words, key=len, reverse=True)) + r")\b",
        re.IGNORECASE,
    )


# A name character; `$` only when another does not follow, since `$$` quotes a
# PostgreSQL function body (`AS $$TRUNCATE sessions$$`).
_SQL_NAME_CHAR = r"(?:[\w#@]|\$(?!\$))"
# Placeholders that stand for a name: `{...}`, `{{...}}`, `${...}`, `#{...}`,
# `$(...)`, Swift `\(...)`, ERB `<%= ... %>`, a batch file's `%name%` and
# `%s`-style; not a Jinja statement tag (`{% endtrans %}`).
_SQL_TEMPLATE = (
    r"\{\{[^{}\n]*\}\}|\\?[$#]?\{(?!%)[^{}\n]*\}|\\?\$\([^()\n]*\)|\\\([^()\n]*\)|<%=?[^%\n]*%>"
    r"|%[A-Za-z_]\w*%|%(?:\(\w+\)|[0-9]+\$)?[A-Za-z]"
)
# A placeholder that is a whole table name part on its own: a lone `?`/`??`;
# a psql variable, `:name`, `:"name"` or `:'name'`, whose quotes a string in
# code may double or escape; a SQL*Plus `&name` or `&&name` (not an HTML
# entity such as `&rarr;`; read after TABLE only, see table_end); or a name in
# angle brackets, as documentation writes one (`<table_name>`).
_SQL_HTML_ENTITY = (
    r"(?:amp|lt|gt|quot|apos|nbsp|hellip|mdash|ndash|[lrudh]arr|[lrudh]Arr|copy|reg|trade|times|middot"
    r"|bull|laquo|raquo|[lr]squo|[lr]dquo|deg|minus|plusmn|euro|pound|cent|sect|para|shy|zwn?j);"
)
_SQL_LONE_PLACEHOLDER = (
    r"\?\??(?![\w#@$?])"
    r"|:[A-Za-z_]\w*|:\"\"[^\"\n]+\"\"|:\"[^\"\n]+\"|:'[^'\n]+'|:\\\"[^\"\\\n]+\\\"|:\\'[^'\\\n]+\\'"
    r"|&&?(?!" + _SQL_HTML_ENTITY + r")[A-Za-z_]\w*|<[A-Za-z_][\w-]*>"
)
# A BigQuery project with dashes before its dataset (`my-project.analytics`),
# read after TABLE only (see table_end), as BigQuery writes TRUNCATE TABLE.
_SQL_DASHED_PART = r"[A-Za-z_]\w*(?:-\w+)+(?=\.[A-Za-z_`])"
_SQL_DASHED_PART_RE = re.compile(_SQL_DASHED_PART)
# A table name part that is not quoted: a lone placeholder; a dashed project;
# or name characters and placeholders glued together. Each repetition takes
# one character or one whole placeholder, so no two repetitions can split the
# same text.
_SQL_NAME_PART = re.compile(
    _SQL_LONE_PLACEHOLDER + "|" + _SQL_DASHED_PART
    + r"|(?:" + _SQL_TEMPLATE + r"|" + _SQL_NAME_CHAR + r")+"
)
# A whole table name that is one placeholder, with no name characters of its own:
# including a shell, PowerShell or Ruby variable (`$LOG`, `@table`).
_SQL_PLACEHOLDER = re.compile(
    _SQL_LONE_PLACEHOLDER + r"|[$@][A-Za-z_]\w*|\$[0-9]+|" + _SQL_TEMPLATE
)
# A value after ON CLUSTER or LIKE: a string, in plain, doubled (inside a SQL
# string) or escaped quotes, a quoted name, or a bare one (`default`,
# `prod-cluster`, `{cluster}`), which may be a word no table can be named.
_SQL_VALUE_RE = re.compile(
    r"''[^'\n]+''|\\'[^'\\\n]*\\'|'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|[\w{}-]+"
)
# What may follow `""` for it to open a name in doubled quotes, as a C# verbatim
# string writes `""Users""`.
_SQL_DOUBLED_NAME_START = re.compile(r"[\w#@${%]")
# A table's name that English could write as a word: letters only.
_SQL_PLAIN_WORD = re.compile(r"[^\W\d_]+")
# The escape character a PostgreSQL `U&"..."` name may name after it.
_SQL_UESCAPE = re.compile(r"[ \t\n\r]+UESCAPE[ \t\n\r]+'[^']'", re.IGNORECASE)
# After a quote that closes where a table name belongs: a string joined to the
# name that follows, by an operator, or as the next argument or list item when
# that is a name (CONCAT, paste0, `" ".join(["TRUNCATE TABLE", name])`), not a
# keyword argument (`name="TRUNCATE TABLE", severity=...`) or another string.
_SQL_CONCATENATION = re.compile(r"\s*(\+|\|\||\.|&|~|<>|<<|,(?=\s*[A-Za-z_$@][\w.:]*\s*[),\]}(+]))")
# After the operator: a name, a variable or a parenthesis, not another string.
_SQL_NAME_AHEAD = re.compile(r"\s*[A-Za-z_$@(]")
_JOINED, _JOINED_NAME = 1, 2
# A NUL also ends the text a C client passes on (SQLite's prepare with no
# length stops there).
_SQL_ENDS = ("\\", "--", "#", "/*", "</", "$$", "{%", "**", "|", "\x00")
# After a line break: a line that goes on with markup (`/>`, `{...props}`, or
# a `>` that closes the tag), so the break is inside an element, not a
# statement. A `>` before text is a quoted line (`> reply`).
_SQL_MARKUP_LINE = re.compile(r">[ \t]*(?:[\n\r{<]|\Z)|/>|\{\.\.\.")
# Or an indented attribute with a quoted or braced value (`  color="gray"`),
# unlike a line of a properties or env file (`flyway.url=jdbc:...`).
_SQL_ATTRIBUTE_LINE = re.compile(r"[A-Za-z_:@][\w:.-]*=[\"'{]")
# After a gap: a quote that opens a word (a Go struct tag, `truncate bool `json:"..."``).
_SQL_QUOTED_WORD = re.compile(r"\\?[\"'`][A-Za-z0-9]")
# What may follow a `;` on its line for the `;` to end a statement: nothing, a
# quote or closer, another `;`, a comment, `$$`, markup, an upper-case SQL
# keyword not followed by prose (see _SqlStatementReader._prose_follows), or a
# lower-case PL/SQL word that English does not put there (`end if`, `exit
# when`, `commit;`, `end $$` closing a PostgreSQL block). Anything else is
# prose: `we truncate it; otherwise ...`.
_SQL_AFTER_SEMICOLON = re.compile(
    r"[ \t]*(?:$|[\n\r\"'`\\)\]},;<%]|--|#|/\*|\*/|\$\$"
    r"|(?P<keyword>(?:BEGIN|CALL|COMMIT|COPY|CREATE|DECLARE|DELETE|DROP|ELSE|ELSIF|END|EXEC|EXECUTE|GO|GRANT"
    r"|INSERT|MERGE|PERFORM|RAISE|RETURN|REVOKE|ROLLBACK|SELECT|SET|TRUNCATE|UPDATE|VACUUM)\b)"
    r"|(?i:(?:exit[ \t]+when|raise[ \t]+(?:notice|exception|warning|info|debug|log))\b"
    r"|(?:end[ \t]+(?:if|loop|case)|end|begin|commit|rollback|return)[ \t]*;"
    r"|end[ \t]*\$[A-Za-z_0-9]*\$))"
)
# After a gap on the same line: an upper-case keyword that begins the next
# statement, as T-SQL writes statements without a `;` between them
# (`BEGIN TRAN TRUNCATE TABLE t COMMIT`, `IF ... TRUNCATE TABLE t ELSE ...`).
# A verb that prose about TRUNCATE also writes in capitals (`requires ALTER
# permission`, `vs DELETE`) counts only with the words that follow it in SQL.
_SQL_NEXT_STATEMENT = re.compile(
    r"(?:BEGIN|COMMIT|DBCC|DECLARE|ELSE|END|EXEC|EXECUTE|GO|IF|INSERT|MERGE|PRINT|RAISERROR|RETURN|ROLLBACK"
    r"|SELECT|SET|THROW|TRUNCATE|USE|WAITFOR|WHILE"
    r"|BULK[ \t]+INSERT|DELETE[ \t]+(?:FROM|TOP)|UPDATE[ \t]+(?:STATISTICS|[\w#@.\[\]`\"]+[ \t]+SET)"
    r"|(?:ALTER|CREATE|DROP)[ \t]+(?:TABLE|INDEX|UNIQUE|CLUSTERED|NONCLUSTERED|VIEW|PROC|PROCEDURE|FUNCTION|TRIGGER"
    r"|SCHEMA|DATABASE|SEQUENCE|SYNONYM|TYPE|USER|LOGIN|ROLE|OR)"
    r"|(?:GRANT|REVOKE|DENY)[ \t]+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE|EXEC|ALTER|CONTROL|ALL|TRUNCATE|REFERENCES))\b"
)
# Two lower-case words in a row, not next to a quote: prose. After the keyword
# of a next statement, the rest of the line holds them in prose about SQL
# (`TRUNCATE TABLE requires ALTER TABLE permission on ...`), not in SQL.
_SQL_LOWER_WORDS = re.compile(r"(?<![\w'\"`])(?=[a-z]+[ \t]+[a-z]+(?![\w'\"`]))")
_WEAK, _STRONG = 1, 2
_AFTER_TABLE, _AFTER_STAR, _AFTER_OPTION = range(3)
# After a neutral option (`ON <name>`, which English also writes). Two neutral
# options never follow one another in a real statement (`ON b ON c` is not SQL),
# so the reader reads no more from here, which keeps a run of them (`ON b\n` × n)
# from being read once per position.
_AFTER_NEUTRAL = 5
# Kinds of node in _SqlStatementReader, in the order the nodes at one position
# are resolved: a gap end first, then a tail, then a head.
_HEAD, _TAIL, _GAP_END = range(3)
# How a node counts for the node that leads to it, indexed by its value. A
# strength passes through unchanged; after an option any ending is strong; a
# first table turns a strength into a score for the words before it (3 for a
# strong ending, 2 for a weak one with the rule's mark of SQL, 1 for a weak one).
_SAME = (0, 1, 2, 3)
_THROUGH_OPTION = (0, _STRONG, _STRONG)
_FIRST_TABLE = (0, 1, 3)
_FIRST_TABLE_NAMED = (0, 2, 3)
# A first table that is only a placeholder, without the rule's mark and with
# the keyword not written in capitals: a weak ending does not count.
_FIRST_PLACEHOLDER = (0, 0, 3)
# Flags of a head node: the statement carries its rule's mark of SQL (for
# TRUNCATE, TABLE was read); the keyword is written in capitals, as SQL in code
# conventionally is (`f"TRUNCATE {table}"`), unlike a class list (`class="truncate
# {{ extra }}"`) or a message (`"truncate %s"`); the string holding the keyword
# is an item of a list or of a call that joins strings (see
# _SQL_JOINED_LIST_BEFORE), unlike a string searched for (`assertIn("TRUNCATE
# TABLE", sql)`); a word before the tables other than TABLE is written in lower
# case (`truncate database names`), after which a weak ending does not count;
# the statement has read the words it requires (see _SqlStatementReader._roots),
# so what follows them is a name, even a placeholder alone or a word such as
# SCHEMA.
_NAMED, _CAPITALS, _LISTED, _LOWER_HEAD, _HEAD_READ = 1, 2, 4, 8, 16
# Flags a required phrase can give (see _SqlGrammar): the statement takes the
# grammar's object options (DROP INDEX and DROP TRIGGER take `ON t`); and what a
# DROP statement drops, which says which of the DROP rules it is for. And a flag
# for a DROP that is a specification of an ALTER TABLE statement.
_TAKES_ON, _DROPS_TABLE, _DROPS_DATABASE, _DROPS_INDEX, _IN_ALTER = 32, 64, 128, 256, 512
# The flags a tail keeps: the mark, for the table options, _TAKES_ON and _IN_ALTER.
_TAIL_FLAGS = _NAMED | _TAKES_ON | _IN_ALTER
_SCORE_WEAK, _SCORE_NAMED, _SCORE_STRONG = 1, 2, 3
# Read over the reversed text before the keyword: the quote opening a string
# that is an item of a list (`["TRUNCATE TABLE", name]`, Go's `[]string{...}`)
# or an argument of a function that joins strings (`paste("TRUNCATE TABLE", t)`).
_SQL_JOINED_LIST_BEFORE = re.compile(
    r"[\"'`][ \t]*(?:[\[{]|\((?:0etsap|etsap|c_rts|sw_tacnoc|tacnoc|nioj|tamrof|ftnirps|eulg)(?!\w))",
    re.IGNORECASE,
)


class _SqlGrammar:
    """The words one kind of statement reads after its keyword (see "SQL statements read to their end").

    Before the tables, *heads*: groups of phrases, read one group at a time,
    in order. With *head_required*, a phrase of the first group must follow
    the keyword (DROP TABLE, DELETE FROM), and *head_flags* holds the flags
    each gives the statement. The phrases in *names_table* give the statement
    its mark of SQL (_NAMED).

    The tables follow one another after commas unless *comma_tables* is
    false. *not_names* are the bare words that cannot name a table; after
    TABLE, those in *names_after_table* can. With *string_names*, a string
    can name a table, as SQLite reads one (`DROP TABLE 'users'`).
    *head_lists* open a list in place of a table's name, and *head_tables*
    stand in place of the tables.

    After the tables, *options*: each is followed by another option or the
    end of the statement, which it makes strong, unless it is one of
    *neutral_options*, which English also writes (`drop index cards on the
    desk`). *lists* are options that open a list, where the statement is read
    no further. Some are read only in some statements: *table_options* with
    the mark, *capital_options* there or when written in capitals, and
    *object_options* after a phrase that gives _TAKES_ON.
    """

    def __init__(
        self,
        *,
        heads: tuple[tuple[tuple[str, ...], ...], ...],
        options: tuple[tuple[str, ...], ...],
        not_names: frozenset[str],
        head_required: bool = False,
        names_table: tuple[tuple[str, ...], ...] = (),
        lists: tuple[tuple[str, ...], ...] = (),
        head_lists: tuple[tuple[str, ...], ...] = (),
        head_tables: tuple[tuple[str, ...], ...] = (),
        table_options: frozenset[tuple[str, ...]] = frozenset(),
        capital_options: frozenset[tuple[str, ...]] = frozenset(),
        neutral_options: frozenset[tuple[str, ...]] = frozenset(),
        comma_tables: bool = True,
        names_after_table: frozenset[str] = frozenset(),
        string_names: bool = False,
        head_flags: dict[tuple[str, ...], int] | None = None,
        object_options: frozenset[tuple[str, ...]] = frozenset(),
    ) -> None:
        self.head_flags, self.object_options = head_flags or {}, object_options
        self.head_required, self.names_table = head_required, names_table
        self.head_lists, self.head_tables = head_lists, head_tables
        self.table_options, self.capital_options = table_options, capital_options
        self.neutral_options, self.comma_tables = neutral_options, comma_tables
        self.not_names, self.names_after_table = not_names, names_after_table
        self.string_names = string_names
        self.not_name_lengths = frozenset(len(word) for word in not_names)
        self._tokens: dict[str, re.Pattern[str]] = {}
        for phrase in chain(options, lists, head_lists, head_tables, *heads):
            for word in phrase:
                if word not in _SQL_PUNCTUATION and word not in (_SQL_NAME_TOKEN, _SQL_VALUE_TOKEN):
                    self.token(word)
        # Each phrase under its first word: ``(group, phrase)`` for the words
        # before the tables, ``(phrase, opens a list)`` for the options.
        head_words = frozenset(phrase[0] for group in heads for phrase in group)
        self.head_phrases = {
            word: [
                (group, phrase)
                for group, phrases in enumerate(heads)
                for phrase in phrases
                if phrase[0] == word
            ]
            for word in head_words
        }
        self.option_phrases = {
            phrase[0]: [
                (other, other in lists)
                for other in options + lists
                if other[0] == phrase[0]
            ]
            for phrase in options + lists
        }
        self.head_word = _sql_named_words(self.head_phrases)
        self.option_word = _sql_named_words(self.option_phrases)
        # Tables after a comma that are plain words with only spaces or tabs
        # before the next comma: `, b, c` in `a, b, c, d`. After each of them
        # the statement can only go on to the next table, so the run is read
        # in one match.
        not_name_alternation = "|".join(sorted(not_names, key=len, reverse=True))
        self.plain_tables = re.compile(
            r"(?:,[ \t]*(?!(?:" + not_name_alternation + r"|[0-9]+)(?![\w#@$]))"
            r"(?:[\w@]|\$(?!\$))" + _SQL_NAME_CHAR + r"*[ \t]*(?=,))+",
            re.IGNORECASE,
        )

    def token(self, word: str) -> re.Pattern[str]:
        """The regex for *word* in a phrase: the word, or digits for a number, and a word boundary.

        Built on first use too, so a reader can look for a word none of the
        grammar's phrases holds (ONLY after a comma, AS before an alias).
        """
        pattern = self._tokens.get(word)
        if pattern is None:
            pattern = self._tokens[word] = re.compile(
                r"[0-9]+\b" if word == _SQL_NUMBER_TOKEN else word + r"\b", re.IGNORECASE
            )
        return pattern


class _SqlStatementReader:
    """Reads one kind of statement in one scan window (see "SQL statements read to their end").

    A statement is read as a graph of nodes, each a position and a kind:

    * ``(pos, _HEAD, group, flags)``: after the keyword or one of the words
      before the tables. *group* is the first group of those words still
      allowed; *flags* holds _NAMED once the statement carries its rule's mark
      of SQL and _CAPITALS when the keyword is written in capitals. Its value
      is a score: 3 for a strong ending, 2 for a weak one with the mark, 1 for
      a weak one.
    * ``(pos, _TAIL, state, named)``: after a table, a `*` or an option;
      *named* is _NAMED when the statement carries the mark, for the options
      only such a statement takes.
    * ``(pos, _GAP_END, state, named)``: where a gap after one of those ends.

    A tail's or gap end's value is the strongest ending reachable from it.
    Each node is resolved once per window, and every scan past a node's own
    position is memoized by the position the scan starts at. Keywords whose
    gaps lead to the same place (a comment can hold any number of them)
    share one reading of what follows. Every edge leads to a later position,
    or from a tail to a gap end at the same one, so the nodes found from a
    keyword are resolved from the last position back, without recursion: a
    list of tables can be longer than Python's recursion limit.

    A subclass names the keyword and its grammar, and may skip a keyword it
    does not read or add places where a statement begins.
    """

    keyword: str
    grammar: _SqlGrammar

    def __init__(self, window: _SqlWindow) -> None:
        self.window = window
        self.text = window.text
        self._reversed: str | None = None
        self._gaps: dict[tuple[int, bool], list[int]] = {}
        self._chains: dict[int, int | None] = {}
        self._phrases: dict[tuple[int, tuple[str, ...]], list[int]] = {}
        self._token_ends: dict[tuple[str, int], int | None] = {}
        self._glued: dict[int, bool] = {}
        self._concatenations: dict[int, int] = {}
        self._placeholders: dict[int, bool] = {}
        self._identifiers: dict[tuple[int, int], bool] = {}
        self._tables: dict[tuple[int, bool], int | None] = {}
        self._semicolons: dict[int, bool] = {}
        self._endings: dict[tuple[int, bool, bool], int] = {}
        self._lower_words: list[int] | None = None
        self._lists: dict[int, list[int]] = {}
        self._values: dict[tuple[int, int, int, int], int] = {}
        self._spans: dict[tuple[int, int, int, int], int | None] = {}

    def match_end(self, keyword_start: int, keyword_end: int) -> int | None:
        """End of the first table of the statement the keyword begins here, or None."""
        if self._skips(keyword_start, keyword_end):
            return None
        capitals = self.text[keyword_start:keyword_end] == self.keyword
        flags = _CAPITALS if capitals else 0
        if capitals and _SQL_JOINED_LIST_BEFORE.match(self._reversed_text(), len(self.text) - keyword_start):
            flags |= _LISTED
        score, span = 0, None
        for root in self._roots(keyword_end, flags):
            value = self._value(root)
            if value > score:
                score, span = value, self._spans[root]
        if score >= _SCORE_NAMED or (score == _SCORE_WEAK and self.statement_start(keyword_start, capitals)):
            return span
        return None

    def _roots(self, keyword_end: int, flags: int) -> list[tuple[int, int, int, int]]:
        """The head nodes a statement starts from, after the keyword or its required words.

        After a required phrase (DROP TABLE, DELETE FROM) the statement has
        read what it cannot go without (_HEAD_READ), and it carries its mark
        of SQL when the keyword and the phrase are both written in capitals.
        """
        grammar, text = self.grammar, self.text
        if not grammar.head_required:
            return [(keyword_end, _HEAD, 0, flags)]
        roots = []
        for gap in self.gaps(keyword_end):
            word = grammar.head_word.match(text, gap) if gap > keyword_end else None
            for group, phrase in grammar.head_phrases[word.lastgroup] if word else ():
                if group == 0:
                    head = flags | _HEAD_READ | grammar.head_flags.get(phrase, 0)
                    if flags & _CAPITALS and text.startswith(phrase[0], gap):
                        head |= _NAMED
                    roots.extend((end, _HEAD, 1, head) for end in self.phrase_ends(gap, phrase))
        return roots

    def _skips(self, keyword_start: int, keyword_end: int) -> bool:
        """True when the keyword from *keyword_start* to *keyword_end* is not read at all."""
        return False

    def _reversed_text(self) -> str:
        if self._reversed is None:
            self._reversed = self.text[::-1]
        return self._reversed

    def statement_start(self, pos: int, capitals: bool = False) -> bool:
        """True when the keyword at *pos* stands where a statement begins.

        Before it, past spaces, tabs, invisible separators and MySQL
        executable-comment openers, comes the start of the text, a line break,
        `;`, the `*/` that closes a comment, a quote or `$$` opening the body
        that holds the statement, a dbt `{% call %}` block, or what
        :meth:`_opens_statement` adds; for a keyword written in capitals, also
        what _SQL_CAPITALS_OPENER_BEFORE reads (an escaped line break, a SQL
        key, a prompt, a code tag). A reversed copy of the text lets a regex
        read backwards.
        """
        reversed_text = self._reversed_text()
        before = _SQL_BEFORE_KEYWORD.match(reversed_text, len(self.text) - pos).end()
        if before == len(self.text):
            return True
        char = reversed_text[before]
        if char == ";":
            return _SQL_LINE_START_SEMICOLON.match(reversed_text, before) is None
        return (
            char in _SQL_STATEMENT_OPENERS
            or reversed_text.startswith(_SQL_REVERSED_OPENERS, before)
            or (capitals and _SQL_CAPITALS_OPENER_BEFORE.match(reversed_text, before) is not None)
            or (char == "}" and _SQL_CALL_BLOCK_BEFORE.match(reversed_text, before) is not None)
            or self._opens_statement(reversed_text, before)
        )

    def _opens_statement(self, reversed_text: str, before: int) -> bool:
        """True when the reversed text at *before* holds another opener of this statement."""
        return False

    def gaps(self, pos: int, names: bool = False) -> list[int]:
        """:meth:`_SqlWindow.gap_ends` with `#` a comment, or :meth:`_SqlWindow.name_gap_ends` for *names*.

        A gap can only start at whitespace or at a character that opens or
        closes a comment, so any other character ends it where it starts, and
        whitespace followed by another character ends it in every reading.
        Without a `#` in the text both readings of `#` are the same, and the
        one already walked is used.
        """
        text, window = self.text, self.window
        char = text[pos:pos + 1]
        if char and char not in "/*-#" and not char.isspace():
            return [pos]
        if window._has_hash is None:
            window._has_hash = "#" in text
        key = (pos, names and window._has_hash)
        found = self._gaps.get(key)
        if found is None:
            end = _SQL_SPACE_RE.match(text, pos).end() if char.isspace() else pos
            if end > pos and (end == len(text) or text[end] not in "/*-#"):
                found = [end]
            else:
                found = window.name_gap_ends(pos) if key[1] else window.gap_ends(pos, True)
            self._gaps[key] = found
        return found

    def table_end(self, pos: int, after_table: bool = False) -> int | None:
        """End of the table named at *pos*, or None.

        Parts join across a dot, or two (`tempdb..#staging`). A part is a
        quoted name, in plain, escaped (`\"Users\"`) or doubled (`""Users""`)
        quotes, or PostgreSQL's `U&"..."`; with the grammar's *string_names*,
        a string, which SQLite reads as a name where one belongs (`DROP TABLE
        'users'`); `IDENTIFIER(...)`; a lone `:name` or `?` placeholder; or name
        characters and template placeholders glued together (`{prefix}logs`,
        `logs_%s`). A bare word in the grammar's *not_names*, such as TABLE or
        a reserved word such as WITH or AND, or a number is not a table;
        *after_table*, the words in its *names_after_table* are, and so are a
        SQL*Plus variable and a dashed BigQuery project, which only follow
        TABLE. Chain ends are memoized at every part start.
        """
        key = (pos, after_table)
        if key in self._tables:
            return self._tables[key]
        memo, text, window, path, at = self._chains, self.text, self.window, [], pos
        grammar = self.grammar
        while True:
            if at in memo:
                tail = memo[at]
                break
            if at < len(text) and (
                text[at] in _SQL_QUOTE_CLOSERS or (text[at] == "'" and grammar.string_names)
            ):
                part = window.quote_end(at)
                if part == at + 2 and text[at] == "\"" and _SQL_DOUBLED_NAME_START.match(text, part):
                    close = _next_position(window._index("\"\""), part)
                    part = None if close is None else close + 2
            elif text.startswith(("\\\"", "\\`"), at):
                close = _next_position(window._index(text[at:at + 2]), at + 2)
                part = None if close is None else close + 2
            elif text.startswith(("U&\"", "u&\""), at):
                # PostgreSQL's identifier with Unicode escapes, and its escape character.
                part = window.quote_end(at + 2)
                escape = _SQL_UESCAPE.match(text, part) if part is not None else None
                if escape:
                    part = escape.end()
            else:
                m = _SQL_NAME_PART.match(text, at)
                part = m.end() if m else None
                if part == at + 10 and text.startswith("(", part) and text[at:part].upper() == "IDENTIFIER":
                    close = _next_position(window._index(")"), part)
                    part = None if close is None else close + 1
            if part is None:
                memo[at] = tail = None
                break
            path.append((at, part))
            if text.startswith("..", part):
                at = part + 2
            elif text.startswith(".", part):
                at = part + 1
            else:
                tail = None
                break
        for part_start, part in reversed(path):
            tail = memo[part_start] = part if tail is None else tail
        end = memo[pos]
        # A SQL*Plus variable or a dashed BigQuery project stands for a table
        # only after TABLE, as those dialects write TRUNCATE TABLE.
        if end is not None and not after_table and (
            text[pos] == "&" or _SQL_DASHED_PART_RE.match(text, pos)
        ):
            end = None
        if end is not None and end - pos in grammar.not_name_lengths:
            word = text[pos:end].upper()
            if word in grammar.not_names and not (after_table and word in grammar.names_after_table):
                end = None
        if end is not None and text[pos] in "#0123456789" and _SQL_NUMBER_NAME_RE.fullmatch(text, pos, end):
            end = None
        self._tables[key] = end
        return end

    def phrase_ends(self, pos: int, phrase: tuple[str, ...]) -> list[int]:
        """Where *phrase* ends when its first word stands at *pos*, in every reading of the gaps.

        The words after the first follow a gap or, where a word boundary
        allows it, directly (`CLUSTER"main"`).
        """
        key = (pos, phrase)
        found = self._phrases.get(key)
        if found is None:
            ends = [pos]
            for index, token in enumerate(phrase):
                reached = set()
                for at in ends:
                    for start in (at,) if index == 0 else self.gaps(at):
                        end = self._token_end(token, start)
                        if end is not None:
                            reached.add(end)
                ends = sorted(reached)
                if not ends:
                    break
            found = self._phrases[key] = ends
        return found

    def _token_end(self, token: str, pos: int) -> int | None:
        text = self.text
        if token in _SQL_PUNCTUATION:
            return pos + 1 if text.startswith(token, pos) else None
        if token == _SQL_NAME_TOKEN:
            return self.table_end(pos)
        if token in (_SQL_NUMBER_TOKEN, _SQL_VALUE_TOKEN):
            # These can run long, and keywords can reach the same one: memoized.
            key = (token, pos)
            if key not in self._token_ends:
                pattern = _SQL_VALUE_RE if token == _SQL_VALUE_TOKEN else self.grammar.token(token)
                m = pattern.match(text, pos)
                self._token_ends[key] = m.end() if m else None
            return self._token_ends[key]
        m = self.grammar.token(token).match(text, pos)
        return m.end() if m else None

    def _first_table_may_start(self, pos: int, start: int, brackets: bool) -> bool:
        """True when a table name may start at *start*, the end of the gap after the word ending at *pos*.

        A bare name needs a gap. A quoted plain identifier does not
        (`DELETE FROM"orders"`). Anything else glued on is text around the
        keyword: the quote closing the string it sits in (`{"mode": "TRUNCATE"}`),
        the next JSON string, or a regex (`DELETE FROM[ \\t]+`). A glued `[` is
        refused where *brackets* is false. The glued-name match is memoized.
        """
        if start > pos:
            return True
        text = self.text
        if start >= len(text) or (text[start] == "[" and not brackets):
            return False
        glued = self._glued.get(start)
        if glued is None:
            glued = self._glued[start] = _SQL_GLUED_NAME.match(text, start) is not None
        return glued

    def _joined(self, quote: int) -> int:
        """How the quote at *quote*, escaped or not, closes a string joined to what follows.

        0: not joined. _JOINED: joined, by `<<` or to something other than a
        name (`" + "more text"`). _JOINED_NAME: joined to a name (`" + name`).
        """
        found = self._concatenations.get(quote)
        if found is None:
            text = self.text
            closed = quote + 2 if text.startswith(("\\\"", "\\'", "\\`"), quote) else quote + 1
            m = None
            if closed == quote + 2 or text[quote:quote + 1] in ("\"", "'", "`"):
                m = _SQL_CONCATENATION.match(text, closed)
            if m is None:
                found = 0
            elif m.group(1) != "<<" and _SQL_NAME_AHEAD.match(text, m.end()):
                found = _JOINED_NAME
            else:
                found = _JOINED
            self._concatenations[quote] = found
        return found

    def _placeholder(self, start: int, end: int) -> bool:
        """True when the table from *start* to *end* is one placeholder, bare or quoted, and nothing else."""
        found = self._placeholders.get(start)
        if found is None:
            text = self.text
            if end - start >= 4 and text.startswith(("\\\"", "\\`", "\"\""), start):
                start_inner, end_inner = start + 2, end - 2
            elif end - start >= 2 and text[start] in _SQL_QUOTE_CLOSERS:
                start_inner, end_inner = start + 1, end - 1
            else:
                start_inner, end_inner = start, end
            found = self._placeholders[start] = (
                _SQL_PLACEHOLDER.fullmatch(text, start_inner, end_inner) is not None
            )
        return found

    def _identifier(self, start: int, end: int) -> bool:
        """True when the table from *start* to *end* is not one plain word: it holds a digit, `_`, a mark or a quote."""
        key = (start, end)
        found = self._identifiers.get(key)
        if found is None:
            word = _SQL_PLAIN_WORD.match(self.text, start)
            found = self._identifiers[key] = word is None or word.end() != end
        return found

    def _soft(self, start: int, end: int) -> bool:
        """True when the first table is a placeholder or a single-quoted string.

        `Delete from {name}` in JSX or an i18n file, `Delete from 'Recent'` in a
        menu: a name written this way is as much English or UI text as SQL, so
        it does not mark the statement (see the ``_FIRST_*`` scores).
        """
        return self.text[start] == "'" or self._placeholder(start, end)

    def _listed_tables(self, comma: int) -> list[int]:
        """Ends of the table after the comma at *comma*: a name, or ONLY and a name."""
        found = self._lists.get(comma)
        if found is None:
            text = self.text
            plain = self.grammar.plain_tables.match(text, comma)
            if plain:
                found = [plain.end()]
            else:
                ends = set()
                after = comma + 1
                for start in self.gaps(after, names=True):
                    if start > after:
                        for only in self.phrase_ends(start, ("ONLY",)):
                            for name in self.gaps(only, names=True):
                                end = self.table_end(name) if name > only else None
                                if end is not None:
                                    ends.add(end)
                    end = self.table_end(start)
                    if end is not None:
                        ends.add(end)
                found = sorted(ends)
            self._lists[comma] = found
        return found

    def _ending(self, pos: int, gap: int) -> int:
        """How the text at *gap*, where the gap after the token ending at *pos* ends, ends a statement.

        It depends on *pos* only through whether a line break comes between
        and whether the gap is empty, so it is memoized by those and *gap*:
        any number of keywords can reach the same gap (a comment can hold them).
        """
        broken = gap > pos and self.window.breaks_between(pos, gap)
        key = (gap, broken, gap == pos)
        found = self._endings.get(key)
        if found is None:
            found = self._endings[key] = self._gap_ending(gap, broken, gap == pos)
        return found

    def _gap_ending(self, gap: int, broken: bool, glued: bool) -> int:
        text = self.text
        if text.startswith(";", gap):
            return _STRONG if not broken and self._semicolon_ends(gap) else _WEAK
        if broken:
            markup = _SQL_MARKUP_LINE.match(text, gap) or (
                text[gap - 1] in " \t" and _SQL_ATTRIBUTE_LINE.match(text, gap)
            )
            return 0 if markup else _WEAK
        if gap == len(text):
            return _WEAK
        if not glued and _SQL_QUOTED_WORD.match(text, gap):
            return 0
        if text[gap] in "\"'`":
            # An apostrophe inside a word is not a quote: `TRUNCATE doesn't`.
            return 0 if glued and text[gap] == "'" and text[gap + 1:gap + 2].isalpha() else _WEAK
        if text.startswith(_SQL_ENDS, gap):
            return _WEAK
        if "A" <= text[gap] <= "Z" and _SQL_NEXT_STATEMENT.match(text, gap):
            return 0 if self._prose_follows(gap) else _WEAK
        return 0

    def _prose_follows(self, pos: int) -> bool:
        """True when two lower-case words in a row follow *pos* on its line, before any comment."""
        if self._lower_words is None:
            self._lower_words = [m.start() for m in _SQL_LOWER_WORDS.finditer(self.text)]
        after = _next_position(self._lower_words, pos)
        if after is None:
            return False
        window = self.window
        limits = [window._line_break(pos, True)] + [_next_position(window._index(c), pos) for c in ("--", "/*", "#")]
        return after < min((limit for limit in limits if limit is not None), default=len(self.text))

    def _semicolon_ends(self, pos: int) -> bool:
        found = self._semicolons.get(pos)
        if found is None:
            m = _SQL_AFTER_SEMICOLON.match(self.text, pos + 1)
            found = m is not None and not (m.group("keyword") and self._prose_follows(m.start("keyword")))
            self._semicolons[pos] = found
        return found

    def _edges(
        self, node: tuple[int, int, int, int]
    ) -> tuple[int, int | None, list[tuple[tuple[int, int, int, int], tuple[int, ...]]]]:
        """``(direct value, its span, [(next node, how it counts)])`` for *node*."""
        pos, kind, state, flags = node
        text, grammar = self.text, self.grammar
        direct, span, edges = 0, None, []
        if kind == _TAIL:
            for gap in self.gaps(pos):
                direct = max(direct, self._ending(pos, gap))
                edges.append(((gap, _GAP_END, state, flags), _SAME))
        elif kind == _GAP_END:
            char = text[pos:pos + 1]
            if char == "," and state in (_AFTER_TABLE, _AFTER_STAR) and grammar.comma_tables:
                edges.extend(((end, _TAIL, _AFTER_TABLE, flags), _SAME) for end in self._listed_tables(pos))
            elif char == "*" and state == _AFTER_TABLE:
                edges.append(((pos + 1, _TAIL, _AFTER_STAR, flags), _SAME))
            word = grammar.option_word.match(text, pos)
            # The gap-ends after the option's first word, for the second-word
            # guard below, computed once for every phrase that shares the word.
            after_word = self.gaps(word.end()) if word else ()
            for phrase, opens_list in grammar.option_phrases[word.lastgroup] if word else ():
                if phrase in grammar.table_options and not flags & _NAMED:
                    continue
                if phrase in grammar.object_options and not flags & _TAKES_ON:
                    continue
                if phrase in grammar.capital_options and not (flags & _NAMED or text.startswith(phrase[0], pos)):
                    continue
                # Skip a phrase whose fixed second word cannot follow, so a long
                # run of one option (`ON b\n` × n) does not walk the others'
                # phrases once per position (see SqlLinearTimeTests).
                neutral = phrase in grammar.neutral_options
                if neutral and state == _AFTER_NEUTRAL:
                    continue
                second = phrase[1] if len(phrase) > 1 else None
                if second is not None and second not in _SQL_TOKEN_STANDINS and second not in _SQL_PUNCTUATION:
                    if all(self._token_end(second, start) is None for start in after_word):
                        continue
                ends = self.phrase_ends(pos, phrase)
                if opens_list and ends:
                    direct = max(direct, _WEAK)
                elif not opens_list:
                    counts = _SAME if neutral else _THROUGH_OPTION
                    next_state = _AFTER_NEUTRAL if neutral else _AFTER_OPTION
                    edges.extend(((end, _TAIL, next_state, flags), counts) for end in ends)
        else:
            for start in self.gaps(pos, names=True):
                # A string that closes right after TABLE written in capitals can
                # be joined to a name (`["TRUNCATE TABLE", name]`); one that
                # closes right after TRUNCATE is more often a word in a list
                # (`["TRUNCATE", "DROP"]`), and a lower-case one a class list.
                glued_ok = flags & _NAMED and flags & _CAPITALS and flags & _LISTED
                # Without TABLE, the string must be joined to a name, and not by
                # `<<`, which also writes a message to a stream.
                if flags and (start > pos or glued_ok) and not direct:
                    joined = self._joined(start)
                    if joined == _JOINED_NAME or (joined and flags & _NAMED):
                        direct, span = (_SCORE_NAMED if flags & _NAMED else _SCORE_WEAK), start
                # SQL Server takes `[name]` only after TRUNCATE TABLE, so a `[`
                # glued to TRUNCATE is a subscript (`TRUNCATE[idx]`), not a name.
                if not self._first_table_may_start(pos, start, brackets=state > 0):
                    continue
                end = self.table_end(start, after_table=bool(flags & (_NAMED | _HEAD_READ)))
                if end is not None:
                    # After required words, a name written as no English word
                    # is marks SQL as capitals do (`drop table #staging`).
                    soft = self._soft(start, end)
                    if flags & _NAMED or (flags & _HEAD_READ and not soft and self._identifier(start, end)):
                        first = _FIRST_TABLE_NAMED
                    elif not flags & _LOWER_HEAD and (flags & _CAPITALS or not soft):
                        first = _FIRST_TABLE
                    else:
                        first = _FIRST_PLACEHOLDER
                    edges.append(((end, _TAIL, _AFTER_TABLE, flags & _TAIL_FLAGS), first))
            for gap in self.gaps(pos):
                word = grammar.head_word.match(text, gap) if gap > pos else None
                for group, phrase in grammar.head_phrases[word.lastgroup] if word else ():
                    if group >= state:
                        table = flags | (_NAMED if phrase in grammar.names_table else 0)
                        if group == 0 and not table & _NAMED and not text.startswith(phrase[0], gap):
                            table |= _LOWER_HEAD
                        ends = self.phrase_ends(gap, phrase)
                        edges.extend(((end, _HEAD, group + 1, table), _SAME) for end in ends)
                for phrase in grammar.head_lists if word and state == 0 else ():
                    ends = self.phrase_ends(gap, phrase) if phrase[0] == word.lastgroup else ()
                    if ends and direct < _SCORE_WEAK:
                        direct, span = _SCORE_WEAK, ends[0]
                for phrase in grammar.head_tables if word and state == 0 else ():
                    ends = self.phrase_ends(gap, phrase) if phrase[0] == word.lastgroup else ()
                    first = _FIRST_TABLE if text.startswith(phrase[0], gap) else _FIRST_PLACEHOLDER
                    edges.extend(((end, _TAIL, _AFTER_TABLE, flags & _TAIL_FLAGS), first) for end in ends)
        return direct, span, edges

    def _value(self, root: tuple[int, int, int, int]) -> int:
        values = self._values
        if root in values:
            return values[root]
        expanded = {}
        todo = [root]
        while todo:
            node = todo.pop()
            if node in values or node in expanded:
                continue
            direct, span, edges = self._edges(node)
            if direct == (_SCORE_STRONG if node[1] == _HEAD else _STRONG):
                values[node] = direct
                if node[1] == _HEAD:
                    self._spans[node] = span
                continue
            expanded[node] = (direct, span, edges)
            todo.extend(child for child, _ in edges)
        for node in sorted(expanded, reverse=True):
            best, span, edges = expanded[node]
            for child, counts in edges:
                value = counts[values[child]]
                if value > best:
                    best = value
                    span = self._spans.get(child) if counts is _SAME else child[0]
            values[node] = best
            if node[1] == _HEAD:
                self._spans[node] = span
        return values[root]


# ---------------------------------------------------------------------------
# TRUNCATE statements
# ---------------------------------------------------------------------------
#
# "truncate" is also an English verb, a CSS class and a function name. After
# TRUNCATE come optional words naming what it empties (TEMPORARY; TABLE,
# [ALL] TABLES FROM, DATABASE, SCHEMA, CLUSTER, MATERIALIZED VIEW, PARTITION
# or SUBPARTITION; IF EXISTS; ONLY), one or more tables separated by commas,
# any of TRUNCATE's own options (CASCADE, RESTART IDENTITY, DROP STORAGE,
# ...), and then the end of the statement (see "SQL statements read to their
# end"). TABLE is the mark of SQL: a statement ended only as English ends must
# begin where statements begin or name TABLE. A first table that is only a
# placeholder, or that follows a word such as DATABASE written in lower case,
# needs TRUNCATE in capitals, TABLE, a semicolon or an option, and a joined
# string TRUNCATE in capitals or TABLE, since markup builds class lists the
# same way (`class="truncate {{ extra }}"`). Lower-case `truncate` in a class
# list (`className="truncate block"`, `@apply truncate italic;`) and the
# coreutils command (`truncate --size 0 file`) are not read at all.

# `ALTER TABLE <name>`, read over the reversed text: TRUNCATE PARTITION follows it.
# The name is bounded, so a run of name characters that many keywords share is
# not read once per keyword.
_SQL_ALTER_TABLE_BEFORE = re.compile(
    r"[\w#@$.`\"\[\]]{1,300}\s+ELBAT\s+RETLA(?:(?![\w#@$])|(?=[nr]\\))", re.IGNORECASE
)
# The words between TRUNCATE and its first table, one group at a time, in order.
_SQL_TRUNCATE_HEADS = (
    (
        ("TABLE",), ("TEMPORARY", "TABLE"), ("TABLES", "FROM"), ("ALL", "TABLES", "FROM"), ("DATABASE",),
        ("SCHEMA",), ("CLUSTER",), ("MATERIALIZED", "VIEW"), ("PARTITION",), ("SUBPARTITION",),
    ),
    (("IF", "EXISTS"),),
    (("ONLY",),),
)
_SQL_TRUNCATE_NAMES_TABLE = (("TABLE",), ("TEMPORARY", "TABLE"))
# Bare words that cannot name a table without quotes: those TRUNCATE reads
# before its tables, and the reserved words.
_SQL_TRUNCATE_NOT_NAMES = frozenset(
    phrase[0] for group in _SQL_TRUNCATE_HEADS for phrase in group
) | _SQL_RESERVED_NAMES
# Words TRUNCATE reads before its tables that PostgreSQL does not reserve: after
# TABLE, where none of them can come next, a bare one is a table's name
# (`TRUNCATE TABLE schema;`).
_SQL_TRUNCATE_NAMES_AFTER_TABLE = frozenset(
    "TEMPORARY TABLES DATABASE SCHEMA CLUSTER MATERIALIZED PARTITION SUBPARTITION".split()
)
# Options after the tables, from PostgreSQL, Oracle, Db2, Informix, MariaDB,
# ClickHouse and HSQLDB. Another option or the end of the statement follows one.
_SQL_TRUNCATE_OPTIONS = (
    ("CASCADE",),
    ("RESTRICT", "WHEN", "DELETE", "TRIGGERS"),
    ("RESTRICT",),
    ("RESTART", "IDENTITY"),
    ("CONTINUE", "IDENTITY"),
    ("DROP", "ALL", "STORAGE"),
    ("DROP", "STORAGE"),
    ("REUSE", "STORAGE"),
    ("PRESERVE", "MATERIALIZED", "VIEW", "LOG"),
    ("PURGE", "MATERIALIZED", "VIEW", "LOG"),
    ("PRESERVE", "SNAPSHOT", "LOG"),
    ("PURGE", "SNAPSHOT", "LOG"),
    ("IGNORE", "DELETE", "TRIGGERS"),
    ("IMMEDIATE",),
    ("KEEP", "STATISTICS"),
    ("SYNC",),
    ("NOWAIT",),
    ("WAIT", _SQL_NUMBER_TOKEN),
    ("ON", "CLUSTER", _SQL_VALUE_TOKEN),
    ("UPDATE", "GLOBAL", "INDEXES"),
    ("UPDATE", "INDEXES"),
    ("AND", "COMMIT", "NO", "CHECK"),
    ("AND", "COMMIT"),
    ("LIKE", _SQL_VALUE_TOKEN),
    ("NOT", "LIKE", _SQL_VALUE_TOKEN),
    ("PARTITION", _SQL_NAME_TOKEN),
)
# Options read only after TRUNCATE TABLE: Sybase ASE's partition
# (`TRUNCATE TABLE titles PARTITION p1`), since English writes `truncate the
# partition first`.
_SQL_TRUNCATE_TABLE_OPTIONS = frozenset({("PARTITION", _SQL_NAME_TOKEN)})
# Options read only when written in capitals or after TABLE, as HSQLDB and
# ClickHouse write them: English writes `truncate logs and commit`, `truncate
# names like 'this'`, `truncate logs on cluster east`, `truncate text settings`.
_SQL_TRUNCATE_CAPITAL_OPTIONS = frozenset({
    ("AND", "COMMIT", "NO", "CHECK"),
    ("AND", "COMMIT"),
    ("LIKE", _SQL_VALUE_TOKEN),
    ("NOT", "LIKE", _SQL_VALUE_TOKEN),
    ("ON", "CLUSTER", _SQL_VALUE_TOKEN),
    ("SETTINGS", _SQL_NAME_TOKEN, "="),
})
# Options that open a list (SQL Server partitions; a Spark, Hive or Doris
# partition spec; ClickHouse settings); the statement is read no further.
_SQL_TRUNCATE_LISTS = (
    ("WITH", "(", "PARTITIONS"),
    ("PARTITION", "(", _SQL_NAME_TOKEN, "="),
    ("PARTITION", "(", _SQL_NAME_TOKEN, ","),
    ("PARTITION", "(", _SQL_NAME_TOKEN, ")"),
    ("SETTINGS", _SQL_NAME_TOKEN, "="),
)
# In place of a partition's name, an Oracle partition key (`PARTITION FOR (...)`).
_SQL_TRUNCATE_HEAD_LISTS = (
    ("PARTITION", "FOR", "("),
    ("SUBPARTITION", "FOR", "("),
)
# In place of the tables, MySQL's every partition (`ALTER TABLE t TRUNCATE
# PARTITION ALL`), which an ending must follow like a table.
_SQL_TRUNCATE_HEAD_TABLES = (("PARTITION", "ALL"),)
_SQL_TRUNCATE_GRAMMAR = _SqlGrammar(
    heads=_SQL_TRUNCATE_HEADS,
    names_table=_SQL_TRUNCATE_NAMES_TABLE,
    options=_SQL_TRUNCATE_OPTIONS,
    lists=_SQL_TRUNCATE_LISTS,
    head_lists=_SQL_TRUNCATE_HEAD_LISTS,
    head_tables=_SQL_TRUNCATE_HEAD_TABLES,
    table_options=_SQL_TRUNCATE_TABLE_OPTIONS,
    capital_options=_SQL_TRUNCATE_CAPITAL_OPTIONS,
    not_names=_SQL_TRUNCATE_NOT_NAMES,
    names_after_table=_SQL_TRUNCATE_NAMES_AFTER_TABLE,
)
# A Tailwind `@apply` list in CSS: `@apply` where a declaration starts (after
# `{`, `;` or `}`, unlike a T-SQL variable in `IF @apply = 1`), and the class
# names after it, over line breaks, up to a `;`, a brace or the end of a
# comment; or, at the start of the text, the class names on its line.
_SQL_APPLY_LIST = re.compile(
    r"\A[ \t]*@apply(?:[ \t]+(?:(?!\*/)[^\s;{}])+)+|[{};]\s*@apply(?:\s+(?:(?!\*/)[^\s;{}])+)+"
)
# GNU coreutils `truncate`, a lower-case command, with a long option, which is
# not a SQL comment there.
_SQL_TRUNCATE_COREUTILS = re.compile(r"[ \t]+--(?:size|reference|no-create|io-blocks)\b")
# Read over the reversed text before lower-case `truncate`: the quote opening a
# string of class names after a class attribute or a class helper
# (`className="truncate block"`, Vue `:class="['truncate block', ...]"`, Blade
# `@class([...])`, twin.macro `tw.h2\`truncate block\``, `cn(...)`, `clsx(...)`).
_SQL_CLASS_STRING_BEFORE = re.compile(
    r"[\"'`][\s\[({\"'`]{0,8}(?:=\s*(?:emaNssalc|ssalc:?|ssalCgn)(?![\w-])"
    r"|(?:nc|xslc|xc|semanssalc|egreMwt|ssalc@)(?!\w)|\w{1,10}\.wt(?!\w))",
    re.IGNORECASE,
)


class _TruncateReader(_SqlStatementReader):
    """Reads the TRUNCATE statements in one scan window (see "TRUNCATE statements")."""

    keyword = "TRUNCATE"
    grammar = _SQL_TRUNCATE_GRAMMAR

    def __init__(self, window: _SqlWindow) -> None:
        super().__init__(window)
        self._applies: tuple[list[int], list[int]] | None = None

    def _skips(self, keyword_start: int, keyword_end: int) -> bool:
        """True for lower-case `truncate` in a class list or the coreutils command."""
        return self.text[keyword_start:keyword_end] == "truncate" and bool(
            self._after_apply(keyword_start, keyword_end)
            or _SQL_TRUNCATE_COREUTILS.match(self.text, keyword_end)
            or _SQL_CLASS_STRING_BEFORE.match(self._reversed_text(), len(self.text) - keyword_start)
        )

    def _opens_statement(self, reversed_text: str, before: int) -> bool:
        """True after `ALTER TABLE <name>`, which TRUNCATE PARTITION follows."""
        return _SQL_ALTER_TABLE_BEFORE.match(reversed_text, before) is not None

    def _after_apply(self, start: int, end: int) -> bool:
        """True when the keyword from *start* to *end* is the Tailwind class in an `@apply` list.

        The list is in CSS and runs over class names up to a `;`, a brace or
        a comment end (see _SQL_APPLY_LIST), so `/* @apply */ truncate ...`
        and `IF @apply = 1 truncate ...` are not in one.
        """
        if self._applies is None:
            lists = [m.span() for m in _SQL_APPLY_LIST.finditer(self.text)] if "@apply" in self.text else []
            self._applies = ([s for s, _ in lists], [e for _, e in lists])
        starts, ends = self._applies
        index = bisect_left(starts, start) - 1
        return index >= 0 and ends[index] >= end


def _sql_truncate(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    reader = window.statement_reader("sql.truncate", _TruncateReader)
    for m in pattern.keyword_re.finditer(window.text):
        end = reader.match_end(m.start(), m.end())
        if end is not None:
            # Like `TRUNCATE\s+(?:TABLE\s+)?\w+`, the match runs to the first
            # table, so the excerpt around it keeps its length.
            return _SqlMatch(m.start(), end)
    return None


# ---------------------------------------------------------------------------
# DROP statements
# ---------------------------------------------------------------------------
#
# English drops things too: "drag and drop table rows to reorder them", "drop
# database connections that have been idle", "drop index cards on the
# board". A DROP rule reads the statement (see "SQL statements read to their
# end"): DROP and what it drops, which it requires (TABLE or TEMPORARY TABLE;
# DATABASE or SCHEMA; INDEX, VIEW, MATERIALIZED VIEW or TRIGGER), then
# CONCURRENTLY for an index and IF EXISTS, one or more names separated by
# commas, any of DROP's options (CASCADE, RESTRICT, PURGE, ...), and the end of
# the statement. What DROP drops says which rule the statement is for. The mark
# of SQL is capitals or the name: with DROP and what it drops both written in
# capitals, as SQL conventionally is, or with a first name that no English
# word is (`#staging`, `user_sessions`, `dbo.users`, quoted, a placeholder), an
# ending that English also has counts wherever the statement stands (`Run
# DROP TABLE users`); otherwise the statement must begin where statements
# begin or end as only SQL ends. Oracle's `DROP DATABASE;` names no database,
# and counts before a semicolon that ends the statement.

# What DROP drops, the rule each is for, and the flags it gives the statement.
_SQL_DROP_OBJECTS = {
    ("TABLE",): _DROPS_TABLE,
    ("TEMPORARY", "TABLE"): _DROPS_TABLE,
    ("DATABASE",): _DROPS_DATABASE,
    ("SCHEMA",): _DROPS_DATABASE,
    ("INDEX",): _DROPS_INDEX | _TAKES_ON,
    ("VIEW",): _DROPS_INDEX,
    ("MATERIALIZED", "VIEW"): _DROPS_INDEX,
    ("TRIGGER",): _DROPS_INDEX | _TAKES_ON,
}
_SQL_DROP_RULES = {
    _DROPS_TABLE: "sql.drop_table",
    _DROPS_DATABASE: "sql.drop_database",
    _DROPS_INDEX: "sql.drop_index",
}
_SQL_DROPS = _DROPS_TABLE | _DROPS_DATABASE | _DROPS_INDEX
# The table an index or a trigger is on (MySQL and SQL Server `DROP INDEX idx
# ON t`, PostgreSQL `DROP TRIGGER trg ON t`, SQL Server's `ON ALL SERVER`),
# which English also writes after other words (`drop table rows on click`).
_SQL_DROP_ON = (("ON", "ALL", "SERVER"), ("ON", _SQL_NAME_TOKEN))
_SQL_DROP_GRAMMAR = _SqlGrammar(
    heads=(tuple(_SQL_DROP_OBJECTS), (("CONCURRENTLY",),), (("IF", "EXISTS"),)),
    head_required=True,
    head_flags=_SQL_DROP_OBJECTS,
    # Options after the names, from PostgreSQL, MySQL, SQL Server, Oracle, Hive,
    # Spark, Snowflake and ClickHouse: Oracle's CASCADE CONSTRAINTS, PURGE,
    # ONLINE, FORCE and PRESERVE TABLE, MySQL's ALGORITHM and LOCK,
    # PostgreSQL's `WITH (FORCE)`, and SQL Server's `WITH (ONLINE = ON)`, a list.
    # ClickHouse's are read only when written in capitals or in a statement with
    # the mark, as for TRUNCATE.
    options=(
        ("CASCADE", "CONSTRAINTS"),
        ("CASCADE",),
        ("RESTRICT",),
        ("PURGE",),
        ("SYNC",),
        ("NO", "DELAY"),
        ("ON", "CLUSTER", _SQL_VALUE_TOKEN),
        ("WITH", "(", "FORCE", ")"),
        ("ONLINE",),
        ("FORCE",),
        ("PRESERVE", "TABLE"),
        ("ALGORITHM", "=", _SQL_VALUE_TOKEN),
        ("ALGORITHM", _SQL_VALUE_TOKEN),
        ("LOCK", "=", _SQL_VALUE_TOKEN),
        ("LOCK", _SQL_VALUE_TOKEN),
    ) + _SQL_DROP_ON,
    lists=(("WITH", "("),),
    capital_options=frozenset({("NO", "DELAY"), ("ON", "CLUSTER", _SQL_VALUE_TOKEN)}),
    object_options=frozenset(_SQL_DROP_ON),
    neutral_options=frozenset(_SQL_DROP_ON),
    # Bare words that cannot name what DROP drops: the reserved words, and the
    # words DROP reads between what it drops and its names. After those, the
    # names may be anything else (`DROP TABLE schema;`).
    not_names=_SQL_RESERVED_NAMES | frozenset({"IF", "CONCURRENTLY"}),
    string_names=True,
)
# Read over the reversed text before DROP: what an ALTER TABLE specification
# follows, the name after ALTER TABLE or the comma after another specification
# (MySQL's `ALTER TABLE t DROP INDEX a, ADD INDEX b (c)`). A specification ends
# at the next comma as well as with the statement.
_SQL_ALTER_SPEC_BEFORE = re.compile(
    r"(?P<comma>\s*,)|\s+[\w#@$.`\"\[\]]{1,300}\s+ELBAT\s+RETLA(?![\w#@$])", re.IGNORECASE
)
_SQL_ALTER_TABLE = re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE)


class _DropReader(_SqlStatementReader):
    """Reads the DROP statements in one scan window, for all three DROP rules (see "DROP statements")."""

    keyword = "DROP"
    grammar = _SQL_DROP_GRAMMAR

    def __init__(self, window: _SqlWindow) -> None:
        super().__init__(window)
        self._rule_ends: dict[int, dict[str, int | None]] = {}
        self._alters: list[int] | None = None

    def rule_ends(self, keyword_start: int, keyword_end: int) -> dict[str, int | None]:
        """``{rule id: end of the first name}`` for the statements DROP begins here, memoized for the three rules."""
        found = self._rule_ends.get(keyword_start)
        if found is None:
            text = self.text
            capitals = text[keyword_start:keyword_end] == self.keyword
            flags = _CAPITALS if capitals else 0
            if capitals and _SQL_JOINED_LIST_BEFORE.match(self._reversed_text(), len(text) - keyword_start):
                flags |= _LISTED
            if self._in_alter_table(keyword_start):
                flags |= _IN_ALTER
            scores: dict[str, tuple[int, int | None]] = {}
            for root in self._roots(keyword_end, flags):
                rule_id = _SQL_DROP_RULES[root[3] & _SQL_DROPS]
                value = self._value(root)
                if value > scores.get(rule_id, (0, None))[0]:
                    scores[rule_id] = (value, self._spans[root])
            found = {
                rule_id: span
                for rule_id, (score, span) in scores.items()
                if score >= _SCORE_NAMED or (score == _SCORE_WEAK and self.statement_start(keyword_start, capitals))
            }
            self._rule_ends[keyword_start] = found
        return found

    def _in_alter_table(self, keyword_start: int) -> bool:
        """True when the DROP at *keyword_start* is a specification of an ALTER TABLE statement.

        It follows the table's name, or a comma after an ALTER TABLE that no
        semicolon has ended.
        """
        before = _SQL_ALTER_SPEC_BEFORE.match(self._reversed_text(), len(self.text) - keyword_start)
        if before is None or before.group("comma") is None:
            return before is not None
        if self._alters is None:
            self._alters = [m.start() for m in _SQL_ALTER_TABLE.finditer(self.text)]
        index = bisect_left(self._alters, keyword_start) - 1
        if index < 0:
            return False
        semicolon = _next_position(self.window._index(";"), self._alters[index])
        return semicolon is None or semicolon > keyword_start

    def _edges(
        self, node: tuple[int, int, int, int]
    ) -> tuple[int, int | None, list[tuple[tuple[int, int, int, int], tuple[int, ...]]]]:
        direct, span, edges = super()._edges(node)
        pos, kind, state, flags = node
        if kind == _TAIL and flags & _IN_ALTER and direct < _STRONG:
            if any(self.text.startswith(",", gap) for gap in self.gaps(pos)):
                direct = _STRONG
        # Straight after DATABASE or SCHEMA: Oracle's `DROP DATABASE;`, before a
        # semicolon that ends the statement.
        if kind == _HEAD and state == 1 and flags & _DROPS_DATABASE and direct < _SCORE_STRONG:
            for gap in self.gaps(pos):
                if self.text.startswith(";", gap) and self._ending(pos, gap) == _STRONG:
                    direct, span = _SCORE_STRONG, pos
        return direct, span, edges


def _sql_drop(rule_id: str) -> Callable[[_SqlWindow, _SqlPattern], _SqlMatch | None]:
    """Finish the DROP rule *rule_id*: the first DROP statement that drops what the rule is for."""

    def finish(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
        reader = window.statement_reader("sql.drop", _DropReader)
        for m in pattern.keyword_re.finditer(window.text):
            end = reader.rule_ends(m.start(), m.end()).get(rule_id)
            if end is not None:
                return _SqlMatch(m.start(), end)
        return None

    return finish


# ---------------------------------------------------------------------------
# DELETE and UPDATE statements
# ---------------------------------------------------------------------------
#
# "Delete from the list any items you no longer need", "tap Delete from
# Library to remove the song", "we update the set of rules every week": the
# no-WHERE rules read a statement too. DELETE requires FROM, then ONLY, one
# table and an optional `*`, an alias (after AS, quoted, or bare), SQLite's
# INDEXED BY or NOT INDEXED, and the end of the statement; or a clause the rule
# reads no further (RETURNING, OUTPUT, ORDER BY, LIMIT, WITH (...), OPTION
# (...), PARTITION (...)). Capitals and names mark SQL as they do for DROP. A
# bare alias counts only before one of those clauses: `delete from local
# storage` is English. An ending that a WHERE follows in the same statement
# does not count (see _SqlWindow.lacks_where), as before. UPDATE names a table,
# then SET and an assignment: a column and `=` or a compound operator such as
# `+=`, a column list in parentheses and `=`, a placeholder that the end of the
# statement follows (`SET %s`), or a string joined to what follows (`"UPDATE t
# SET " + sets`).

# After a table and its `*`: an alias read after AS or in quotes, which the
# end of the statement may follow, or a bare one, which only a clause may.
_AFTER_ALIAS, _AFTER_BARE_ALIAS = 3, 4
_SQL_DELETE_GRAMMAR = _SqlGrammar(
    heads=((("FROM",),), (("ONLY",),)),
    head_required=True,
    options=(("INDEXED", "BY", _SQL_NAME_TOKEN), ("NOT", "INDEXED")),
    lists=(
        ("RETURNING",),
        ("OUTPUT",),
        ("ORDER", "BY"),
        ("LIMIT",),
        ("WITH", "("),
        ("OPTION", "("),
        ("PARTITION", "("),
        ("USING",),
    ),
    # USING is read only when written in capitals or in a statement with the
    # mark: English deletes from a disk using a tool.
    capital_options=frozenset({("USING",)}),
    neutral_options=frozenset({("INDEXED", "BY", _SQL_NAME_TOKEN), ("NOT", "INDEXED")}),
    comma_tables=False,
    not_names=_SQL_RESERVED_NAMES | frozenset({"ONLY", "OUTPUT", "OPTION", "PARTITION", "INDEXED"}),
    string_names=True,
)
_SQL_AS = ("AS",)
# Reversed, before DELETE: the parenthesis after AS that opens a common table
# expression's body (`WITH d AS (DELETE FROM t RETURNING *) ...`, `WITH
# RECURSIVE d AS (...)`, `WITH d(id) AS (...)`), and PostgreSQL's EXPLAIN with
# ANALYZE, which runs the statement it explains (`explain analyze delete from
# t`, `explain (analyze, buffers) delete ...`).
_SQL_DELETE_OPENER_BEFORE = re.compile(
    r"\(\s*sa(?![\w#@$])\s*(?:\)[^()\n]{0,200}\(\s*)?[\w\"'`.\[\]$#@-]{1,64}?\s+(?:(?:evisrucer\s+)?htiw(?![\w])|,)"
    r"|(?:esobrev\s+)?(?:ezylana|esylana)\s+nialpxe(?![\w#@$])"
    r"|\)(?=[^()\n]{0,100}?(?:ezylana|esylana))[^()\n]{0,100}\(\s*nialpxe(?![\w#@$])",
    re.IGNORECASE,
)
# The characters outside a word that a name read by _SqlStatementReader.table_end
# can hold: quotes and brackets, the marks of placeholders, and the separators of
# its parts. A word alone can hold WHERE only by being it, and WHERE names nothing.
_SQL_NAME_MARKS = "\"'`[]{}()<>\\#@$.:&%-"


class _DeleteReader(_SqlStatementReader):
    """Reads DELETE statements without WHERE in one scan window (see "DELETE and UPDATE statements")."""

    keyword = "DELETE"
    grammar = _SQL_DELETE_GRAMMAR

    def __init__(self, window: _SqlWindow) -> None:
        super().__init__(window)
        self._name_marks: list[int] | None = None

    def _opens_statement(self, reversed_text: str, before: int) -> bool:
        """True after a common table expression's `AS (` or an EXPLAIN that analyzes (see _SQL_DELETE_OPENER_BEFORE)."""
        return _SQL_DELETE_OPENER_BEFORE.match(reversed_text, before) is not None

    def match_end(self, keyword_start: int, keyword_end: int) -> int | None:
        """End of the table of the DELETE without WHERE that begins here, or None.

        An ending counts only where no WHERE follows before the statement
        stops, and the statement is read from after its table. So when a
        WHERE follows DELETE before the stop, only a name that holds that
        WHERE can take the statement past it, and a name that holds one also
        holds a quote, a bracket, a placeholder's mark or another character
        outside a word. Without one of those between DELETE and the WHERE,
        nothing can match and the statement is not read (see _SQL_NAME_MARKS).
        """
        where = self.window.where_ahead(keyword_end)
        if where is not None:
            if self._name_marks is None:
                self._name_marks = sorted(chain.from_iterable(
                    self.window._index(mark) for mark in _SQL_NAME_MARKS
                ))
            # A name can begin at the WHERE itself (`WHERE$x`, a SQLite table),
            # whose first mark is at where + len("WHERE"); a name that reaches
            # past the WHERE holds a mark at or before that.
            mark = _next_position(self._name_marks, keyword_end)
            if mark is None or mark > where + 5:
                return None
        return super().match_end(keyword_start, keyword_end)

    def _edges(
        self, node: tuple[int, int, int, int]
    ) -> tuple[int, int | None, list[tuple[tuple[int, int, int, int], tuple[int, ...]]]]:
        direct, span, edges = super()._edges(node)
        pos, kind, state, flags = node
        lacks_where = self.window.lacks_where
        if kind == _TAIL:
            # One before a WHERE does not end the statement. After a bare alias
            # only a strong ending does: `delete from local storage` is English.
            if not lacks_where(pos) or (state == _AFTER_BARE_ALIAS and direct != _STRONG):
                direct = 0
        elif kind == _GAP_END:
            if direct and not lacks_where(pos):
                direct = 0
            if state in (_AFTER_TABLE, _AFTER_STAR):
                edges.extend(self._aliases(pos, flags))
        elif direct and not lacks_where(span if span is not None else pos):
            direct = 0
        return direct, span, edges

    def _aliases(self, pos: int, flags: int) -> list[tuple[tuple[int, int, int, int], tuple[int, ...]]]:
        """Edges to the end of an alias at *pos*: after AS, quoted, or bare."""
        text, found = self.text, []
        for as_end in self.phrase_ends(pos, _SQL_AS):
            for start in self.gaps(as_end, names=True):
                if self._first_table_may_start(as_end, start, brackets=True):
                    end = self.table_end(start)
                    if end is not None:
                        found.append(((end, _TAIL, _AFTER_ALIAS, flags), _SAME))
        end = self.table_end(pos)
        if end is not None:
            state = _AFTER_ALIAS if text[pos] in _SQL_QUOTE_CLOSERS or text[pos] == "'" else _AFTER_BARE_ALIAS
            found.append(((end, _TAIL, state, flags), _SAME))
        return found


def _sql_delete_no_where(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    text = window.text
    reader = window.statement_reader("sql.delete_no_where", _DeleteReader)
    for m in pattern.keyword_re.finditer(text):
        end = reader.match_end(m.start(), m.end())
        if end is not None:
            return _SqlMatch(m.start(), _SQL_TERMINATOR.search(text, end).end())
    return None


_SQL_SET = re.compile(r"SET\b", re.IGNORECASE)
# An assignment after a column: `=`, not `==` or `=>`, one of T-SQL's compound
# operators (`+=`, `|=`, ...), or `:=`.
_SQL_ASSIGNMENT = re.compile(r"[-+*/%&^|:]?=(?![=>])")
# Subscripts after a column (PostgreSQL's `SET tags[1] = ...`).
_SQL_SUBSCRIPTS = re.compile(r"(?:\[[^\[\]\n]*\])+")
# A column list in parentheses (`SET (a, b) = (1, 2)`), with no parenthesis
# inside, so a scan from one `(` never passes another.
_SQL_COLUMN_LIST = re.compile(r"\([^()\n]*\)")
_SQL_UPDATE_GRAMMAR = _SqlGrammar(heads=(), options=(), not_names=_SQL_RESERVED_NAMES, string_names=True)


class _UpdateReader(_SqlStatementReader):
    """Reads UPDATE statements without WHERE in one scan window (see "DELETE and UPDATE statements")."""

    keyword = "UPDATE"
    grammar = _SQL_UPDATE_GRAMMAR

    def __init__(self, window: _SqlWindow) -> None:
        super().__init__(window)
        self._assignments: dict[int, bool] = {}
        self._assignment_starts: dict[int, bool] = {}

    def match_end(self, keyword_start: int, keyword_end: int) -> int | None:
        """End of SET in the statement UPDATE begins here, when an assignment follows and no WHERE, or None."""
        text = self.text
        capitals = text[keyword_start:keyword_end] == self.keyword
        for start in self.gaps(keyword_end, names=True):
            if not self._first_table_may_start(keyword_end, start, brackets=True):
                continue
            end = self.table_end(start, after_table=True)
            if end is None:
                continue
            if self._soft(start, end) and not capitals:
                continue
            for gap in self.gaps(end):
                # With no gap, SET can only follow a closing quote (`"users"SET`):
                # a bare name would have taken its letters.
                set_m = _SQL_SET.match(text, gap)
                if set_m and self._assigns(set_m.end()) and self.window.lacks_where(set_m.end()):
                    return set_m.end()
        return None

    def _assigns(self, pos: int) -> bool:
        """True when an assignment follows the SET that ends at *pos*; memoized, as keywords can share one SET."""
        found = self._assignments.get(pos)
        if found is None:
            text = self.text
            found = False
            for start in self.gaps(pos, names=True):
                if start == pos and text[pos:pos + 1] not in ("(", "\"", "`", "["):
                    continue
                if self._assignment_at(start):
                    found = True
                    break
            self._assignments[pos] = found
        return found

    def _assignment_at(self, start: int) -> bool:
        """True when an assignment starts at *start*; memoized, as the gaps after many SETs can end there."""
        found = self._assignment_starts.get(start)
        if found is None:
            found = self._assignment_starts[start] = self._read_assignment(start)
        return found

    def _read_assignment(self, start: int) -> bool:
        text = self.text
        if text.startswith("(", start):
            columns = _SQL_COLUMN_LIST.match(text, start)
            targets = [columns.end()] if columns else []
        else:
            end = self.table_end(start)
            subscripts = _SQL_SUBSCRIPTS.match(text, end) if end is not None else None
            targets = [end] if end is not None else []
            if subscripts:
                targets.append(subscripts.end())
        for target in targets:
            for gap in self.gaps(target):
                if _SQL_ASSIGNMENT.match(text, gap):
                    return True
        # The assignments written by code: a placeholder that the end of the
        # statement follows, or the string holding UPDATE closing and joined.
        placeholder = _SQL_PLACEHOLDER.match(text, start)
        if placeholder and any(self._ending(placeholder.end(), gap) for gap in self.gaps(placeholder.end())):
            return True
        return text[start:start + 1] in ("\"", "'", "`", "\\") and self._joined(start) != 0


def _sql_update_no_where(window: _SqlWindow, pattern: _SqlPattern) -> _SqlMatch | None:
    text = window.text
    reader = window.statement_reader("sql.update_no_where", _UpdateReader)
    for m in pattern.keyword_re.finditer(text):
        end = reader.match_end(m.start(), m.end())
        if end is not None:
            return _SqlMatch(m.start(), _SQL_TERMINATOR.search(text, end).end())
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
# A whole-word root, home or working-directory glob target, matched as a literal
# path token. ``/`` and globs of root (``/*``, ``//``, ``/*/``), and ``~`` and
# ``$HOME`` alone or as a glob of their contents (``~/``, ``~/*``, ``$HOME/*``),
# count wherever they stand among the operands. A bare ``*`` (a glob of the
# working directory) and ``./*`` count as the last operand, or when another
# operand (a word that is not an option) follows — ``rm -r * .git`` wipes the
# directory just as ``rm -r *`` does. A ``*`` does not count when an option
# follows, so a ``*`` that is the value of an option, such as
# ``aws s3 rm --recursive --exclude * --include ...``, is not a root wipe. A
# ``/``, ``~/`` or ``*`` followed by a name is a narrower path (``/etc``,
# ``~/.cache``, ``/tmp/*``, ``*.pyc``), left to the generic rule. ``_AFTER_TARGET``
# ends the token — a redirection glued straight onto it (``rm -r ~>/dev/null``)
# ends it as ``<`` and ``>`` do to a shell.
_AFTER_TARGET = r"(?=[\s\"';&|()`\\#<>]|$)"
#: A ``/``, ``~`` or ``$HOME`` root token, alone or globbing its contents.
#: Shared with the ``fs.find_delete_root`` rule below.
_ROOT_PATH = r"(?:/[/*]*|~(?:/[/*]*)?|\$HOME(?:/[/*]*)?)"
_RM_ROOT_TARGET = _rm_argument(
    r"(?:" + _ROOT_PATH + _AFTER_TARGET
    + r"|(?:\./)?\*(?=\s*(?:[" + _CMD_BREAK + r"#]|$)|\s+[^-\s" + _CMD_BREAK + r"#]))"
)


# ---------------------------------------------------------------------------
# find … -delete / -exec rm  (a filesystem wipe by another name)
# ---------------------------------------------------------------------------
#
# A ``find`` rooted at ``/``, ``~`` or ``$HOME`` that deletes — ``-delete`` or an
# ``-exec``/``-execdir`` that runs ``rm`` — removes the tree just as ``rm -rf``
# would, and no ``rm`` rule sees it. This reads one ``find`` command (the same
# ``_CMD_CHAR`` boundary and ``_CMD_START`` gating as the ``rm`` rules, so many
# ``find`` words cost a fixed number of passes, not one squared) and fires when
# a root/home path token and a deleting action both stand somewhere in it. The
# path may be a later operand (``find /home / -delete`` deletes ``/`` too), so
# both are free-floating lookaheads. It is root-restricted, so an ordinary
# ``find . -name '*.pyc' -delete`` or ``find /var/log -mtime +30 -delete`` is
# spared, and it needs a deleting action, so a read-only ``find / -name x`` is.
# Like the ``rm`` rules it screens command *text*, so a break-free prose line
# that strings together ``find``, a bare ``/`` and ``-delete`` is over-flagged;
# that is accepted (a real ``find / -delete`` must not slip), as ``rm -r /`` in
# prose is.
_FIND_COMMAND_START = (
    _CMD_START
    + r"(?=(?P<find_before>" + _CMD_CHAR + r"*?)find(?<![-\w]find)(?=[\s\"'<>]))"
    + r"(?P=find_before)"
)
#: The action: ``-delete``, or an ``-exec``/``-execdir`` whose command is ``rm``
#: (optionally ``sudo`` and/or a path such as ``/bin/rm``).
_FIND_ACTION = (
    r"(?:-delete(?![\w-])"
    r"|-exec(?:dir)?\s+(?:sudo\s+)?(?:\S+/)?rm(?![\w-]))"
)
_FIND_DELETE_ROOT = (
    _FIND_COMMAND_START
    + _rm_argument(_ROOT_PATH + _AFTER_TARGET)
    + _rm_argument(_FIND_ACTION)
    + r"(?P<find_command>find" + _CMD_CHAR + r"*)"
)


# ---------------------------------------------------------------------------
# Shell normalization for the rm / find rules
# ---------------------------------------------------------------------------
#
# The rm and find rules read one command with a boundary that approximates a
# shell's rather than parsing it, so a genuinely destructive command whose flag
# or target lands past a quote, a command substitution, an ${IFS} token or an
# &-bearing redirection can screen `none`. Those rules (``_ActionRule.normalize``)
# are therefore also searched over a normalized reading of the text, which
# resolves the constructs a shell would:
#
# * `$(...)` command substitutions (nested) and backtick runs -> a space;
# * `${IFS}` / `$IFS` (the field separator) -> a space;
# * an `&`-bearing fd redirection (`2>&1`, `>&2`, `&>`) -> a space;
# * a single-quoted token -> its contents (`'a.txt'` -> `a.txt`, `''` -> ``).
#
# The normalized reading is scanned AFTER the raw one, so it can only ADD a
# finding, never drop one. Single quotes are unquoted but double quotes are NOT:
# the payload may be a tool call serialized as JSON, where `"` delimits fields,
# so unquoting it would join a neighbouring field to the command; JSON never uses
# `'` as a delimiter, so unquoting `'...'` leaves the `"` command boundary
# intact.
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS\b")
_FD_REDIRECT_RE = re.compile(r"[0-9]*(?:>&|<&)[0-9-]*|&>>?")
_BACKTICK_RE = re.compile(r"`[^`]*`")
_SINGLE_QUOTED_RE = re.compile(r"'([^']*)'")


def _strip_command_subst(text: str) -> str:
    """Replace ``$(...)`` (nested) and backtick runs with a space.

    A single left-to-right pass tracking ``$(`` nesting depth — linear even on
    many unbalanced openers, where re-scanning for a close from every opener
    would be quadratic. An unterminated ``$(`` drops the rest of the text.
    """
    if "`" in text:
        text = _BACKTICK_RE.sub(" ", text)
    if "$(" not in text:
        return text
    out: list[str] = []
    i, n, depth = 0, len(text), 0
    while i < n:
        c = text[i]
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            depth += 1
            i += 2
            continue
        if depth:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    if depth:
        out.append(" ")
    return "".join(out)


def _shell_normalize(text: str) -> str:
    """A small shell approximation for the rm / find rules; see the block above.

    Returns *text* unchanged when it holds none of the constructs, so the common
    payload adds no second scan.
    """
    if not ("'" in text or "$(" in text or "`" in text
            or "IFS" in text or ">&" in text or "<&" in text or "&>" in text):
        return text
    text = _strip_command_subst(text)
    text = _IFS_RE.sub(" ", text)
    text = _FD_REDIRECT_RE.sub(" ", text)
    text = _SINGLE_QUOTED_RE.sub(r"\1", text)
    return text


_RULES: tuple[_ActionRule, ...] = (
    # ── SQL: irreversible schema / data destruction ──────────────────────
    # Gaps between keywords may hold comments; see "SQL statements" above.
    # Each rule reads a statement, not its keywords: see "SQL statements read
    # to their end" and the sections after it.
    _ActionRule(
        rule_id="sql.drop_database",
        name="DROP DATABASE / SCHEMA",
        severity=ActionSeverity.CRITICAL,
        pattern=_SqlPattern("DROP", _sql_drop("sql.drop_database")),
    ),
    _ActionRule(
        rule_id="sql.drop_table",
        name="DROP TABLE",
        severity=ActionSeverity.CRITICAL,
        pattern=_SqlPattern("DROP", _sql_drop("sql.drop_table")),
    ),
    _ActionRule(
        rule_id="sql.truncate",
        name="TRUNCATE TABLE",
        severity=ActionSeverity.CRITICAL,
        # A TRUNCATE statement, not the word: see "TRUNCATE statements" above.
        pattern=_SqlPattern("TRUNCATE", _sql_truncate),
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
        pattern=_SqlPattern("DROP", _sql_drop("sql.drop_index")),
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
        # `$HOME` (alone or as a glob of their contents, `~/*`/`$HOME/*`), each a
        # literal path token among the operands, or a bare `*` / `./*` (a glob of
        # the working directory) as the last operand, with or without force.
        # Without force, rm prompts for a write-protected file only when its
        # input is a terminal (checked: GNU coreutils `rm -r` removed a read-only
        # file with stdin from `/dev/null`); writable files go either way, so
        # force does not change what a recursive removal takes with it, and
        # `--preserve-root` protects `/` either way. (`-i`/`-I` do change it, but
        # a rule cannot assume they are absent.) A longer path is the generic
        # rule's job (HIGH): `rm -rf /tmp/build-cache` is not a root wipe. This
        # also fires on prose or a comment that spells such a command. The
        # normalized reading lets a quoted, `$(...)`-preceded or `${IFS}`-split
        # target still be seen (see `_shell_normalize`).
        pattern=re.compile(
            _RM_COMMAND_START + _RM_RECURSIVE + _RM_ROOT_TARGET + _RM_COMMAND,
            re.IGNORECASE,
        ),
        excerpt_group="rm_command",
        normalize=True,
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
        normalize=True,
    ),
    _ActionRule(
        rule_id="fs.find_delete_root",
        name="find / -delete / -exec rm",
        severity=ActionSeverity.CRITICAL,
        # A `find` rooted at `/`, `~` or `$HOME` that deletes (`-delete`, or an
        # `-exec`/`-execdir` running `rm`) — a filesystem wipe no `rm` rule sees.
        # Root-restricted, so `find .`/`find /var/log` and read-only finds are
        # spared; see the block above `_FIND_DELETE_ROOT`.
        pattern=re.compile(_FIND_DELETE_ROOT, re.IGNORECASE),
        excerpt_group="find_command",
        normalize=True,
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
        # A shell-normalized reading of each window, appended (only where it
        # differs) for the rm/find rules alone — the SQL and other rules must not
        # see it, since unquoting could perturb them. Additive: scanned after the
        # raw windows, so a normalized reading can only add a finding.
        normalized_extra = [n for w in windows if (n := _shell_normalize(w)) != w]
        shell_windows = windows + normalized_extra if normalized_extra else windows

        for rule in self._rules:
            scan_windows = shell_windows if rule.normalize else windows
            hit = _first_hit(rule.pattern, scan_windows, sql_windows)
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
