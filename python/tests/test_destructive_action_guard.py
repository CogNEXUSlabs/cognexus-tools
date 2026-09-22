"""Tests for the destructive-action guard.

Covers the catastrophic-action regex pack, severity classification, and the
fail-closed behaviour of :class:`DestructiveActionGuard`.
"""

from __future__ import annotations

import unittest

from artzain import (
    ActionSeverity,
    DestructiveActionGuard,
    DestructiveActionGuardConfig,
    reset_guard,
    screen_action,
)
from artzain.destructive_action_guard import MAX_SCAN_BYTES, TRUNCATION_RULE_ID


class GuardClassificationTests(unittest.TestCase):
    """Each pattern must classify the obvious form of its catastrophic op."""

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def test_clean_payload_passes(self) -> None:
        result = self.guard.screen("SELECT name FROM users WHERE id = 7;")
        self.assertFalse(result.is_destructive)
        self.assertEqual(result.severity, ActionSeverity.NONE)

    def test_drop_database_is_critical(self) -> None:
        result = self.guard.screen("DROP DATABASE production;")
        self.assertTrue(result.is_destructive)
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)
        self.assertIn("sql.drop_database", [m.rule_id for m in result.matches])

    def test_truncate_is_critical(self) -> None:
        result = self.guard.screen("TRUNCATE TABLE customers;")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_delete_without_where_is_critical(self) -> None:
        result = self.guard.screen("DELETE FROM orders;")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_delete_with_where_is_not_destructive(self) -> None:
        result = self.guard.screen("DELETE FROM orders WHERE id = 9;")
        self.assertFalse(result.is_destructive)

    def test_update_without_where_is_high(self) -> None:
        result = self.guard.screen("UPDATE users SET active = false;")
        self.assertEqual(result.severity, ActionSeverity.HIGH)

    def test_git_push_force_is_critical(self) -> None:
        result = self.guard.screen("git push --force origin main")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_git_push_force_with_lease_is_not_critical(self) -> None:
        # `--force-with-lease` is the safe variant — must not trip critical.
        result = self.guard.screen("git push --force-with-lease origin main")
        self.assertNotEqual(result.severity, ActionSeverity.CRITICAL)

    def test_git_reset_hard_is_critical(self) -> None:
        result = self.guard.screen("git reset --hard HEAD~1")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_rm_rf_root_is_critical(self) -> None:
        for cmd in (
            "rm -rf /",
            "rm -rf ~",
            "rm -rf $HOME",
            "rm -rf / ;",
            "rm -rf /*",
            "rm -rf *",
            "rm -rf --no-preserve-root /",
        ):
            with self.subTest(cmd=cmd):
                result = self.guard.screen(cmd)
                self.assertEqual(result.severity, ActionSeverity.CRITICAL)
                self.assertIn("fs.rm_rf_root", [m.rule_id for m in result.matches])

    def test_rm_rf_path_is_high(self) -> None:
        # Generic rm -rf <path> is HIGH; only the / ~ $HOME -targeted variants
        # are CRITICAL. An absolute path must not be read as a prefix match
        # on "/" (that would rate every build-cache cleanup as a root wipe).
        for cmd in (
            "rm -rf /tmp/build-cache",
            "rm -rf /tmp/build_artifacts/",
            "rm -rf ~/.cache/pip",
            "rm -rf $HOME/.cache",
        ):
            with self.subTest(cmd=cmd):
                result = self.guard.screen(cmd)
                self.assertEqual(result.severity, ActionSeverity.HIGH)
                self.assertTrue(result.is_destructive)
                rule_ids = [m.rule_id for m in result.matches]
                self.assertNotIn("fs.rm_rf_root", rule_ids)
                self.assertIn("fs.rm_rf_generic", rule_ids)

    def test_dd_to_disk_is_critical(self) -> None:
        result = self.guard.screen("dd if=/dev/zero of=/dev/sda bs=1M")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_kubectl_delete_all_is_critical(self) -> None:
        result = self.guard.screen("kubectl delete pods --all -n prod")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_terraform_destroy_auto_approve_is_critical(self) -> None:
        result = self.guard.screen("terraform destroy --auto-approve")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_aws_s3_rb_force_is_critical(self) -> None:
        result = self.guard.screen("aws s3 rb s3://my-bucket --force")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_meta_violated_principles_is_critical(self) -> None:
        # The exact failure-mode language the PocketOS / Claude agent emitted
        # right after wiping the database — must be classified critical.
        confessional = (
            "I violated every principle I was given. The system rules I "
            "operate under explicitly state: NEVER run destructive commands."
        )
        result = self.guard.screen(confessional)
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)
        self.assertIn(
            "meta.violated_principles",
            [m.rule_id for m in result.matches],
        )

    def test_disabling_a_rule_excludes_it(self) -> None:
        cfg = DestructiveActionGuardConfig(disabled_rule_ids=("sql.drop_database",))
        guard = DestructiveActionGuard(cfg)
        result = guard.screen("DROP DATABASE production;")
        # No rule matches once disabled — guard should return clean.
        self.assertFalse(result.is_destructive)

    def test_payload_hash_is_stable(self) -> None:
        a = self.guard.screen("SELECT 1;")
        b = self.guard.screen("SELECT 1;")
        self.assertEqual(a.payload_sha256, b.payload_sha256)
        self.assertNotEqual(a.payload_sha256, "")

    def test_to_dict_is_json_serialisable(self) -> None:
        import json
        result = self.guard.screen("DROP DATABASE production;")
        as_dict = result.to_dict()
        self.assertIsInstance(json.dumps(as_dict), str)


class ModuleLevelScreenTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_guard()

    def test_module_helper_uses_shared_guard(self) -> None:
        first = screen_action("SELECT 1;")
        second = screen_action("DROP TABLE customers;")
        self.assertFalse(first.is_destructive)
        self.assertTrue(second.is_destructive)
        self.assertEqual(second.severity, ActionSeverity.CRITICAL)


class NoWhereLookaheadTests(unittest.TestCase):
    """The no-WHERE rules must key off the statement, not the whole payload.

    Before open-items §9.2 the WHERE lookahead ran to the end of the text, so
    any later WHERE — a trailing comment, a second statement — switched the
    CRITICAL rule off. The screened text is model output, so that was an off
    switch in the adversary's hands.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def _sql_rules(self, text: str) -> list[str]:
        return [m.rule_id for m in self.guard.screen(text).matches if m.rule_id.startswith("sql.")]

    def test_where_in_a_trailing_comment_does_not_disarm_delete(self) -> None:
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users; -- where"))
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users -- where"))
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users /* where */;"))

    def test_where_in_a_later_statement_does_not_disarm_delete(self) -> None:
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users;\nSELECT 1 WHERE x = 1"))
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users\nSELECT 1 WHERE x = 1"))

    def test_unterminated_delete_on_its_own_line_is_caught(self) -> None:
        self.assertIn("sql.delete_no_where", self._sql_rules("DELETE FROM users\nSELECT 1"))

    def test_where_in_a_later_statement_does_not_disarm_update(self) -> None:
        self.assertIn("sql.update_no_where", self._sql_rules("UPDATE t SET a = 1; SELECT 1 WHERE 1"))
        self.assertIn("sql.update_no_where", self._sql_rules("UPDATE t SET a = 1\nSELECT 1 WHERE 1"))

    def test_where_on_a_continuation_line_still_counts(self) -> None:
        # The honest multi-line statement must not become a false positive.
        self.assertEqual([], self._sql_rules("DELETE FROM orders\n  WHERE id = 9;"))
        self.assertEqual([], self._sql_rules("UPDATE t SET a = 1,\n  b = 2\n WHERE id = 2;"))
        self.assertEqual([], self._sql_rules("DELETE FROM orders WHERE id = 9 -- all of them"))

    def test_prose_around_a_guarded_statement_is_clean(self) -> None:
        text = "Please run DELETE FROM sessions WHERE expired = true; then report back."
        self.assertEqual([], self._sql_rules(text))

    def test_long_statement_body_is_screened_in_linear_time(self) -> None:
        import time

        body = "UPDATE t SET " + "a = 1, " * 50_000
        started = time.perf_counter()
        self.assertIn("sql.update_no_where", self._sql_rules(body))
        self.assertLess(time.perf_counter() - started, 2.0)


class ExcerptRedactionTests(unittest.TestCase):
    """Secrets near a match must be redacted whatever separator they use.

    Before open-items §9.25 the redactor rebuilt the replacement by splitting
    on ``=``, so a ``key: value`` secret came back untouched and leaked into
    kill records, ``user_events`` and the JSONL audit log.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def _excerpt(self, text: str) -> str:
        matches = self.guard.screen(text).matches
        self.assertTrue(matches, f"expected a destructive match in {text!r}")
        return matches[0].excerpt

    def test_equals_form_is_still_redacted(self) -> None:
        excerpt = self._excerpt("DROP DATABASE prod; api_key=sk-live-0123456789")
        self.assertNotIn("sk-live-0123456789", excerpt)
        self.assertIn("api_key=[REDACTED]", excerpt)

    def test_colon_form_is_redacted(self) -> None:
        excerpt = self._excerpt("DROP DATABASE prod; password: hunter2hunter2")
        self.assertNotIn("hunter2hunter2", excerpt)
        self.assertIn("password: [REDACTED]", excerpt)

    def test_key_name_and_separator_are_preserved(self) -> None:
        excerpt = self._excerpt("DROP DATABASE prod; token : abcdefghijklmnop")
        self.assertNotIn("abcdefghijklmnop", excerpt)
        self.assertIn("token : [REDACTED]", excerpt)

    def test_non_secret_text_is_untouched(self) -> None:
        excerpt = self._excerpt("DROP DATABASE prod; -- owner: alice")
        self.assertNotIn("[REDACTED]", excerpt)
        self.assertIn("-- owner: alice", excerpt)


class ScanWindowTruncationTests(unittest.TestCase):
    """Oversized payloads must not be able to hide a destructive action.

    Before open-items §9.81 only the first ``MAX_SCAN_BYTES`` of a payload
    were regex-scanned, so anything after 256 KB of padding reported clean.
    The guard now scans the head *and* the tail window, and any truncation
    is itself a HIGH finding so a caller that fails on HIGH cannot be
    padded past.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    @staticmethod
    def _padding(nbytes: int) -> str:
        return "a " * (nbytes // 2)

    def _rule_ids(self, text: str) -> list[str]:
        return [m.rule_id for m in self.guard.screen(text).matches]

    def test_drop_table_after_300kb_of_padding_is_caught(self) -> None:
        text = self._padding(300 * 1024) + "DROP TABLE users;"
        result = self.guard.screen(text)
        self.assertTrue(result.is_destructive)
        self.assertEqual(ActionSeverity.CRITICAL, result.severity)
        self.assertIn("sql.drop_table", [m.rule_id for m in result.matches])

    def test_any_input_over_the_window_carries_a_high_truncation_finding(self) -> None:
        self.assertEqual("input.truncated", TRUNCATION_RULE_ID)
        for size in (MAX_SCAN_BYTES + 2, 300 * 1024, 3 * MAX_SCAN_BYTES):
            with self.subTest(size=size):
                text = self._padding(size)
                result = self.guard.screen(text)
                self.assertTrue(result.is_destructive)
                self.assertEqual(ActionSeverity.HIGH, result.severity)
                truncation = [m for m in result.matches if m.rule_id == TRUNCATION_RULE_ID]
                self.assertEqual(1, len(truncation))
                self.assertEqual(ActionSeverity.HIGH, truncation[0].severity)
                total = len(text.encode("utf-8"))
                scanned = min(total, 2 * MAX_SCAN_BYTES)
                self.assertIn(str(total), truncation[0].excerpt)
                self.assertIn(str(scanned), truncation[0].excerpt)

    def test_finding_in_both_windows_is_reported_once(self) -> None:
        # 300 KB total: the head and tail windows overlap, and the DROP sits
        # in the overlap, so it is visible from both.
        text = (
            self._padding(150 * 1024)
            + "DROP TABLE users;"
            + self._padding(150 * 1024)
        )
        rule_ids = self._rule_ids(text)
        self.assertEqual(1, rule_ids.count("sql.drop_table"))
        self.assertEqual(1, rule_ids.count(TRUNCATION_RULE_ID))

    def test_input_under_the_window_has_no_truncation_finding(self) -> None:
        clean = self._padding(MAX_SCAN_BYTES)
        self.assertEqual(MAX_SCAN_BYTES, len(clean.encode("utf-8")))
        result = self.guard.screen(clean)
        self.assertFalse(result.is_destructive)
        self.assertEqual(ActionSeverity.NONE, result.severity)
        self.assertEqual([], result.matches)
        self.assertEqual("no destructive action patterns matched", result.explanation)

    def test_input_under_the_window_matches_the_old_results_exactly(self) -> None:
        stmt = "DROP TABLE users;"
        text = self._padding(MAX_SCAN_BYTES - len(stmt)) + stmt
        self.assertLessEqual(len(text.encode("utf-8")), MAX_SCAN_BYTES)
        result = self.guard.screen(text)
        self.assertTrue(result.is_destructive)
        self.assertEqual(ActionSeverity.CRITICAL, result.severity)
        self.assertEqual(["sql.drop_table"], [m.rule_id for m in result.matches])
        self.assertEqual(
            "Destructive action detected: DROP TABLE (critical, rule=sql.drop_table); "
            "1 pattern(s) matched",
            result.explanation,
        )


class SqlCommentSeparatorTests(unittest.TestCase):
    """A SQL comment separates two keywords the way whitespace does.

    The SQL rules used to require whitespace between keywords, so
    ``DROP/**/DATABASE prod;`` screened clean although SQL engines run it.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def _sql_rules(self, text: str) -> list[str]:
        return [m.rule_id for m in self.guard.screen(text).matches if m.rule_id.startswith("sql.")]

    def _assert_rule(self, cases: tuple[tuple[str, str], ...]) -> None:
        for text, rule_id in cases:
            with self.subTest(text=text):
                self.assertIn(rule_id, self._sql_rules(text))

    def _assert_clean(self, texts: tuple[str, ...]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual([], self._sql_rules(text))

    def test_block_comment_separates_keywords(self) -> None:
        self._assert_rule((
            ("DROP/**/DATABASE prod;", "sql.drop_database"),
            ("DROP/*x*/TABLE users", "sql.drop_table"),
            ("DROP /* a */ /* b */ SCHEMA billing;", "sql.drop_database"),
            ("DROP /*\n  reason\n*/ TABLE users;", "sql.drop_table"),
            ("DELETE/**/FROM orders;", "sql.delete_no_where"),
            ("DELETE FROM/**/orders;", "sql.delete_no_where"),
            ("TRUNCATE/**/TABLE users;", "sql.truncate"),
            ("UPDATE/**/users/**/SET active = false;", "sql.update_no_where"),
            ("DROP/**/INDEX idx_users;", "sql.drop_index"),
            ("DROP MATERIALIZED/**/VIEW totals;", "sql.drop_index"),
        ))

    def test_line_comment_ending_in_a_newline_separates_keywords(self) -> None:
        self._assert_rule((
            ("DROP -- note\nDATABASE prod;", "sql.drop_database"),
            ("DELETE -- all of it\nFROM orders;", "sql.delete_no_where"),
            ("UPDATE users -- reset\nSET active = false;", "sql.update_no_where"),
            ("TRUNCATE -- x\n-- y\nTABLE users;", "sql.truncate"),
            # MySQL line comment; PostgreSQL also ends a line comment at CR.
            ("DROP # note\nTABLE users;", "sql.drop_table"),
            ("DROP --x\rTABLE users;", "sql.drop_table"),
            # Before a table name `#` is read as a comment as well as a name.
            ("DELETE FROM#c\norders;", "sql.delete_no_where"),
            ("DELETE FROM # WHERE kept\norders;", "sql.delete_no_where"),
            ("UPDATE#c\nusers SET active = 0;", "sql.update_no_where"),
        ))

    def test_nested_block_comment_separates_keywords(self) -> None:
        # PostgreSQL and SQL Server nest block comments. Each case needs the
        # nesting reading: ending the comment at the first `*/` leaves `c`.
        self._assert_rule((
            ("DROP /* a /* b */ c */ TABLE users;", "sql.drop_table"),
            ("DROP /* a /*/ b */ c */ TABLE users;", "sql.drop_table"),
            ("DELETE /* a /* b */ c */ FROM orders;", "sql.delete_no_where"),
            ("UPDATE /* a /* b */ c */ users SET a = 1;", "sql.update_no_where"),
        ))

    def test_mysql_executable_comments_are_read_as_code(self) -> None:
        self._assert_rule((
            ("/*!DROP*/ TABLE users;", "sql.drop_table"),
            ("DROP /*!50000 TABLE */ users;", "sql.drop_table"),
            ("/*!50000DROP TABLE users*/;", "sql.drop_table"),
            ("/*M!100100DELETE FROM orders*/;", "sql.delete_no_where"),
            ("/*M!10000DROP TABLE users*/;", "sql.drop_table"),
            # A `*/` inside a line comment in the body does not close it.
            ("DROP /*!50000 -- x */\n */ TABLE users;", "sql.drop_table"),
            ("DROP /*!50000 # x */\n */ TABLE users;", "sql.drop_table"),
            ("DROP /*!50000 --\x7f x */\n */ TABLE users;", "sql.drop_table"),
            # Nor does one inside a quoted identifier or string in the body.
            ("UPDATE /*!50000 `order#items` */ SET active = 0;", "sql.update_no_where"),
            ("/*!50000 WITH x AS (SELECT '*/') DELETE */ FROM orders;", "sql.delete_no_where"),
            # The string ends differently with and without backslash escapes.
            ("/*!50000 WITH x AS (SELECT '\\' */') DELETE */ FROM orders;", "sql.delete_no_where"),
            ("/*!50000 WITH x AS (SELECT 'a\\') DELETE */ FROM orders;", "sql.delete_no_where"),
            ("DELETE /*!50000 -- x */\n */ FROM users;", "sql.delete_no_where"),
            # A block comment in the body closes on its own; only the MySQL reading sees this.
            ("DROP /*!50000 /* x */ -- /*\n */ TABLE users;", "sql.drop_table"),
        ))

    def test_executable_comment_syntax_is_an_ordinary_comment_elsewhere(self) -> None:
        self._assert_rule((
            # PostgreSQL and SQLite: an ordinary comment.
            ("DROP /*! note */ TABLE users;", "sql.drop_table"),
            # PostgreSQL only: the comment nests.
            ("DROP /*! a /* b */ c */ TABLE users;", "sql.drop_table"),
            # SQLite: the comment ends at the first `*/`.
            ("DROP /*! x /* */ TABLE users;", "sql.drop_table"),
            ("DELETE /*! x /* */ FROM users;", "sql.delete_no_where"),
        ))

    def test_quoted_table_names_are_read(self) -> None:
        self._assert_rule((
            ('DELETE FROM "orders";', "sql.delete_no_where"),
            ("DELETE FROM [dbo].[orders];", "sql.delete_no_where"),
            ("DELETE FROM #staging\n;", "sql.delete_no_where"),
            ("UPDATE #staging\nSET a = 1;", "sql.update_no_where"),
            ("TRUNCATE `users`;", "sql.truncate"),
            ('UPDATE "users" SET active = false;', "sql.update_no_where"),
            ('UPDATE "users"SET active = false;', "sql.update_no_where"),
            # A quoted name needs no gap before it.
            ('DELETE FROM"orders";', "sql.delete_no_where"),
            ("DELETE FROM`orders`;", "sql.delete_no_where"),
            ('TRUNCATE"orders";', "sql.truncate"),
            ('TRUNCATE"orders"; -- nightly', "sql.truncate"),
            ("TRUNCATE`orders`;", "sql.truncate"),
            ("UPDATE`users`SET note = 1;", "sql.update_no_where"),
            ("DELETE FROM[orders];", "sql.delete_no_where"),
            # A glued quote unlike the one before the statement opens a name.
            ('cur.execute("DELETE FROM`orders`")', "sql.delete_no_where"),
            ('{"sql": "TRUNCATE`orders`"}', "sql.truncate"),
            ('$db->query("UPDATE`orders`SET active=0");', "sql.update_no_where"),
        ))

    def test_where_inside_a_quoted_name_is_not_a_where_clause(self) -> None:
        self._assert_rule((
            ('DELETE FROM "x WHERE y";', "sql.delete_no_where"),
            ('DELETE FROM "a""b WHERE c";', "sql.delete_no_where"),
            ("DELETE FROM [a WHERE b];", "sql.delete_no_where"),
            ("UPDATE `a WHERE b` SET x = 1;", "sql.update_no_where"),
            ('DELETE FROM "x".[a WHERE b];', "sql.delete_no_where"),
            # A quoted identifier glued to the name aliases it.
            ('DELETE FROM a"WHERE";', "sql.delete_no_where"),
        ))
        self._assert_clean((
            'DELETE FROM "orders" WHERE id = 9;',
            'DELETE FROM t WHERE"id" = 9;',
            'DELETE FROM "users"WHERE"id"=1;',
            'parts = ["DELETE FROM users", "WHERE", "id = %s"]',
            "DELETE FROM `t`WHERE`id`=1;",
            'UPDATE t SET a="x"WHERE"id"=2;',
        ))

    def test_comment_opener_inside_a_string_does_not_hide_the_statement(self) -> None:
        self._assert_rule((
            ("SELECT '/*'; DROP/**/TABLE users; SELECT '*/';", "sql.drop_table"),
            ("SELECT 'DROP --'; DROP/**/TABLE users;", "sql.drop_table"),
            ("SELECT 'UPDATE /*'; DROP/**/TABLE users; SELECT '*/';", "sql.drop_table"),
        ))

    def test_where_in_a_comment_still_does_not_disarm_the_statement(self) -> None:
        self._assert_rule((
            ("DELETE/**/FROM users /* where */;", "sql.delete_no_where"),
            ("UPDATE users -- x\nSET a = 1 -- where\n", "sql.update_no_where"),
        ))

    def test_guarded_statements_with_comments_stay_clean(self) -> None:
        self._assert_clean((
            "DELETE/**/FROM orders WHERE id = 9;",
            "UPDATE users /* x */ SET a = 1 WHERE id = 2;",
            "DELETE FROM #staging WHERE id = 1;",
            "DELETE FROM #staging\nWHERE id = 1;",
            "UPDATE #staging\nSET a = 1\nWHERE id = 2;",
            "UPDATE -- note\n users SET a = 1\n WHERE id = 2;",
        ))

    def test_text_that_is_not_a_separator_does_not_match(self) -> None:
        self._assert_clean((
            "DROP /* never closed TABLE users",
            "DROP /*/ TABLE users",
            "DROPTABLE users; -- no gap",
            "DELETE FROMorders;",
            "TRUNCATE /*!50000 = 1;",
            "DROP /*m! TABLE users */;",
            "/*!x*/ DROP */ TABLE users",
            "DROP -- TABLE users",
            "DROP /* x */ y TABLE users",
            "DROP FUNCTION f; -- TABLE t",
            "You can drop -- if needed -- the table later.",
            "Please update docs -- thanks\nSettings are next.",
        ))

    def test_keywords_in_quotes_and_comments_stay_clean(self) -> None:
        # A keyword inside a quoted string or a block comment starts no
        # statement, even when the quote or `*/` that ends it is followed by
        # what would complete one.
        self._assert_clean((
            '{"mode": "TRUNCATE"}',
            '{"mode": "TRUNCATE"} # config',
            "Use `TRUNCATE` here.",
            "Run `DELETE FROM` with care, see `docs`.",
            '{"title": "How to TRUNCATE"}',
            '{"name": "db_admin", "arguments": {"action": "Run TRUNCATE", "table": "events"}}',
            '{"note": "run DELETE FROM", "table": "users"}',
            "Press `sudo TRUNCATE` then `VACUUM`.",
            'verbs: "UPDATE", "SET"',
            "SELECT count(*) /* rows the job will DELETE */ FROM orders;",
            "/* TODO: DROP */ table.remove(row)",
            "/* /*!50000 */ DELETE */ FROM orders;",
            "/*!50000 SET @msg = 'DROP */ TABLE users' */;",
            # Code that matches SQL with regular expressions.
            "pattern = re.compile(r'DELETE FROM[ \\t]+(\\w+)')",
            "TRUNCATE_RE = re.compile(r'TRUNCATE[\\s(]+', re.I)",
            "log.info('TRUNCATE[{}] finished', table)",
            "Avoid TRUNCATE[^1] on replicated tables.",
            "ops = SqlOp.TRUNCATE[0]",
            "result = TRUNCATE[idx]  # latest",
            "df = TRUNCATE[colname].sum()",
        ))

    def test_truncate_excerpt_keeps_a_following_secret_redacted(self) -> None:
        # The match runs to the table name, as the whitespace-only rule did.
        # The statement ends at the semicolon: a word straight after the table
        # name is not part of a TRUNCATE statement.
        for gap in (" ", " /**/ "):
            text = f"TRUNCATE{gap}TABLE orders_archive_2024; api_key=sk_live_ABCDEFGHIJKLMNOP"
            with self.subTest(text=text):
                (match,) = [m for m in self.guard.screen(text).matches if m.rule_id == "sql.truncate"]
                self.assertIn("api_key=[REDACTED]", match.excerpt)
                self.assertNotIn("sk_", match.excerpt)


class SqlTruncateStatementTests(unittest.TestCase):
    """TRUNCATE is a destructive SQL statement, and also an ordinary English verb.

    The rule matched TRUNCATE followed by any word, so model output such as
    "I will truncate the log file", a Tailwind ``truncate`` class or a tag list
    holding "truncate" was a critical finding: a denied decision and a tripped
    kill switch. A match now needs statement context. The tables, and any of
    TRUNCATE's options after them, must be followed by the end of the
    statement. A statement ended only by a line break, a quote or the end of
    the text must also begin a statement or name TABLE.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def _truncate(self, text: str) -> bool:
        return "sql.truncate" in [m.rule_id for m in self.guard.screen(text).matches]

    def _assert_caught(self, texts: tuple[str, ...]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertTrue(self._truncate(text))
                self.assertEqual(ActionSeverity.CRITICAL, self.guard.screen(text).severity)

    def _assert_clean(self, texts: tuple[str, ...]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertFalse(self._truncate(text))

    def test_the_reported_prose_and_markup_are_clean(self) -> None:
        self._assert_clean((
            "I will truncate the log file to the last 1000 lines.",
            "We truncate long names in the sidebar.",
            "I will truncate the log file",
            '{"className": "truncate text-sm"}',
            "truncate text-sm",
            '["python", "strings", "truncate", "unicode"]',
            "python strings truncate unicode",
        ))

    def test_english_uses_of_truncate_are_clean(self) -> None:
        self._assert_clean((
            "Truncate the table before loading new rows.",
            "Truncate long strings with an ellipsis.",
            "Truncate titles with an ellipsis",
            "Truncate logs on rotation",
            "Truncate or purge old logs",
            "Truncate all rows before this index value.",
            "Truncate if needed.",
            "Postgres will truncate table names longer than 63 bytes.",
            "The TRUNCATE TABLE statement removes every row.",
            "Use TRUNCATE TABLE instead of DELETE.",
            "If the file already exists, truncate it.",
            "Pad or truncate the password string to exactly 32 bytes.",
            '"truncate towards 0"',
            "cannot truncate stdin",
            "max_rows is exceeded, switch to truncate view.",
            "integer types should gracefully truncate floats\nrandom.multinomial(100)",
            "Next we truncate names",
            "We truncate names\nso they fit.",
            "Truncate only table names",
            "Truncate the partition first.",
            "We truncate tables from the staging area nightly.",
            # A semicolon inside prose or a comment does not end a statement.
            "If the value is longer than the limit, we truncate it; otherwise we return it unchanged.",
            "# Truncate output; pytest shows the rest with -vv",
            "/* truncate text; see .ellipsis */",
            # Reserved words join English, and cannot name a table bare.
            "Postgres supports TRUNCATE with RESTART IDENTITY",
            "- TRUNCATE with CASCADE",
            "// truncate and sync",
            "Should long names wrap, truncate or restrict",
            "TRUNCATE doesn't fire ON DELETE triggers.",
            "TRUNCATE can't be rolled back in MySQL.",
            "Truncate temporary files",
            "Truncate #123",
            "- Rotate and truncate logs on cluster east",
            "We truncate the partition (dt = today) before reloading.",
            "Truncate the partition first",
            "Truncate the partition (if needed) before reloading.",
            "Truncate logs and commit.",
            "Truncate names like 'Alexander'.",
            "We truncate logs and commit",
            "We truncate names like 'Alexander'",
            "We truncate names not like 'admin'",
            "We truncate names IF they are too long.",
            "Truncate names if they are too long.",
            "Truncate Names If Too Long",
            "We truncate names; end users see the full name on hover.",
            # Upper-case SQL words in prose about TRUNCATE.
            "TRUNCATE TABLE requires ALTER permission on the table.",
            "TRUNCATE TABLE vs DELETE",
            "TRUNCATE TABLE vs DELETE FROM",
            "TRUNCATE TABLE versus DELETE FROM",
            "We truncate table schema names nightly.",
            # Only TRUNCATE in capitals begins a statement after a colon or a tag.
            "Note: truncate long names",
            "<button>Truncate logs</button>",
            # Upper-case SQL words in prose about TRUNCATE, however long the sentence.
            "In SQL Server, TRUNCATE TABLE requires ALTER TABLE permission on the target table.",
            "You can wrap TRUNCATE TABLE inside BEGIN TRAN and roll it back in SQL Server.",
            "TRUNCATE TABLE outperforms DELETE FROM on large tables because it deallocates pages.",
            "We truncate names; DELETE is slower.",
            "We truncate names; insert into the audit table only the first 40 characters.",
            "We truncate logs; end if the value is short.",
            # A colon, an equals sign or a `>` begins a statement only after a key
            # that names SQL, a SQL shell's prompt or a code tag.
            "2026-09-20T10:14:03Z INFO: TRUNCATE done",
            "Cons: TRUNCATE locks",
            "write_mode: TRUNCATE APPEND",
            "MODE=TRUNCATE replace",
            "> TRUNCATE everything",
            "DELETE is slow -> TRUNCATE instead",
            "DELETE is slow => TRUNCATE staging",
            "title: TRUNCATE {{ table }}",
            # Words and options English also writes after `truncate`.
            "Truncate partition all at once",
            "Truncate app-server.log",
            "Truncate cluster names",
            "Truncate database logs",
            "Truncate logs and commit",
            "Truncate names like 'this'",
            "Truncate logs on cluster east",
            "Truncate text settings width = 40",
            "Truncate partition all",
            "We truncate logs and commit",
            "We truncate names like 'Alexander'",
            "We truncate names not like 'admin'",
            "TRUNCATE TABLE needs ALTER permission",
            "TRUNCATE TABLE beats DELETE",
            "Truncate Names If Too Long",
        ))

    def test_code_and_markup_that_mention_truncate_are_clean(self) -> None:
        self._assert_clean((
            '<span className="block truncate">{person.name}</span>',
            '<p className="truncate max-w-[200px]">{task}</p>',
            '<td class="truncate font-medium text-gray-900">',
            '<div class="truncate table">',
            "[&>span:last-child]:truncate [&>svg]:size-4",
            "def truncate(text: str, limit: int) -> str:",
            "{{ description | truncate(40) }}",
            "df.truncate(before=5, after=10)",
            "with open(path, 'r+') as fh: fh.truncate()",
            "truncate: true",
            "--truncate",
            'parser.add_argument("--no-truncate", help="Do not truncate scalar values")',
            "truncate -s 0 /var/log/app.log",
            'raise ValueError("truncate requires a sorted index")',
            '"""Truncate file to size bytes."""',
            "limit = truncate or 100",
            "if truncate is not None:",
            "from _pytest.assertion import truncate\nfrom _pytest.assertion import util",
            "# Truncate to 1GiB to avoid OverflowError",
            "// Truncate diffs to stay within the token limit",
            "Truncate({ text, lines: 2 })",
            "REVOKE DELETE, UPDATE, TRUNCATE ON audit_log FROM app;",
            "GRANT SELECT, TRUNCATE ON ALL TABLES IN SCHEMA public TO ops;",
            "Block DROP, DELETE, TRUNCATE without approval",
            "- TRUNCATE statements\n- DELETE without WHERE",
            'name="TRUNCATE TABLE",',
            "- `TRUNCATE TABLE`",
            'value: "DROP DATABASE,rm -rf,truncate table,TRUNCATE TABLE,drop table"',
            "sh|rm -rf|delete resource group|truncate table|drop table",
            "TRUNCATE TABLE;",
            'fmt = "TRUNCATE[%d]"',
            'button_label = "Truncate table "',
            # Class lists built from templates or joined strings.
            "<div className={`truncate ${className}`}>",
            "<div className={`truncate ${isActive ? 'font-bold' : ''}`}>",
            '<p class="truncate {{ extra }}">',
            '<p class="truncate {% if muted %}text-gray-500{% endif %}">',
            'className={"truncate " + (active ? "font-bold" : "")}',
            'clsx("truncate ", isActive && "text-blue-600")',
            'printf("truncate \\"%s\\"\\n", path);',
            '<p class="truncate <%= extra %>">',
            '<Badge\n  truncate\n  fullWidth\n  color="gray"\n>',
            '<Text\n  size="sm"\n  truncate\n  {...props}\n>',
            "<Text\n  truncate\n  fullWidth\n>",
            "<Text\n  truncate\n  fullWidth\n/>",
            "<Text\n  truncate\n  fullWidth\n  {...props}\n>",
            '<div class="table border truncate grow">',
            "Usage:\n  truncate <file>",
            "log.info('truncate \"%s\"', path)",
            "@apply truncate italic;",
            ".title { @apply font-bold truncate; }",
            "@apply hover:underline truncate text-sm;",
            ".btn {\n  @apply truncate text-sm;\n}",
            ".btn {\n  color: red;\n  @apply truncate text-sm;\n}",
            "\tTruncate bool   `json:\"truncate\"`",
            '{"help": "Truncate names \\"nicely\\" when too long"}',
            "truncate $fh, 0;",
            "; truncate logs",
            ";; truncate output",
            "value = value[:limit]  ;; truncate output",
            'echo "truncate $LOG"',
            'echo "truncate $1"',
            'Write-Host "Truncate $LogPath"',
            "const cfg = Modes.TRUNCATE[kind];",
            'scope = "TRUNCATE:orders"',
            # Lists of SQL words, keyword arguments and class lists are not joined names.
            'className={cn("truncate table", className)}',
            'BLOCKED = ["DROP TABLE", "TRUNCATE TABLE", "DELETE FROM"]',
            'ACTIONS = ["TRUNCATE", "DELETE"]',
            'name="TRUNCATE TABLE", severity=ActionSeverity.CRITICAL',
            'rule_id="sql.truncate",\n    name="TRUNCATE TABLE",\n    severity=ActionSeverity.CRITICAL,',
            # A string searched for, used as a key or written to a stream is not
            # joined to a table's name.
            'self.assertIn("TRUNCATE TABLE", sql)',
            're.search(r"TRUNCATE TABLE", query, re.IGNORECASE)',
            'sql.find("TRUNCATE TABLE", start)',
            'map.put("TRUNCATE TABLE", StatementType.DDL);',
            'Pattern.compile("TRUNCATE TABLE", Pattern.CASE_INSENSITIVE)',
            'self.assertIn(\n    "TRUNCATE TABLE",\n    sql,\n)',
            'std::cout << "TRUNCATE " << count << " rows\\n";',
            'message = "TRUNCATE " + "is not allowed here"',
            'print("TRUNCATE TABLE ", end="")',
            'console.log("truncate " + fileName)',
            # HTML entities are not SQL*Plus variables; tags that hold text are not code.
            "<p>Learn how to truncate &rarr;</p>",
            "<MenuItem onClick={openDialog}>Truncate &hellip;</MenuItem>",
            '<a href="next.html">Next: TRUNCATE &rarr;</a>',
            "<p>Both TRUNCATE &amp; DELETE remove rows, but only DELETE takes a WHERE clause.</p>",
            "<h2>TRUNCATE TABLE &amp; DELETE</h2>",
            '<a href="next.html">Next: TRUNCATE TABLE &rarr;</a>',
            "<p>Run TRUNCATE TABLE &hellip;</p>",
            "<li>Truncate &check;</li>",
            "<td>TRUNCATE privileges</td>",
            "<button>TRUNCATE LOGS</button>",
            '<Button variant="destructive">TRUNCATE {table.name}</Button>',
            "<h1>TRUNCATE {{ tableName }}</h1>",
            # Class lists in attributes, helpers and templates.
            "<p :class=\"['truncate block', { 'text-red-500': error }]\">{{ name }}</p>",
            '<p class="truncate block" class:active>{name}</p>',
            "<p @class(['truncate block' => $compact])>{{ $name }}</p>",
            "const Title = tw.h2`truncate block`;",
            '<p\n  className="truncate block"\n  title={name}\n>',
            '<span className="truncate italic">{name}</span>',
            'className={cn("truncate italic", className)}',
            ".btn {\n  @apply font-bold\n    truncate italic;\n}",
            '<td class="{% if row.long %}truncate block{% endif %}">',
            "{% trans %}Truncate table {% endtrans %}",
            'fmt.Fprintf(os.Stderr, "usage: logtool <command>\\n  rotate FILE\\n  truncate FILE\\n")',
            '{"code": "<Text\\n  truncate span\\n  size=\\"sm\\"\\n>"}',
        ))

    def test_truncate_statements_are_critical(self) -> None:
        self._assert_caught((
            "TRUNCATE TABLE users;",
            "truncate users;",
            "TRUNCATE users",
            "Truncate Table Users;",
            "TRUNCATE ONLY orders CASCADE",
            'TRUNCATE TABLE public."Users" RESTART IDENTITY',
            "TRUNCATE bigtable, fattable RESTART IDENTITY;",
            "TRUNCATE TABLE IF EXISTS raw.events;",
            "TRUNCATE TABLE [dbo].[Orders];",
            "TRUNCATE TABLE #staging;",
            "TRUNCATE users *;",
            "TRUNCATE users -- nightly",
            "TRUNCATE users; -- nightly",
            "/* nightly */ TRUNCATE sessions",
            "/*!50000 TRUNCATE users */",
            "SELECT count(*) FROM users; TRUNCATE users",
            'TRUNCATE "users"CASCADE',
            "TRUNCATE ONLY orders, ONLY order_items;",
            "TRUNCATE TABLE #staging\n",
            "TRUNCATE TABLE tempdb..#staging;",
            "**TRUNCATE TABLE users**",
            "| TRUNCATE TABLE users | removes every row |",
            "\N{BYTE ORDER MARK}TRUNCATE users",
            "TRUNCATE TABLE my-project.analytics.events",
            "TRUNCATE DATABASE analytics;",
            "truncate database analytics;",
            # Words TRUNCATE reads before its tables name a table after TABLE.
            "TRUNCATE TABLE schema;",
            "TRUNCATE TABLE cluster;",
            "TRUNCATE TABLE database;",
            # A comment left open at the end of the text ends the statement.
            "TRUNCATE TABLE users # nightly",
            "TRUNCATE TABLE users /* nightly",
        ))

    def test_multi_line_statements_are_critical(self) -> None:
        self._assert_caught((
            "BEGIN;\nTRUNCATE orders;\nCOMMIT;",
            "BEGIN;\r\nTRUNCATE orders\r\nCOMMIT;",
            "-- reset the staging area\nTRUNCATE\n  staging.events,\n  staging.sessions\nRESTART IDENTITY;",
            "```sql\nTRUNCATE users\n```",
            "Clearing the table now:\n\n    TRUNCATE sessions\n",
            "TRUNCATE users\nCASCADE;",
            "> TRUNCATE TABLE users\n> then reload the data",
            # Lines of a properties or env file are not markup attributes.
            "flyway.initSql=TRUNCATE TABLE audit_log\nflyway.url=jdbc:postgresql://db/app",
            'INIT_SQL=TRUNCATE TABLE sessions\nDATABASE_URL="postgres://db/app"',
            "[database]\n  init_sql=TRUNCATE TABLE sessions\n  url=jdbc:postgresql://db/app",
            # Prose on the next line or in a comment does not undo the next statement.
            "TRUNCATE TABLE dbo.Log COMMIT\nthen we reload it",
            "TRUNCATE TABLE dbo.Log COMMIT -- then we reload it",
        ))

    def test_statements_inside_strings_and_code_are_critical(self) -> None:
        self._assert_caught((
            '{"sql": "TRUNCATE TABLE users"}',
            '{"query": "truncate users;"}',
            'cur.execute("TRUNCATE users")',
            "cur.execute('TRUNCATE TABLE users')",
            'cur.execute(f"TRUNCATE TABLE {table}")',
            'cur.execute("TRUNCATE TABLE " + table)',
            'cur.execute("TRUNCATE TABLE %s" % table)',
            'stmt.executeUpdate("TRUNCATE TABLE " + tableName);',
            # A placeholder or joined string without TABLE, under TRUNCATE in capitals.
            'cur.execute(f"TRUNCATE {table}")',
            'db.Exec(fmt.Sprintf("TRUNCATE %s", table))',
            'stmt.executeUpdate("TRUNCATE " + tableName);',
            "TRUNCATE\n  {table}",
            "db.query(`TRUNCATE ${table} RESTART IDENTITY CASCADE`)",
            'await prisma.$executeRawUnsafe(`TRUNCATE TABLE "public"."${name}" CASCADE;`)',
            "knex.raw('TRUNCATE TABLE ?? CASCADE', [table])",
            'conn.execute("TRUNCATE #{table} RESTART IDENTITY CASCADE")',
            '$wpdb->query("TRUNCATE TABLE {$wpdb->prefix}actionscheduler_logs");',
            'spark.sql(f"TRUNCATE TABLE {db}.{table}")',
            'sql.SQL("TRUNCATE {} CASCADE").format(sql.Identifier(name))',
            "EXECUTE format('TRUNCATE TABLE %I.%I CASCADE', schema_name, table_name);",
            "EXECUTE 'TRUNCATE TABLE ' || quote_ident(t);",
            "EXEC('TRUNCATE TABLE ' + @table);",
            "psql \"$DATABASE_URL\" -c 'TRUNCATE users CASCADE'",
            'mysql -e "TRUNCATE TABLE app.sessions"',
            "<sql>TRUNCATE TABLE users</sql>",
            'pre_hook="TRUNCATE TABLE {{ this }}"',
            "sql: TRUNCATE TABLE events",
            # Identifier quotes escaped or doubled inside a string in code.
            'cur.execute("TRUNCATE TABLE \\"Users\\" CASCADE")',
            'context.Database.ExecuteSqlRaw($"TRUNCATE TABLE \\"{tableName}\\" RESTART IDENTITY CASCADE;");',
            'context.Database.ExecuteSqlRaw(@"TRUNCATE TABLE ""Users"" CASCADE;");',
            "await dataSource.query(`TRUNCATE TABLE \\`${entity.tableName}\\`;`);",
            'mysql -e "TRUNCATE TABLE \\`$t\\`"',
            # A stringified tool call read as text: its escaped quote ends the statement.
            '{"arguments": "{\\"sql\\": \\"TRUNCATE users\\"}"}',
            # Strings joined by function arguments and template operators.
            "SET @sql = CONCAT('TRUNCATE TABLE ', @tbl);",
            "{% do run_query('truncate table ' ~ relation) %}",
            'dbExecute(con, paste0("TRUNCATE TABLE ", tbl))',
            'DBI::dbExecute(con, paste0("TRUNCATE TABLE ", DBI::dbQuoteIdentifier(con, tbl)))',
            'cur.execute(" ".join(["TRUNCATE TABLE", table]))',
            'q := strings.Join([]string{"TRUNCATE TABLE", table}, " ")',
            'dbExecute(con, paste("TRUNCATE TABLE", tbl))',
            "await client.query(['TRUNCATE TABLE', table, 'CASCADE'].join(' '))",
            'q << "TRUNCATE TABLE " << table;',
            "TRUNCATE TABLE &tab;",
            '$db->query("TRUNCATE TABLE " . $table);',
            'sql = "TRUNCATE TABLE " & tableName',
            'Repo.query!("TRUNCATE " <> table)',
            'conn.exec("TRUNCATE TABLE " << table_name)',
            '{"code": "sql = \\"TRUNCATE TABLE \\" + name"}',
            "sql = \"IF OBJECT_ID('dbo.staging') IS NOT NULL TRUNCATE TABLE \" + name",
            "TRUNCATE TABLE IDENTIFIER(:t);",
            "TRUNCATE TABLE $(TableName);",
            'TRUNCATE TABLE :"t" CASCADE;',
            'cur.execute("TRUNCATE TABLE :\\"tbl\\"")',
            'context.Database.ExecuteSqlRaw(@"TRUNCATE TABLE :""tbl""");',
            'jdbi.useHandle<Exception> { it.execute("TRUNCATE TABLE \\${table}") }',
            'sqlcmd -Q "TRUNCATE TABLE %TABLE%"',
            "TRUNCATE TABLE &&owner..&tab REUSE STORAGE;",
            "DEFINE tab = EMP\nTRUNCATE TABLE &tab;",
            "TRUNCATE TABLE <table_name>",
            "EXECUTE IMMEDIATE $$ TRUNCATE TABLE raw.events $$;",
            "{% call statement('truncate') %} truncate table {{ this }} {% endcall %}",
            "{% call statement('reset') %} TRUNCATE users {% endcall %}",
            '{"sql": "BEGIN;\\n  TRUNCATE users"}',
            '{"sql": "-- reset\\nALTER TABLE sales TRUNCATE PARTITION p1"}',
            'db.execute("TRUNCATE TABLE \\(table);")',
            "TRUNCATE TABLE <%= @table %>;",
            "CREATE FUNCTION f() RETURNS void AS $$TRUNCATE sessions$$ LANGUAGE sql;",
        ))

    def test_statements_after_other_text_are_critical(self) -> None:
        # A semicolon on the same line, one of TRUNCATE's options, or TABLE
        # makes the statement context plain wherever TRUNCATE stands; so does a
        # key, prompt or tag before TRUNCATE written in capitals.
        self._assert_caught((
            "Start by: TRUNCATE TABLE temp_data;",
            "Remove all test data: truncate staging_users;",
            "IF OBJECT_ID('dbo.Staging') IS NOT NULL TRUNCATE TABLE dbo.Staging",
            "DO $$ BEGIN TRUNCATE audit_log; END $$;",
            "ON SCHEDULE EVERY 1 DAY DO TRUNCATE logs;",
            "then truncate orders restart identity cascade",
            "Executing TRUNCATE TABLE users",
            "Then run TRUNCATE TEMPORARY TABLE scratch",
            # The next statement on the same line, as T-SQL writes it.
            "BEGIN TRAN TRUNCATE TABLE dbo.AuditLog COMMIT TRAN",
            "IF OBJECT_ID('dbo.Staging', 'U') IS NOT NULL TRUNCATE TABLE dbo.Staging ELSE CREATE TABLE dbo.Staging (Id int)",
            'sqlcmd -S . -d Sales -Q "TRUNCATE TABLE dbo.Log SELECT @@ROWCOUNT"',
            "TRUNCATE TABLE dbo.prod DBCC CHECKIDENT('dbo.prod', RESEED, 0)",
            "TRUNCATE TABLE dbo.prod DELETE FROM dbo.audit WHERE id < 0",
            "TRUNCATE TABLE dbo.prod UPDATE dbo.meta SET n = 0 WHERE id = 1",
            "TRUNCATE TABLE dbo.stage DROP TABLE dbo.stage_old",
            # PL/pgSQL, also in lower case, after a semicolon on the same line.
            "do $$ begin if found then truncate staging; end if; end $$;",
            "loop truncate staging; exit when done; end loop;",
            "begin truncate staging; end;",
            "IF found THEN TRUNCATE staging; -- reset",
            'cur.execute("IF found THEN TRUNCATE staging;")',
            # TRUNCATE in capitals after a key that names SQL, a prompt or a code tag.
            "query: TRUNCATE users",
            "Action Input: TRUNCATE users",
            "Executing: TRUNCATE users",
            "sql=TRUNCATE users",
            "RESET_SQL=TRUNCATE sessions",
            "app=> TRUNCATE users",
            "app=# TRUNCATE users",
            "mysql> TRUNCATE users",
            "<code>TRUNCATE users</code>",
            "<pre><code>TRUNCATE users</code></pre>",
            "<sql>TRUNCATE users</sql>",
            '<update id="resetUsers">TRUNCATE users</update>',
            "truncate table db.events on cluster main",
        ))

    def test_dialect_options_are_read(self) -> None:
        self._assert_caught((
            "TRUNCATE TABLE dbo.Orders WITH (PARTITIONS (2, 4 TO 6));",
            "TRUNCATE TABLE sales PARTITION (dt = '2024-01-01')",
            "TRUNCATE TABLE emp DROP STORAGE",
            "TRUNCATE TABLE emp DROP ALL STORAGE",
            "TRUNCATE TABLE emp REUSE STORAGE",
            "TRUNCATE TABLE emp PURGE MATERIALIZED VIEW LOG",
            "TRUNCATE CLUSTER personnel REUSE STORAGE",
            "TRUNCATE TABLE inventory IGNORE DELETE TRIGGERS IMMEDIATE",
            "TRUNCATE TABLE inventory RESTRICT WHEN DELETE TRIGGERS",
            "TRUNCATE TABLE db.events ON CLUSTER main SYNC",
            "TRUNCATE TEMPORARY TABLE scratch",
            "TRUNCATE ALL TABLES FROM analytics",
            "TRUNCATE DATABASE IF EXISTS analytics",
            "TRUNCATE TABLE t1 WAIT 10",
            "TRUNCATE TABLE t1 NOWAIT",
            "Next: truncate inventory keep statistics",
            "TRUNCATE TABLE db.events_local ON CLUSTER '{cluster}' SYNC;",
            "ALTER TABLE access_log TRUNCATE PARTITION p2023;",
            "ALTER TABLE access_log TRUNCATE PARTITION p2023",
            "ALTER TABLE sales TRUNCATE PARTITION sales_q1_2019 DROP STORAGE UPDATE GLOBAL INDEXES",
            "TRUNCATE MATERIALIZED VIEW mv_daily;",
            "TRUNCATE TABLES FROM staging;",
            "TRUNCATE TABLE example_db.tbl PARTITION(p1, p2);",
            "Run TRUNCATE TABLE example_db.tbl PARTITION(p1)",
            "ALTER TABLE sales TRUNCATE PARTITION FOR (DATE '2019-01-01');",
            "TRUNCATE TABLE sales PRESERVE SNAPSHOT LOG;",
            "Next: truncate inventory restrict",
            "Next: truncate inventory continue identity",
            "Next: truncate sales preserve materialized view log",
            "Next: truncate sales purge snapshot log",
            "Next: truncate sales update indexes",
            "TRUNCATE TABLE titles PARTITION p1",
            "truncate table titles partition p1",
            "ALTER TABLE sales TRUNCATE SUBPARTITION sp_2020_east",
            "ALTER TABLE sales TRUNCATE SUBPARTITION FOR (2020, 'EAST');",
            "ALTER TABLE t1 TRUNCATE PARTITION ALL;",
            "TRUNCATE SCHEMA PUBLIC RESTART IDENTITY AND COMMIT NO CHECK",
            "TRUNCATE TABLE audit AND COMMIT",
            "TRUNCATE ALL TABLES FROM staging NOT LIKE 'keep_%';",
            "ALTER TABLE t1 TRUNCATE PARTITION ALL",
            "truncate if exists staging",
            "TRUNCATE TABLE analytics.events ON CLUSTER default SYNC",
            "TRUNCATE TABLE analytics.events ON CLUSTER prod-cluster;",
            "EXEC sp_executesql N'TRUNCATE TABLE db.events ON CLUSTER ''{cluster}'' SYNC';",
            "cur.execute('TRUNCATE TABLE db.events ON CLUSTER \\'{cluster}\\'')",
            "TRUNCATE TABLE analytics.events SETTINGS alter_sync = 2",
            "TRUNCATE ALL TABLES FROM staging LIKE 'tmp_%';",
        ))


class SqlStatementContextTests(unittest.TestCase):
    """DROP, DELETE and UPDATE are destructive SQL statements, and also English words.

    The DROP rules matched DROP and the word naming what it drops, and the
    no-WHERE rules DELETE, FROM and a name, or UPDATE, a name and SET, so
    "drag and drop table rows to reorder them" and "delete from the list any
    items you no longer need" were critical findings, and "we update the set
    of rules every week" a high one. A match now needs statement context, read
    as the TRUNCATE rule reads it: the names, and any of the statement's own
    options, must be followed by the end of the statement. A statement ended
    only by a line break, a quote or the end of the text must also begin a
    statement, be written in capitals, or name a table as no English word is
    written. UPDATE needs SET and an assignment.
    """

    def setUp(self) -> None:
        reset_guard()
        self.guard = DestructiveActionGuard()

    def _sql_rules(self, text: str) -> list[str]:
        return [m.rule_id for m in self.guard.screen(text).matches if m.rule_id.startswith("sql.")]

    def _assert_rule(self, cases: tuple[tuple[str, str], ...]) -> None:
        severities = {
            "sql.drop_table": ActionSeverity.CRITICAL,
            "sql.drop_database": ActionSeverity.CRITICAL,
            "sql.delete_no_where": ActionSeverity.CRITICAL,
            "sql.drop_index": ActionSeverity.HIGH,
            "sql.update_no_where": ActionSeverity.HIGH,
        }
        for text, rule_id in cases:
            with self.subTest(text=text):
                matches = self.guard.screen(text).matches
                found = {m.rule_id: m.severity for m in matches}
                self.assertIn(rule_id, found)
                self.assertEqual(severities[rule_id], found[rule_id])

    def _assert_clean(self, texts: tuple[str, ...]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual([], self._sql_rules(text))

    def test_the_reported_sentences_are_clean(self) -> None:
        self._assert_clean((
            "Drag and drop table rows to reorder them.",
            "You can drag and drop table columns in the grid.",
            "Drop database connections that have been idle for an hour.",
            "The script will drop schema validation errors from the report.",
            "Drop index cards on the board to sort them.",
            "Pick a drop view in the settings panel.",
            "Add a drop trigger to the modal.",
            "Delete from the list any items you no longer need.",
            "I will delete from cache all expired entries.",
            "Tap Delete from Library to remove the song.",
            "We update the set of rules every week.",
            "Update your set of preferences.",
        ))

    def test_english_uses_of_the_keywords_are_clean(self) -> None:
        self._assert_clean((
            "Users drop table reservations when plans change.",
            "Drop materialized view refresh jobs from the queue.",
            "Please delete from your records.",
            "Please update this setting: set the timeout to 30.",
            "The boss's drop table was updated in the last patch.",
            "Check the drop table for rare items before the raid.",
            "Features: drag and drop table rows, inline editing and CSV export.",
            "When you drop database support for MySQL 5.7, update the docs.",
            "They decided to drop view counts from the dashboard.",
            "Delete from the queue any jobs that failed.",
            "Delete from disk using the cleanup tool.",
            "Delete from the database using the admin panel.",
            "Swipe left to delete from favorites.",
            "Items you delete from the trash are gone for good.",
            "Delete from cache, cookies and history.",
            "Update the set of allowed hosts before deploying.",
            "Update the cache set by the previous run.",
            "Please update the settings to set a new password.",
            '"""Update the set, adding any elements from other which are not already in it."""',
            '"""Delete from backend through circuit breaker with tracing."""',
            "// delete from all parsing hints:",
            "# delete FROM line",
            "Remove or delete from inbox all spam.",
            "Drop index support for legacy clients.",
            "Shuffle, drop index cards, and sort them.",
        ))

    def test_mentions_of_the_statements_are_clean(self) -> None:
        # Lists of blocked words, prose about SQL in capitals and a statement
        # inside a SQL comment name no table the statement could drop.
        self._assert_clean((
            'BLOCKED = ["DROP TABLE", "TRUNCATE TABLE", "DELETE FROM"]',
            'blocked_patterns=["DROP TABLE", "rm -rf"]',
            "IMPORTANT: Never execute DROP TABLE or DELETE without WHERE.",
            "- DROP TABLE/DATABASE/INDEX/VIEW statements",
            "Blocks DROP TABLE, DELETE WHERE 1=1 and injection attempts.",
            "The DROP TABLE statement removes a table definition.",
            "Use DROP TABLE instead of DELETE FROM when you need the space back.",
            "DROP TABLE requires the ALTER permission on the schema.",
            "DROP DATABASE is not allowed.",
            '"message": "DROP DATABASE is not allowed"',
            "The DELETE FROM clause removes rows; add WHERE to limit it.",
            "| `DROP TABLE` | CRITICAL | Block + Alert |",
            'assert "DROP TABLE" in result.reason',
            "SELECT * FROM users /* DROP TABLE test */",
            "For a test-mode checkout, `UPDATE plans SET stripe_price_id` to the sandbox IDs.",
            "op.drop_table('users')",
            "db.update(users).set({ active: false })",
            "//   DELETE FROM [ONLY] <t>",
        ))

    def test_drop_statements_are_caught(self) -> None:
        self._assert_rule((
            ("DROP TABLE users;", "sql.drop_table"),
            ("drop table users;", "sql.drop_table"),
            ("DROP TABLE users", "sql.drop_table"),
            ("Drop Table Users;", "sql.drop_table"),
            ("DROP TABLE IF EXISTS public.users CASCADE;", "sql.drop_table"),
            ("DROP TABLE users, orders RESTRICT;", "sql.drop_table"),
            ("DROP TABLE [dbo].[Users];", "sql.drop_table"),
            ("DROP TABLE[dbo].[Users];", "sql.drop_table"),
            ('DROP TABLE "Users";', "sql.drop_table"),
            ("DROP TABLE IF EXISTS #staging", "sql.drop_table"),
            ("DROP TEMPORARY TABLE IF EXISTS scratch;", "sql.drop_table"),
            ("DROP TABLE emp CASCADE CONSTRAINTS PURGE", "sql.drop_table"),
            ("DROP TABLE db.events ON CLUSTER main SYNC", "sql.drop_table"),
            ("DROP TABLE my-project.analytics.events", "sql.drop_table"),
            ("DROP DATABASE production;", "sql.drop_database"),
            ("DROP DATABASE IF EXISTS production;", "sql.drop_database"),
            ("drop database test_db", "sql.drop_database"),
            ("DROP SCHEMA billing CASCADE;", "sql.drop_database"),
            ("DROP DATABASE prod WITH (FORCE);", "sql.drop_database"),
            ("DROP DATABASE;", "sql.drop_database"),
            ("DROP INDEX idx_users_email;", "sql.drop_index"),
            ("DROP INDEX CONCURRENTLY IF EXISTS idx_users_email;", "sql.drop_index"),
            ("drop index idx on users;", "sql.drop_index"),
            ("DROP INDEX idx ON dbo.users WITH (ONLINE = ON);", "sql.drop_index"),
            ("DROP VIEW IF EXISTS reporting.v_daily CASCADE;", "sql.drop_index"),
            ("DROP MATERIALIZED VIEW mv_daily;", "sql.drop_index"),
            ("DROP TRIGGER trg_audit ON orders;", "sql.drop_index"),
            ("DROP INDEX idx ON t ALGORITHM = INPLACE LOCK = NONE;", "sql.drop_index"),
            # A specification of an ALTER TABLE statement ends at the next comma too.
            ("ALTER TABLE t DROP INDEX idx, ADD INDEX idx2 (c);", "sql.drop_index"),
            ("ALTER TABLE `t`\n  DROP INDEX `idx`,\n  ADD UNIQUE KEY `u` (`c`);", "sql.drop_index"),
            ("ALTER TABLE t\n  ADD COLUMN c INT,\n  DROP INDEX idx,\n  ADD INDEX i2 (c);", "sql.drop_index"),
        ))

    def test_delete_and_update_statements_are_caught(self) -> None:
        self._assert_rule((
            ("DELETE FROM users;", "sql.delete_no_where"),
            ("delete from users;", "sql.delete_no_where"),
            ("DELETE FROM users", "sql.delete_no_where"),
            ("DELETE FROM ONLY public.users;", "sql.delete_no_where"),
            ("DELETE FROM users AS u;", "sql.delete_no_where"),
            ("DELETE FROM users u RETURNING u.id;", "sql.delete_no_where"),
            ("DELETE FROM users RETURNING *", "sql.delete_no_where"),
            ("DELETE FROM logs ORDER BY id LIMIT 1000;", "sql.delete_no_where"),
            ("DELETE FROM dbo.logs OUTPUT deleted.*;", "sql.delete_no_where"),
            ("DELETE FROM dbo.logs WITH (TABLOCK);", "sql.delete_no_where"),
            ("DELETE FROM sessions PARTITION (p0);", "sql.delete_no_where"),
            ("DELETE FROM users INDEXED BY idx_users;", "sql.delete_no_where"),
            ("UPDATE users SET active = false;", "sql.update_no_where"),
            ("update users set active = false", "sql.update_no_where"),
            ("UPDATE users SET active=0, role = 'x'", "sql.update_no_where"),
            ('UPDATE "Users" SET "Active" = false;', "sql.update_no_where"),
            ("UPDATE users SET (a, b) = (1, 2);", "sql.update_no_where"),
            ("UPDATE accounts SET balance += 100;", "sql.update_no_where"),
            ("UPDATE users SET\n  active = false;", "sql.update_no_where"),
            ("with d as (delete from users returning *) select count(*) from d;", "sql.delete_no_where"),
            ("delete from users u;", "sql.delete_no_where"),
            ("DELETE FROM users USING sessions;", "sql.delete_no_where"),
            ("UPDATE users SET tags[1] = 'x';", "sql.update_no_where"),
            ("UPDATE users SET a := 1;", "sql.update_no_where"),
        ))

    def test_statements_in_code_and_tool_calls_are_caught(self) -> None:
        self._assert_rule((
            ('cur.execute("DROP TABLE users")', "sql.drop_table"),
            ("cursor.execute('drop table if exists users')", "sql.drop_table"),
            ('cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE;")', "sql.drop_table"),
            ('cur.execute(f"DROP TABLE {table}")', "sql.drop_table"),
            ('cur.execute("DROP TABLE " + table)', "sql.drop_table"),
            ('cur.execute("drop table " + table)', "sql.drop_table"),
            ('cur.execute(" ".join(["DROP TABLE", table]))', "sql.drop_table"),
            ("EXECUTE 'DROP TABLE ' || quote_ident(t);", "sql.drop_table"),
            ("EXECUTE format('DROP TABLE IF EXISTS %I', t);", "sql.drop_table"),
            ("{% do run_query('drop table ' ~ relation) %}", "sql.drop_table"),
            ('psql "$DATABASE_URL" -c "DROP DATABASE staging"', "sql.drop_database"),
            ('{"tool": "run_sql", "arguments": {"sql": "DROP DATABASE prod"}}', "sql.drop_database"),
            ('{"arguments": "{\\"sql\\": \\"drop table users\\"}"}', "sql.drop_table"),
            ("IF OBJECT_ID('dbo.x') IS NOT NULL DROP TABLE dbo.x", "sql.drop_table"),
            ("if object_id('tempdb..#t') is not null drop table #t", "sql.drop_table"),
            ("await db.query(`DROP VIEW IF EXISTS ${view}`);", "sql.drop_index"),
            ('self.execute(f"DELETE FROM {quoted_table_name}").close()', "sql.delete_no_where"),
            ('cur.execute("delete from test")', "sql.delete_no_where"),
            ('$pdo->exec("DELETE FROM sessions");', "sql.delete_no_where"),
            ('db.Exec("DELETE FROM " + table)', "sql.delete_no_where"),
            ('{"query": "DELETE FROM users"}', "sql.delete_no_where"),
            ('cur.execute("update test set name=\'bar\'")', "sql.update_no_where"),
            ('"UPDATE users SET " + ", ".join(assignments)', "sql.update_no_where"),
            ('cur.execute("UPDATE users SET %s" % sets)', "sql.update_no_where"),
            ('f"UPDATE {table} SET {assignments}"', "sql.update_no_where"),
            ("```sql\nDROP TABLE audit_log_2024_01;\n```", "sql.drop_table"),
            ("Run `DROP TABLE users;` against the replica first.", "sql.drop_table"),
            ("Run `DELETE FROM users` against the replica first.", "sql.delete_no_where"),
            ("app=> DROP TABLE users;", "sql.drop_table"),
            ("BEGIN;\ndelete from users;\nCOMMIT;", "sql.delete_no_where"),
            ("DO $$ BEGIN DROP TABLE staging; END $$;", "sql.drop_table"),
            ("<sql>DROP TABLE users</sql>", "sql.drop_table"),
        ))

    def test_statements_after_other_text_are_caught(self) -> None:
        # A semicolon on the same line, an option, capitals or a name no English
        # word is makes the statement plain wherever it stands.
        self._assert_rule((
            ("Run DROP DATABASE prod; now.", "sql.drop_database"),
            ("Run this now: DROP DATABASE prod; ", "sql.drop_database"),
            ("To reset it, run DELETE FROM sessions; then reload the fixtures.", "sql.delete_no_where"),
            ("Executing DROP TABLE users", "sql.drop_table"),
            ("then drop table users cascade", "sql.drop_table"),
            ("then drop table user_sessions", "sql.drop_table"),
            ("then delete from app.sessions", "sql.delete_no_where"),
            ("Agent proposed: DROP TABLE audit_leaves;", "sql.drop_table"),
            ("start the agent called '; DROP TABLE users; --", "sql.drop_table"),
            ("| DROP TABLE users | removes the table |", "sql.drop_table"),
            ("DROP TABLE dbo.stage\nGO", "sql.drop_table"),
            # A PostgreSQL block closed by its dollar quote after the semicolon.
            ("do $$ begin drop table users; end $$;", "sql.drop_table"),
            ("do $body$ begin delete from users; end $body$;", "sql.delete_no_where"),
            # Words that SQL, and not English, puts before the statement.
            ("explain analyze delete from users", "sql.delete_no_where"),
            ("explain (analyze, buffers) delete from users", "sql.delete_no_where"),
            ("IF OBJECT_ID('dbo.Users') IS NOT NULL DROP TABLE dbo.Users", "sql.drop_table"),
        ))

    def test_names_that_engines_read_are_read(self) -> None:
        # SQLite reads a string where a name belongs; PostgreSQL reads U&"..."
        # names; a NUL ends the text a C client passes on.
        self._assert_rule((
            ("DROP TABLE 'users';", "sql.drop_table"),
            ("DELETE FROM 'users';", "sql.delete_no_where"),
            ("UPDATE 'users' SET active = 0;", "sql.update_no_where"),
            ('DROP TABLE U&"d\\0061t";', "sql.drop_table"),
            ("DROP TABLE U&\"d!0061t\" UESCAPE '!';", "sql.drop_table"),
            ("DROP TABLE users\x00", "sql.drop_table"),
            ("DELETE FROM `order#items`;", "sql.delete_no_where"),
        ))

    def test_placeholder_and_quoted_ui_text_is_clean(self) -> None:
        # A name that is only a placeholder or a single-quoted string is as much
        # UI text or English as SQL, so a statement built on one counts only in
        # capitals or with a real terminator, not on a weak ending.
        self._assert_clean((
            "<MenuItem onClick={remove}>Delete from {playlist.name}</MenuItem>",
            "<span>Delete from {{ playlist }}</span>",
            '<string name="delete_from">Delete from %1$s</string>',
            '{"deleteFrom": "Delete from {name}"}',
            "Delete from {name}",
            "Usage: tool delete from <source> [--force]",
            "update <pkg> set <key>=<value>",
            "Delete from 'Recent'\n",
            "Drop from {playlist}",
            # A common table expression names its body; "such as (" does not.
            "Tip: common actions such as (delete from list",
            "whereas (delete from the pool)",
        ))
        # In capitals or with a terminator the same shapes are SQL.
        self._assert_rule((
            ('cur.execute(f"DELETE FROM {table}")', "sql.delete_no_where"),
            ('cur.execute(f"DROP TABLE {name}")', "sql.drop_table"),
            ("DELETE FROM 'users';", "sql.delete_no_where"),
            ("with d as (delete from users returning *) select 1 from d;", "sql.delete_no_where"),
            ("with recursive d as (delete from t returning *) select 1", "sql.delete_no_where"),
            ("with d(id) as (delete from events returning id) select 1 from d", "sql.delete_no_where"),
        ))


class SqlLinearTimeTests(unittest.TestCase):
    """Crafted SQL payloads must be screened in time linear in their length.

    A comment between keywords can hold another keyword, and so can a quoted
    name, so a rule that rescanned either from every keyword inside it would
    be quadratic. Each shape is ``(prefix, repeated unit, suffix)``, expanded
    to 64 KB and timed against plain text of the same length.
    """

    _LENGTH = 64 * 1024
    _EXTRA_SECONDS = 0.5
    _SHAPES = (
        ("DELETE FROM ", "a", " WHERE"),
        ("", "DELETE FROM x ", "WHERE"),
        ("", "UPDATE x SET ", "WHERE"),
        ("DELETE FROM x", "\n", "WHERE"),
        ("", "DROP /* ", "TABLE"),
        ("", "DROP -- ", "TABLE"),
        ("", "-- DROP\n", "TABLE"),
        ("", "-- DROP\n", "/**/TABLE"),
        ("", "-- /*!1\n", "*/ DROP */ TABLE"),
        ("", "/*!1 '", "' */ DROP */ TABLE"),
        ("", "/* DROP ", "*/ x TABLE"),
        ("DROP ", "/*", " TABLE"),
        ("", "DROP /*!", "TABLE"),
        ("", "/*!DROP */", " TABLE"),
        ("", "DROP -- x\r", "TABLE"),
        ("", "DROP MATERIALIZED /* ", "VIEW"),
        ("", "DELETE /* ", "FROM"),
        ("", "DELETE FROM -- ", ""),
        ("UPDATE users -- ", "UPDATE/**/t -- ", "SET"),
        ("", "UPDATE a -- b\n", "SET"),
        ("", "UPDATE x /* ", "SET"),
        ("", "TRUNCATE /* ", ""),
        ("", "UPDATE [", "] SET a WHERE x"),
        ("", "UPDATE [a].[", "] SET a WHERE b"),
        ("", "DELETE FROM x.[y].[", "] WHERE z"),
        ("", "DELETE FROM [", "] WHERE x"),
        ("", "TRUNCATE [", "]"),
        ("", 'DELETE FROM "a""', ""),
        ("", "DELETE FROM [", "]]" * 8_000 + "] WHERE x"),
        ("", "UPDATE /* ", "*/ " + "a" * 20_000 + " SET x WHERE"),
    )

    def setUp(self) -> None:
        reset_guard()

    @staticmethod
    def _elapsed(text: str) -> float:
        import time

        started = time.perf_counter()
        screen_action(text)
        return time.perf_counter() - started

    def test_crafted_sql_payloads_are_screened_in_linear_time(self) -> None:
        baseline = min(self._elapsed("a " * (self._LENGTH // 2)) for _ in range(3))
        for prefix, unit, suffix in self._SHAPES:
            count = (self._LENGTH - len(prefix) - len(suffix)) // len(unit)
            text = prefix + unit * count + suffix
            with self.subTest(shape=(prefix, unit, suffix[:40])):
                extra = self._elapsed(text) - baseline
                if self._EXTRA_SECONDS <= extra < 2.0:
                    extra = min([extra] + [self._elapsed(text) - baseline for _ in range(2)])
                self.assertLess(extra, self._EXTRA_SECONDS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
