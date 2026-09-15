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
        for gap in (" ", " /**/ "):
            text = f"TRUNCATE{gap}TABLE orders_archive_2024 api_key=sk_live_ABCDEFGHIJKLMNOP"
            with self.subTest(text=text):
                (match,) = [m for m in self.guard.screen(text).matches if m.rule_id == "sql.truncate"]
                self.assertIn("api_key=[REDACTED]", match.excerpt)
                self.assertNotIn("sk_", match.excerpt)


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
