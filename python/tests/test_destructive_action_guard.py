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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
