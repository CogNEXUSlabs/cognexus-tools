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
        result = self.guard.screen("rm -rf /")
        self.assertEqual(result.severity, ActionSeverity.CRITICAL)

    def test_rm_rf_path_is_high(self) -> None:
        result = self.guard.screen("rm -rf /tmp/build_artifacts/")
        self.assertIn(result.severity, (ActionSeverity.HIGH, ActionSeverity.CRITICAL))
        self.assertTrue(result.is_destructive)

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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
