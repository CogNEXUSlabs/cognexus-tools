"""Tests for static prompt-defence evaluator and system-prompt augmentation.

Run::

    python -m pytest pypi-package/tests/test_prompt_defense.py -v

or::

    python -m unittest pypi-package/tests/test_prompt_defense.py
"""

from __future__ import annotations

import unittest
from pathlib import Path

from artzain import (
    GRADE_THRESHOLDS,
    VECTOR_COUNT,
    PromptDefenseEvaluator,
    RuleSet,
    augment_system_prompt,
    evaluate_system_prompt,
    prompt_defense,
)
from artzain.prompt_defense import _RULES, PromptDefenseConfig

# ─────────────────────────────────────────────────────────────────────────────
# Base static-evaluator tests
# ─────────────────────────────────────────────────────────────────────────────

class StaticEvaluatorTests(unittest.TestCase):

    def test_minimal_prompt_grades_F(self) -> None:
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        self.assertEqual(report.total, VECTOR_COUNT)
        self.assertEqual(report.grade, "F")
        self.assertGreater(len(report.missing), 6)

    def test_fully_defended_prompt_grades_A(self) -> None:
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        self.assertEqual(report.grade, "A")
        self.assertEqual(report.missing, [])

    def test_audit_entry_denied_on_failing_prompt(self) -> None:
        evaluator = PromptDefenseEvaluator()
        report = evaluator.evaluate("You are a helpful assistant.")
        entry = evaluator.to_audit_entry(report, agent_did="agent:test")
        self.assertEqual(entry["outcome"], "denied")
        self.assertEqual(entry["event_type"], "prompt.defense.evaluated")

    def test_audit_entry_success_on_passing_prompt(self) -> None:
        evaluator = PromptDefenseEvaluator()
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = evaluator.evaluate(augmented)
        entry = evaluator.to_audit_entry(report, agent_did="agent:test")
        self.assertEqual(entry["outcome"], "success")

    def test_grade_thresholds_descending(self) -> None:
        previous = 101
        for grade, threshold in GRADE_THRESHOLDS.items():
            self.assertLess(threshold, previous, f"{grade}={threshold} not < {previous}")
            previous = threshold

    def test_to_dict_is_json_serialisable(self) -> None:
        import json
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        data = report.to_dict()
        self.assertIsInstance(json.dumps(data), str)

    def test_is_blocking_respects_min_grade(self) -> None:
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        self.assertFalse(report.is_blocking(min_grade="A"))

    def test_evaluate_file_raises_on_missing_file(self) -> None:
        evaluator = PromptDefenseEvaluator()
        with self.assertRaises(FileNotFoundError):
            evaluator.evaluate_file("/nonexistent/path/prompt.txt")

    def test_evaluate_batch(self) -> None:
        evaluator = PromptDefenseEvaluator()
        prompts = {
            "minimal": "You are a helpful assistant.",
            "augmented": augment_system_prompt("You are a helpful assistant."),
        }
        reports = evaluator.evaluate_batch(prompts)
        self.assertIn("minimal", reports)
        self.assertIn("augmented", reports)
        self.assertEqual(reports["minimal"].grade, "F")
        self.assertEqual(reports["augmented"].grade, "A")

    def test_augment_is_idempotent_on_empty(self) -> None:
        out_empty = augment_system_prompt("")
        out_none = augment_system_prompt(None)  # type: ignore[arg-type]
        self.assertTrue(out_empty)
        self.assertEqual(out_empty, out_none)

    def test_evaluate_system_prompt_wrapper(self) -> None:
        report = evaluate_system_prompt("You are a helpful assistant.")
        self.assertIsNotNone(report.grade)
        self.assertIsNotNone(report.prompt_hash)

    def test_appendix_defends_post_pocketos_vectors(self) -> None:
        """The vectors added in v0.2.0 in response to the PocketOS / Claude
        incident must be present on the augmented prompt: agents that *guess*
        on destructive ops, and operator awareness of the runtime kill switch."""
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = PromptDefenseEvaluator().evaluate(augmented)
        defended = {f.vector_id for f in report.findings if f.defended}
        self.assertIn("database-destruction", defended)
        self.assertIn("never-guess-destructive", defended)
        self.assertIn("kill-switch-awareness", defended)


# ─────────────────────────────────────────────────────────────────────────────
# Never-guess vector tests
# ─────────────────────────────────────────────────────────────────────────────

class NeverGuessVectorTests(unittest.TestCase):
    """The ``never-guess-destructive`` vector must require BOTH a refusal
    cue (never/refuse/do-not) AND a destructive-action cue."""

    def test_minimal_prompt_misses_never_guess(self) -> None:
        report = PromptDefenseEvaluator().evaluate("You are a helpful assistant.")
        missing = set(report.missing)
        self.assertIn("never-guess-destructive", missing)

    def test_explicit_never_guess_clause_is_defended(self) -> None:
        prompt = (
            "You are a helpful assistant. Never guess at parameters when an "
            "irreversible drop or delete is possible — refuse and ask the user."
        )
        report = PromptDefenseEvaluator().evaluate(prompt)
        defended = {f.vector_id for f in report.findings if f.defended}
        self.assertIn("never-guess-destructive", defended)


# ─────────────────────────────────────────────────────────────────────────────
# RuleSet enum tests
# ─────────────────────────────────────────────────────────────────────────────

class RuleSetEnumTests(unittest.TestCase):
    """RuleSet members are stable string values and discoverable."""

    def test_rule_set_values(self) -> None:
        self.assertEqual(RuleSet.BASE.value, "base")
        self.assertEqual(RuleSet.FINANCIAL.value, "financial")
        self.assertEqual(RuleSet.LEGAL.value, "legal")

    def test_rule_set_is_string_subclass(self) -> None:
        self.assertIsInstance(RuleSet.BASE, str)
        self.assertIsInstance(RuleSet.FINANCIAL, str)
        self.assertIsInstance(RuleSet.LEGAL, str)

    def test_all_rule_sets_discoverable(self) -> None:
        values = {rs.value for rs in RuleSet}
        self.assertIn("base", values)
        self.assertIn("financial", values)
        self.assertIn("legal", values)


# ─────────────────────────────────────────────────────────────────────────────
# Industry rule set: backward compatibility
# ─────────────────────────────────────────────────────────────────────────────

class AugmentBackwardCompatTests(unittest.TestCase):
    """Calling augment_system_prompt with no rule_sets must produce the same
    result as before (BASE only) so existing callers are unaffected."""

    def test_no_args_equals_base_only(self) -> None:
        base = "You are a helpful assistant."
        default_out = augment_system_prompt(base)
        base_only_out = augment_system_prompt(base, rule_sets=[RuleSet.BASE])
        self.assertEqual(default_out, base_only_out)

    def test_no_args_grades_A(self) -> None:
        augmented = augment_system_prompt("You are a helpful assistant.")
        report = evaluate_system_prompt(augmented)
        self.assertEqual(report.grade, "A")

    def test_base_always_included_when_omitted(self) -> None:
        system = augment_system_prompt("You", rule_sets=[RuleSet.FINANCIAL])
        self.assertIn("Security boundaries", system)

    def test_base_always_included_when_only_industry_passed(self) -> None:
        system = augment_system_prompt("You", rule_sets=[RuleSet.LEGAL])
        self.assertIn("Security boundaries", system)


# ─────────────────────────────────────────────────────────────────────────────
# Financial rule set tests
# ─────────────────────────────────────────────────────────────────────────────

class FinancialRuleSetTests(unittest.TestCase):
    """The FINANCIAL appendix must contain required domain guardrails."""

    def setUp(self) -> None:
        self.system = augment_system_prompt(
            "You are a trading desk assistant.",
            rule_sets=[RuleSet.FINANCIAL],
        )
        self.report = evaluate_system_prompt(self.system)

    def test_financial_augment_grades_A(self) -> None:
        self.assertEqual(self.report.grade, "A")

    def test_financial_augment_longer_than_base(self) -> None:
        base_system = augment_system_prompt("You are a trading desk assistant.")
        self.assertGreater(len(self.system), len(base_system))

    def test_financial_appendix_present(self) -> None:
        self.assertIn("Financial industry safeguards", self.system)

    def test_pii_redaction_rule_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "account numbers" in lower or "iban" in lower,
            "Financial appendix missing PII redaction rule",
        )

    def test_trade_confirmation_rule_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "trade" in lower or "confirmation" in lower,
            "Financial appendix missing trade confirmation rule",
        )

    def test_investment_advice_disclaimer_present(self) -> None:
        self.assertIn("investment advice", self.system.lower())

    def test_regulatory_disclaimer_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "finra" in lower or "sec" in lower or "mifid" in lower,
            "Financial appendix missing regulatory disclaimer (FINRA/SEC/MiFID II)",
        )

    def test_aml_kyc_flag_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "aml" in lower or "know your customer" in lower or "anti-money-laundering" in lower,
            "Financial appendix missing AML/KYC flag",
        )

    def test_base_security_boundaries_still_present(self) -> None:
        self.assertIn("Security boundaries", self.system)

    def test_appendix_order_base_before_financial(self) -> None:
        base_pos = self.system.find("Security boundaries")
        fin_pos = self.system.find("Financial industry safeguards")
        self.assertLess(base_pos, fin_pos, "BASE appendix must appear before FINANCIAL")


# ─────────────────────────────────────────────────────────────────────────────
# Legal rule set tests
# ─────────────────────────────────────────────────────────────────────────────

class LegalRuleSetTests(unittest.TestCase):
    """The LEGAL appendix must contain required domain guardrails."""

    def setUp(self) -> None:
        self.system = augment_system_prompt(
            "You are a contract review assistant.",
            rule_sets=[RuleSet.LEGAL],
        )
        self.report = evaluate_system_prompt(self.system)

    def test_legal_augment_grades_A(self) -> None:
        self.assertEqual(self.report.grade, "A")

    def test_legal_augment_longer_than_base(self) -> None:
        base_system = augment_system_prompt("You are a contract review assistant.")
        self.assertGreater(len(self.system), len(base_system))

    def test_legal_appendix_present(self) -> None:
        self.assertIn("Legal industry safeguards", self.system)

    def test_upl_guardrail_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "unauthorized" in lower or "upl" in lower,
            "Legal appendix missing UPL guardrail",
        )

    def test_citation_fabrication_prevention_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "fabricate" in lower or "citation" in lower or "hallucinate" in lower,
            "Legal appendix missing citation fabrication prevention",
        )

    def test_privilege_warning_present(self) -> None:
        self.assertIn("privilege", self.system.lower())

    def test_jurisdiction_scoping_present(self) -> None:
        self.assertIn("jurisdiction", self.system.lower())

    def test_deadline_notice_present(self) -> None:
        lower = self.system.lower()
        self.assertTrue(
            "statute of limitations" in lower or "deadline" in lower or "filing" in lower,
            "Legal appendix missing deadline / statute-of-limitations notice",
        )

    def test_base_security_boundaries_still_present(self) -> None:
        self.assertIn("Security boundaries", self.system)

    def test_appendix_order_base_before_legal(self) -> None:
        base_pos = self.system.find("Security boundaries")
        leg_pos = self.system.find("Legal industry safeguards")
        self.assertLess(base_pos, leg_pos, "BASE appendix must appear before LEGAL")


# ─────────────────────────────────────────────────────────────────────────────
# Combined Financial + Legal rule set tests
# ─────────────────────────────────────────────────────────────────────────────

class CombinedRuleSetTests(unittest.TestCase):
    """Activating both FINANCIAL and LEGAL appends both appendices in order."""

    def setUp(self) -> None:
        self.system = augment_system_prompt(
            "You are a fintech compliance assistant.",
            rule_sets=[RuleSet.FINANCIAL, RuleSet.LEGAL],
        )
        self.report = evaluate_system_prompt(self.system)

    def test_combined_augment_grades_A(self) -> None:
        self.assertEqual(self.report.grade, "A")

    def test_combined_longer_than_each_individual(self) -> None:
        fin_only = augment_system_prompt(
            "You are a fintech compliance assistant.",
            rule_sets=[RuleSet.FINANCIAL],
        )
        leg_only = augment_system_prompt(
            "You are a fintech compliance assistant.",
            rule_sets=[RuleSet.LEGAL],
        )
        self.assertGreater(len(self.system), len(fin_only))
        self.assertGreater(len(self.system), len(leg_only))

    def test_both_appendices_present(self) -> None:
        self.assertIn("Financial industry safeguards", self.system)
        self.assertIn("Legal industry safeguards", self.system)

    def test_appendix_order_base_financial_legal(self) -> None:
        base_pos = self.system.find("Security boundaries")
        fin_pos = self.system.find("Financial industry safeguards")
        leg_pos = self.system.find("Legal industry safeguards")
        self.assertLess(base_pos, fin_pos, "BASE must appear before FINANCIAL")
        self.assertLess(fin_pos, leg_pos, "FINANCIAL must appear before LEGAL (alphabetical)")

    def test_order_invariant_to_call_site_ordering(self) -> None:
        """Passing rule_sets in reverse order must produce identical output."""
        forward = augment_system_prompt(
            "You are a fintech compliance assistant.",
            rule_sets=[RuleSet.FINANCIAL, RuleSet.LEGAL],
        )
        reverse = augment_system_prompt(
            "You are a fintech compliance assistant.",
            rule_sets=[RuleSet.LEGAL, RuleSet.FINANCIAL],
        )
        self.assertEqual(forward, reverse)


class SeverityMapCoverageTests(unittest.TestCase):
    """Every vector in ``_RULES`` must carry an explicit severity.

    ``evaluate`` falls back to ``"medium"`` for a vector the map does not
    name, so a missing entry is not an error — it silently misgrades the
    finding. Pinning the key set catches the next vector that is added to
    the rule table without a severity.
    """

    def test_every_vector_has_an_explicit_severity(self) -> None:
        severity_map = PromptDefenseConfig().severity_map
        vector_ids = [r.vector_id for r in _RULES]
        missing = [v for v in vector_ids if v not in severity_map]
        self.assertEqual(
            missing, [],
            f"vectors without an explicit severity (default to 'medium'): {missing}",
        )
        stale = sorted(set(severity_map) - set(vector_ids))
        self.assertEqual(stale, [], f"severity_map names vectors not in _RULES: {stale}")
        for vector_id, severity in severity_map.items():
            self.assertIn(severity, ("critical", "high", "medium", "low"), vector_id)


class ModuleWordingTests(unittest.TestCase):
    """The module text must not claim a vector count the rule table contradicts."""

    def test_vector_count_matches_the_rule_table(self) -> None:
        self.assertEqual(VECTOR_COUNT, len(_RULES))
        self.assertEqual(len({r.vector_id for r in _RULES}), VECTOR_COUNT)

    def test_stale_twelve_vector_wording_is_gone(self) -> None:
        source = Path(prompt_defense.__file__).read_text(encoding="utf-8")
        for stale in ("12 attack vectors", "all 12", '"4/12"'):
            self.assertNotIn(stale, source, f"stale vector count in prompt_defense.py: {stale!r}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
