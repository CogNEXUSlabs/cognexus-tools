"""Tests for the SDK copy of the PII detector (derived from security/pii_detector.py)."""

from __future__ import annotations

import unittest

from artzain.pii_detector import redact_text, scan_text


class SsnSeparatorTests(unittest.TestCase):
    """Separated SSN forms (space, dot) and the non-alphanumeric boundary.

    Ported from the Agent Governance Toolkit credential redactor fix
    (microsoft/agent-governance-toolkit#3531): the dash-only pattern missed
    the space and dot separated forms, and ``\\b`` let an SSN glued to an
    underscore (``employee_536-22-1948``) through. A separator stays
    mandatory — bare nine digits are tracking numbers, routing numbers and
    ZIP+4 far more often than SSNs.
    """

    def test_space_separated_detected(self):
        self.assertEqual(scan_text("SSN 536 22 1948 on file").get("ssn"), 1)

    def test_dot_separated_detected(self):
        self.assertEqual(scan_text("SSN 536.22.1948 on file").get("ssn"), 1)

    def test_glued_to_underscore_detected(self):
        self.assertEqual(scan_text("key employee_536-22-1948").get("ssn"), 1)

    def test_never_issued_ranges_still_rejected_in_new_forms(self):
        self.assertEqual(scan_text("000 12 3456 and 666.12.3456 and 900 12 3456"), {})
        self.assertEqual(scan_text("536 00 1948 and 536.22.0000"), {})

    def test_bare_nine_digits_rejected(self):
        for sample in (
            "tracking 536221948",       # contiguous nine digits
            "ABA routing 021000021",    # routing number
            "ZIP 98101-1234",           # ZIP+4
            "ref 1536-22-1948",         # digit glued before
            "ref 536-22-19485",         # digit glued after
            "ref A536-22-1948",         # letter glued before
        ):
            with self.subTest(sample=sample):
                self.assertNotIn("ssn", scan_text(sample))

    def test_redact_text_covers_new_forms(self):
        out, counts = redact_text("a 536 22 1948 b 536.22.1948 c employee_536-22-1948")
        self.assertEqual(counts.get("ssn"), 3)
        self.assertNotIn("536", out)
        self.assertEqual(out.count("[REDACTED-SSN]"), 3)
        # The underscore prefix survives; only the identifier is replaced.
        self.assertIn("employee_[REDACTED-SSN]", out)


class PassportIdentifierTests(unittest.TestCase):
    """A passport number after its label carries a digit; a word is not one."""

    def test_identifier_with_a_digit_counts(self):
        for sample in (
            "passport no: X1234567", "passport: 123456789", "Passport number AB1234567",
            "My passport number is X1234567", "Passport number - 123456789",
        ):
            with self.subTest(sample=sample):
                self.assertEqual(scan_text(sample).get("passport"), 1)

    def test_a_word_after_the_label_is_not_a_passport_number(self):
        for sample in ("passport: pending", "passport country: France", "passportNumber"):
            with self.subTest(sample=sample):
                self.assertNotIn("passport", scan_text(sample))


class OtherScriptDigitTests(unittest.TestCase):
    """Digits of another script are checked by their value, as ASCII digits are."""

    def test_checks_read_the_digit_values(self):
        from artzain.pii_detector import luhn_ok

        def fullwidth(text):
            return "".join(chr(0xFF10 + int(char)) if char.isdigit() else char for char in text)

        self.assertFalse(luhn_ok(fullwidth("1234567890123456")))
        self.assertTrue(luhn_ok(fullwidth("4111111111111111")))
        self.assertNotIn("ssn", scan_text("ref " + fullwidth("900-00-0000")))


class ToolCallMemberTests(unittest.TestCase):
    """The SDK copy of the tool-call member reading counts labelled arguments."""

    def test_argument_names_label_their_values(self):
        import json

        from artzain.tool_call_contract import member_text, scan_tool_call_pii

        payload = json.dumps({"tool": "create_user", "arguments": {
            "password": "hunter2", "date_of_birth": "1990-01-01", "passport_number": "X1234567",
        }})
        self.assertEqual(scan_text(payload), {})
        self.assertEqual(
            member_text(payload),
            "tool: create_user\n;\npassword: hunter2\n;\ndate of birth: 1990-01-01"
            "\n;\npassport number: X1234567",
        )
        self.assertEqual(scan_tool_call_pii(payload), {"passport": 1, "dob": 1, "secrets": 1})


if __name__ == "__main__":
    unittest.main()
