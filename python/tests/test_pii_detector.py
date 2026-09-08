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


if __name__ == "__main__":
    unittest.main()
