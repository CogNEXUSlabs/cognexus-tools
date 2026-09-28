"""What ``audit_chain`` documents about its HMAC key must be what it does.

``verify_chain`` checks the signature of every chained entry and fails the log
when one is missing or does not match -- deliberately, because the hash chain
alone can be recomputed by anyone who can write the file. The module and
``verify_chain`` docstrings still said that with an ephemeral key "only
hash-chain integrity (prev_hash / entry_hash) can be verified", which reads as
a partial verification that does not exist: an unkeyed writer's log fails
outright in the next process. These tests pin the behaviour and the wording
together.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from artzain import audit_chain as ac


class EphemeralKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="artzain-ephemeral-"))
        self._saved = os.environ.get("COGNEXUS_AUDIT_HMAC_KEY")
        os.environ.pop("COGNEXUS_AUDIT_HMAC_KEY", None)
        ac._signer_instance = None
        ac._chains.clear()
        self.log = self._dir / "decisions.jsonl"

    def tearDown(self) -> None:
        ac._signer_instance = None
        ac._chains.clear()
        if self._saved is None:
            os.environ.pop("COGNEXUS_AUDIT_HMAC_KEY", None)
        else:
            os.environ["COGNEXUS_AUDIT_HMAC_KEY"] = self._saved
        shutil.rmtree(self._dir, ignore_errors=True)

    def _fresh_process(self) -> None:
        """Forget the signer and the chain, as a new interpreter would."""
        ac._signer_instance = None
        ac._chains.clear()

    def test_an_unkeyed_log_fails_in_the_next_process(self) -> None:
        ac.get_chain(self.log).append({"decision_id": "d1"})
        self.assertTrue(ac.verify_chain(self.log).ok, "the writer verifies its own log")

        self._fresh_process()
        result = ac.verify_chain(self.log)
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 1)
        self.assertEqual(result.entries_checked, 0)
        self.assertEqual(result.error, "HMAC mismatch at seq=1")

    def test_a_shared_key_verifies_across_processes(self) -> None:
        os.environ["COGNEXUS_AUDIT_HMAC_KEY"] = "ab" * 32
        self._fresh_process()
        ac.get_chain(self.log).append({"decision_id": "d1"})

        self._fresh_process()
        result = ac.verify_chain(self.log)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.entries_checked, 1)

    def test_the_key_is_read_once_per_process(self) -> None:
        signer = ac._get_signer()
        self.assertTrue(signer._ephemeral)

        os.environ["COGNEXUS_AUDIT_HMAC_KEY"] = "cd" * 32
        self.assertIs(ac._get_signer(), signer, "a later key has no effect")
        self.assertTrue(ac._get_signer()._ephemeral)


class DocstringTests(unittest.TestCase):
    """The docstrings a reader trusts when deciding whether to set a key."""

    def _docs(self) -> list[tuple[str, str]]:
        return [
            ("module", ac.__doc__ or ""),
            ("verify_chain", ac.verify_chain.__doc__ or ""),
        ]

    def test_no_docstring_promises_a_hash_chain_only_verification(self) -> None:
        for name, doc in self._docs():
            flat = " ".join(doc.split()).lower()
            for claim in (
                "only hash-chain integrity",
                "only hash chain integrity",
            ):
                self.assertNotIn(claim, flat, f"{name} docstring still promises {claim!r}")

    def test_the_docstrings_say_an_unkeyed_log_fails_later(self) -> None:
        for name, doc in self._docs():
            flat = " ".join(doc.split()).lower()
            self.assertIn("fails", flat, f"{name} docstring does not say verification fails")
            self.assertIn("hmac mismatch", flat, f"{name} docstring does not name the error")

    def test_the_module_docstring_says_the_key_is_read_once(self) -> None:
        flat = " ".join((ac.__doc__ or "").split()).lower()
        self.assertIn("once per process", flat)


if __name__ == "__main__":
    unittest.main()
