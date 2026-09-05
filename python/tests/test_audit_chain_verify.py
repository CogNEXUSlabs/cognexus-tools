"""``artzain.verify_chain`` must refuse entries whose signature was removed.

Mirrors ``application/security/tests/test_audit_chain.py`` for the SDK's
HMAC-signed JSONL chain: a chained entry without ``sig`` fails, and an
unsequenced line after the chain has started fails — both were previously
accepted, which let a writer rewrite an entry, drop its signature, recompute
the hashes forward, and still verify.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from artzain import audit_chain as ac


def _rechain(entries: list[dict]) -> list[str]:
    prev_hash = ac._GENESIS_HASH
    lines: list[str] = []
    for entry in entries:
        if entry.get("seq") is None:
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        else:
            entry = dict(entry)
            entry["prev_hash"] = prev_hash
            body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
            canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            entry["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        lines.append(line)
        prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
    return lines


class VerifyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="artzain-chain-"))
        # A fixed key so the verifier holds the same HMAC key as the writer.
        self._saved = os.environ.get("COGNEXUS_AUDIT_HMAC_KEY")
        os.environ["COGNEXUS_AUDIT_HMAC_KEY"] = "ab" * 32
        ac._signer_instance = None
        ac._chains.clear()
        self.log = self._dir / "decisions.jsonl"
        self.chain = ac.get_chain(self.log)

    def tearDown(self) -> None:
        ac._signer_instance = None
        ac._chains.clear()
        if self._saved is None:
            os.environ.pop("COGNEXUS_AUDIT_HMAC_KEY", None)
        else:
            os.environ["COGNEXUS_AUDIT_HMAC_KEY"] = self._saved
        shutil.rmtree(self._dir, ignore_errors=True)

    def _append(self, n: int) -> list[dict]:
        return [json.loads(self.chain.append({"decision_id": f"d{i}"})) for i in range(n)]

    def _write(self, lines: list[str]) -> None:
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_untouched_chain_verifies(self) -> None:
        self._append(3)
        result = ac.verify_chain(self.log)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.entries_checked, 3)

    def test_signature_stripped_is_rejected(self) -> None:
        entries = self._append(3)
        entries[1]["decision_id"] = "forged"
        del entries[1]["sig"]
        self._write(_rechain(entries))
        result = ac.verify_chain(self.log)
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 2)
        self.assertIn("missing signature", result.error or "")

    def test_seq_dropped_after_chain_started_is_rejected(self) -> None:
        entries = self._append(3)
        for key in ("seq", "sig", "entry_hash", "prev_hash"):
            entries[1].pop(key, None)
        self._write(_rechain(entries))
        result = ac.verify_chain(self.log)
        self.assertFalse(result.ok)
        self.assertIn("unchained entry", result.error or "")

    def test_legacy_lines_before_the_chain_are_accepted(self) -> None:
        self.log.write_text(json.dumps({"decision_id": "old"}) + "\n", encoding="utf-8")
        ac._chains.clear()
        chain = ac.get_chain(self.log)
        chain.append({"decision_id": "d1"})
        result = ac.verify_chain(self.log)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.entries_checked, 2)


if __name__ == "__main__":
    unittest.main()
