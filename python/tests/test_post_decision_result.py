"""post_decision_result sends the reference and not a timestamp."""

import json

import pytest

import artzain.cloud as cloud
from artzain.cloud import configure
from artzain.decide import DecisionError, post_decision_result

_DECISION = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


class _Resp:
    def __init__(self, raw: bytes):
        self._raw = raw

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_the_call_sends_only_the_reference(monkeypatch):
    configure(api_key="unit-key", base_url="https://example.test")
    seen = {}

    def urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode())
        raw = json.dumps({
            "decision_id": _DECISION,
            "result_ref": "invoice-9",
            "result_posted_at": "2026-10-14T16:00:00+00:00",
        }).encode()
        return _Resp(raw)

    monkeypatch.setattr(cloud, "_urlopen", urlopen)
    out = post_decision_result(" " + _DECISION.lower() + " ", " invoice-9 ")
    assert seen["url"] == f"https://example.test/api/v1/decisions/{_DECISION}/result"
    assert seen["body"] == {"result_ref": "invoice-9"}
    assert out["result_posted_at"] == "2026-10-14T16:00:00+00:00"


def test_no_key_does_not_post(monkeypatch):
    configure(api_key=None, base_url=None)
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)

    def urlopen(req, timeout=0):
        raise AssertionError("sent")

    monkeypatch.setattr(cloud, "_urlopen", urlopen)
    with pytest.raises(DecisionError):
        post_decision_result(_DECISION, "invoice-9")


def test_a_short_id_is_refused_before_sending():
    with pytest.raises(ValueError):
        post_decision_result("short", "invoice-9")
