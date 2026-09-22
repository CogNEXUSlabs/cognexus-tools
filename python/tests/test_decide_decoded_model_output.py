"""Offline ``decide(kind="model_output")`` reads a JSON reply the way it reads a tool call.

A reply written as JSON reaches its consumer through a JSON parser, so the
offline destructive-action and injection votes read a ``model_output`` payload
that is JSON as sent and JSON-decoded, as they read a ``tool_call`` payload,
and draw the same findings on it. Before, they read such a payload only as
sent.

The greeting, keyword-list, delimiter-line, string-cap and parity tests failed
before the offline votes read a JSON reply decoded. The plain-text tests passed
before and have to keep passing: a reply that is not JSON is read as written.
"""

from __future__ import annotations

import importlib
import json

import pytest

from artzain.decide import decide


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """No key from the environment or a credentials profile: decide() stays offline."""
    for var in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    from artzain import cloud

    cloud.configure(api_key=None, base_url=None)
    yield
    cloud.configure(api_key=None, base_url=None)


def _decide(payload: str, kind: str = "model_output") -> tuple[str, dict]:
    out = decide(action="send_reply", target="crm:contact:1", payload=payload, kind=kind)
    assert out["offline"] is True
    return out["outcome"], {v["name"]: v for v in out["contributing_agents"]}


GREETINGS = [
    pytest.param("Привет, Иван!", id="cyrillic"),
    pytest.param("こんにちは", id="japanese"),
    pytest.param("Thanks 👍🎉", id="emoji"),
]


@pytest.mark.parametrize("text", GREETINGS)
def test_escaped_non_latin_text_in_a_json_reply_is_allowed(text):
    """``ensure_ascii`` escapes are read as the characters a parser returns."""
    payload = json.dumps({"city": "Paris", "reply": text})
    assert "\\u" in payload  # premise
    outcome, votes = _decide(payload)
    assert outcome == "allow", votes


def test_a_statement_split_across_a_json_list_is_read_as_one_text():
    """Each list of strings is also read joined, as a tool call's is, so a
    statement split across its elements is caught. A list whose joined text is
    not a statement (a bare `["drop", "table"]`, which names no table) is not a
    finding, as the parity test below checks."""
    outcome, votes = _decide(json.dumps({"steps": ["drop table", "users;"]}))
    assert outcome == "deny"
    assert votes["destructive-action"]["findings"][0].startswith("sql.drop_table:")


def test_a_delimiter_line_inside_a_json_reply_string_is_reviewed():
    """A string is read decoded, so its closing code fence stands on a line of its own."""
    outcome, votes = _decide(json.dumps({"answer": "Fix:\n```python\nprint(1)\n```\n"}))
    assert outcome == "review"
    assert votes["prompt-injection"]["severity"] == "medium"


def test_padding_a_json_reply_past_the_string_cap_holds_it():
    from artzain.tool_call_contract import MAX_SCREENED_STRINGS

    outcome, votes = _decide(json.dumps({"rows": [f"row {i}" for i in range(MAX_SCREENED_STRINGS + 50)]}))
    assert outcome == "review"
    assert any(f.startswith("input.too_many_strings:") for f in votes["destructive-action"]["findings"])


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(json.dumps({"city": "Paris", "reply": "It is 21C and clear."}), id="plain"),
        pytest.param(json.dumps({"reply": "Привет, Иван!"}), id="escaped-cyrillic"),
        pytest.param(json.dumps({"keywords": ["drop", "table"]}), id="keyword-list"),
        pytest.param(json.dumps({"answer": "Fix:\n```python\nprint(1)\n```\n"}), id="closing-fence"),
    ],
)
def test_a_json_reply_is_read_the_way_a_tool_call_is(payload, monkeypatch):
    """The same readings; the injection vote's preset is set to the reply's for the call."""
    # The package's ``decide`` attribute is the function, not the module.
    decide_mod = importlib.import_module("artzain.decide")

    _, reply = _decide(payload)
    monkeypatch.setitem(decide_mod._INJECTION_PRESET, "tool_call", decide_mod._INJECTION_PRESET["model_output"])
    _, call = _decide(payload, "tool_call")
    for name in ("destructive-action", "prompt-injection"):
        assert reply[name] == call[name], name


@pytest.mark.parametrize(
    "text, outcome",
    [
        pytest.param('Use "---" as the separator line.', "allow", id="quoted-delimiter"),
        pytest.param("The capital of France is Paris.", "allow", id="plain"),
        # Escapes written in prose are not JSON's, so they are read as written.
        pytest.param("Store it as \\u0441\\u0435\\u043a\\u0440 in the config.", "deny", id="escape-run"),
    ],
)
def test_a_plain_text_reply_is_read_as_written(text, outcome):
    assert _decide(text)[0] == outcome
