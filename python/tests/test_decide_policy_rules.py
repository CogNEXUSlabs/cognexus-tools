"""Offline ``decide()`` screens the policy rules ``screen_client_policy()`` screens.

With no API key, ``screen_client_policy()`` screens what
``load_client_policy_rules()`` returns: the rules in
``COGNEXUS_POLICY_RULES_JSON``, else in the JSON file
``COGNEXUS_POLICY_RULES_PATH`` names, with the built-in conduct rules merged in.
Offline ``decide()`` screened the built-in conduct rules alone, so a text that
broke one of those rules was refused by the one call and allowed by the other,
and nothing in the decision said the rules had been left out.

The offline policy vote now screens the list ``load_client_policy_rules()``
loads, without its fetch of the tenant's rules, so an offline decision makes
no network call. Rules that cannot be loaded are not screened as no rules at
all: ``screen_client_policy()`` raises, and the vote is a ``deny`` carrying the
error. With nothing configured and no key, the loader no longer caches the
conduct rules it returns, so a call made before a key is configured cannot
keep the tenant's rules out of the process once one is.
"""

from __future__ import annotations

import importlib
import json
import linecache
import sys
from typing import Any

import pytest

from artzain import _helpers, cloud
from artzain._helpers import (
    load_client_policy_rules,
    screen_client_policy,
    should_block_policy,
)
from artzain.decide import decide
from artzain.policy_enforcement import ClientPolicyRule

#: The module, not the function ``artzain`` exports under the same name.
decide_module = importlib.import_module("artzain.decide")

BUILTIN_IDS = ["CONDUCT-PROFANITY-CLIENT", "CONDUCT-HARASSMENT"]
TEST_KEY = "cnx_test_key_not_real"
TEST_BASE = "https://example.test"

#: A rule of the user's own, as the SDK guide writes its example.
DISCOUNTS = ClientPolicyRule(
    rule_id="CPR-discounts",
    title="No discount promises",
    summary="Account managers must not promise discounts to customers.",
    category="business_policy",
    agent="compliance_monitor",
    violation_patterns=(r"promise.{0,40}discount",),
    severity="high",
)
#: A second rule, at a severity that refuses nothing on its own.
SLANG = ClientPolicyRule(
    rule_id="CPR-slang",
    title="No slang in customer email",
    summary="Write 'widget assembly', not 'widget thingy'.",
    category="business_policy",
    agent="compliance_monitor",
    violation_patterns=(r"\bwidget thingy\b",),
    severity="low",
)

PROMISE = "I can promise you a 40% discount if you sign today."
CLEAN = "The quarterly report is attached."
DISCOUNTS_FINDING = "CPR-discounts: No discount promises"
#: Profanity in a customer context: CONDUCT-PROFANITY-CLIENT, critical.
PROFANITY_AT_CUSTOMER = "Tell the customer this is bullshit and we will not refund them."
PROFANITY_FINDING = "CONDUCT-PROFANITY-CLIENT: Professional conduct with clients"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """No key, rules or audit directory from the environment, and a fresh cache."""
    for name in (
        "COGNEXUS_POLICY_RULES_JSON",
        "COGNEXUS_POLICY_RULES_PATH",
        "COGNEXUS_API_KEY",
        "MYAPP_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    # No credentials profile either: the path names no file.
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "no-profile.toml"))
    cloud.configure(api_key=None, base_url=None)
    # The loaded list is cached for the process; monkeypatch restores it.
    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)
    yield
    cloud.configure(api_key=None, base_url=None)


def _configure(
    monkeypatch: pytest.MonkeyPatch, how: str, rules: list[ClientPolicyRule], tmp_path: Any
) -> None:
    """Configure *rules* the way a user does, inline (``json``) or as a file (``path``)."""
    raw = json.dumps([r.to_dict() for r in rules])
    if how == "json":
        monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", raw)
    else:
        path = tmp_path / "rules.json"
        path.write_text(raw, encoding="utf-8")
        monkeypatch.setenv("COGNEXUS_POLICY_RULES_PATH", str(path))


def _decide(payload: str, *, kind: str = "user_input") -> dict:
    out = decide(action="send_email", target="crm:1", payload=payload, kind=kind)
    assert out["offline"] is True
    return out


def _policy_vote(decision: dict) -> dict:
    return next(
        v for v in decision["contributing_agents"] if v["name"] == "policy-enforcement"
    )


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        pytest.param("user_input", PROFANITY_AT_CUSTOMER, id="text"),
        pytest.param(
            "tool_call",
            json.dumps({"tool": "send_email", "arguments": {"body": PROFANITY_AT_CUSTOMER}}),
            id="tool-call",
        ),
    ],
)
def test_with_nothing_configured_the_conduct_rules_still_apply(kind: str, payload: str) -> None:
    """With no rules configured the offline vote screens the built-in conduct
    rules, as it always did. An empty list would not do: the evaluator runs the
    conduct detector only beside a non-empty rule list."""
    out = _decide(payload, kind=kind)
    vote = _policy_vote(out)

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"] == [PROFANITY_FINDING]
    assert out["outcome"] == "deny"


@pytest.mark.parametrize("how", ["json", "path"])
def test_offline_decide_screens_the_configured_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, how: str
) -> None:
    """A configured rule refuses a decision offline, as it refuses the same text
    in ``screen_client_policy()``."""
    _configure(monkeypatch, how, [DISCOUNTS], tmp_path)

    out = _decide(PROMISE)
    vote = _policy_vote(out)

    assert (vote["verdict"], vote["severity"]) == ("deny", "high")
    assert vote["findings"] == [DISCOUNTS_FINDING]
    assert out["outcome"] == "deny"
    assert out["reasons"] == [f"policy-enforcement (high): {DISCOUNTS_FINDING}"]


@pytest.mark.parametrize("kind", ["user_input", "external_content", "tabular", "model_output"])
def test_offline_decide_and_screen_client_policy_screen_one_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, kind: str
) -> None:
    """What the offline vote finds in a text is what ``screen_client_policy()``
    reports for it, and both refuse it."""
    _configure(monkeypatch, "json", [DISCOUNTS, SLANG], tmp_path)
    text = "I promise a discount on every widget thingy we ship."

    report = screen_client_policy(text, source="unit-test")
    vote = _policy_vote(_decide(text, kind=kind))

    assert [f.rule_id for f in report.findings] == ["CPR-discounts", "CPR-slang"]
    assert sorted(vote["findings"]) == sorted(
        f"{f.rule_id}: {f.rule_title}" for f in report.findings
    )
    assert should_block_policy(report)
    assert vote["verdict"] == "deny"


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        pytest.param(
            "tool_call",
            json.dumps({"tool": "send_email", "arguments": {"to": "a@b.example", "body": PROMISE}}),
            id="tool-call",
        ),
        pytest.param("model_output", json.dumps({"reply": PROMISE}), id="json-reply"),
    ],
)
def test_a_json_payload_is_screened_against_the_configured_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, kind: str, payload: str
) -> None:
    """The readings a tool call or a JSON reply gets offline take the configured
    rules too, not only a plain text."""
    _configure(monkeypatch, "json", [DISCOUNTS], tmp_path)

    out = _decide(payload, kind=kind)

    assert _policy_vote(out)["findings"] == [DISCOUNTS_FINDING]
    assert out["outcome"] == "deny"


@pytest.mark.parametrize(
    ("variable", "value", "error"),
    [
        pytest.param("COGNEXUS_POLICY_RULES_PATH", "missing.json", FileNotFoundError, id="missing-file"),
        pytest.param("COGNEXUS_POLICY_RULES_JSON", "[{", json.JSONDecodeError, id="malformed-json"),
        pytest.param("COGNEXUS_POLICY_RULES_JSON", '"rules"', ValueError, id="not-a-list"),
    ],
)
def test_rules_that_cannot_be_read_deny_rather_than_go_unscreened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    variable: str,
    value: str,
    error: type[Exception],
) -> None:
    """Configured rules that cannot be read are not screened as no rules at all:
    ``screen_client_policy()`` raises, and the offline vote is a ``deny`` that
    carries the error, as any guard that raises offline is."""
    if variable == "COGNEXUS_POLICY_RULES_PATH":
        value = str(tmp_path / value)
    monkeypatch.setenv(variable, value)

    with pytest.raises(error) as raised:
        screen_client_policy(CLEAN, source="unit-test")
    out = _decide(CLEAN)
    vote = _policy_vote(out)

    assert type(raised.value) is error
    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["error"].startswith(f"{error.__name__}: ")
    assert vote["findings"] == [f"policy-enforcement raised {error.__name__}"]
    assert out["outcome"] == "deny"


def _serve_tenant_rules(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Serve ``DISCOUNTS`` as the tenant's rules, as the platform endpoint does:
    nothing without a key. Returns whether each fetch had a key.

    It stands in for ``cloud._fetch_policy_rules``, the request the loader
    makes: ``fetch_client_policy_rules`` returns the same rows, but cannot tell
    a failed request from a tenant without rules, so the loader does not go
    through it."""
    fetched_with_key: list[bool] = []

    def _fetch(creds: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        keyed = creds is not None and bool(creds.api_key)
        fetched_with_key.append(keyed)
        return [DISCOUNTS.to_dict()] if keyed else []

    monkeypatch.setattr(cloud, "_fetch_policy_rules", _fetch)
    return fetched_with_key


def _configure_key() -> None:
    cloud.configure(api_key=TEST_KEY, base_url=TEST_BASE)


def test_an_offline_decision_never_fetches_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """The vote screens what is loaded and never fetches the tenant's rules, so
    an offline decision makes no network call, even when a key is configured
    while it is being decided (``configure()`` in another thread, or
    ``artzain login``), and caches nothing that would keep them out later."""
    fetched_with_key = _serve_tenant_rules(monkeypatch)
    injection_vote = decide_module._offline_injection_vote

    def _vote_then_configure_a_key(*args: Any, **kwargs: Any) -> dict:
        # The policy vote runs after this one, with a key configured by then.
        vote = injection_vote(*args, **kwargs)
        _configure_key()
        return vote

    monkeypatch.setattr(decide_module, "_offline_injection_vote", _vote_then_configure_a_key)

    out = _decide(PROMISE)

    assert fetched_with_key == []
    assert out["outcome"] == "allow"
    assert [r.rule_id for r in load_client_policy_rules()] == ["CPR-discounts", *BUILTIN_IDS]
    assert fetched_with_key == [True]


@pytest.mark.parametrize("first", ["load_client_policy_rules", "decide"])
def test_a_key_configured_later_fetches_the_tenant_rules(
    monkeypatch: pytest.MonkeyPatch, first: str
) -> None:
    """With nothing configured and no key, the conduct rules are all there is to
    screen, and that list is no longer cached: once a key is configured, the
    tenant's rules are fetched, whichever call ran first. The ``decide`` case
    holds the offline vote to it, since the vote now loads rules too."""
    fetched_with_key = _serve_tenant_rules(monkeypatch)
    if first == "decide":
        assert _decide(PROMISE)["outcome"] == "allow"
    else:
        assert [r.rule_id for r in load_client_policy_rules()] == BUILTIN_IDS

    _configure_key()

    assert [r.rule_id for r in load_client_policy_rules()] == ["CPR-discounts", *BUILTIN_IDS]
    assert fetched_with_key[-1:] == [True]


def test_a_reload_with_nothing_to_load_drops_the_cached_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reload that finds no rules configured and no key leaves nothing cached.
    The tenant's rules fetched while a key was set do not outlast it, and once
    a key is set again the next call fetches, rather than reading back a list
    cached while there was none."""
    fetched_with_key = _serve_tenant_rules(monkeypatch)
    _configure_key()
    assert [r.rule_id for r in load_client_policy_rules()] == ["CPR-discounts", *BUILTIN_IDS]

    cloud.configure(api_key=None, base_url=None)

    assert [r.rule_id for r in load_client_policy_rules(force_refresh=True)] == BUILTIN_IDS
    assert [r.rule_id for r in load_client_policy_rules()] == BUILTIN_IDS
    assert _decide(PROMISE)["outcome"] == "allow"

    _configure_key()

    assert [r.rule_id for r in load_client_policy_rules()] == ["CPR-discounts", *BUILTIN_IDS]
    assert fetched_with_key == [True, True]


def _drop_the_cache_before_it_is_copied() -> list[int]:
    """Trace ``artzain._helpers`` and set its rules cache to ``None`` just before
    the first ``return list(...)`` line there runs, as a reload with nothing to
    load, in another thread, can. Returns the line numbers it acted on."""
    acted: list[int] = []

    def _line(frame: Any, event: str, _arg: Any) -> Any:
        if event == "line" and not acted:
            source = linecache.getline(frame.f_code.co_filename, frame.f_lineno)
            if source.strip().startswith("return list("):
                acted.append(frame.f_lineno)
                _helpers._policy_rules_cache = None
        return _line

    def _call(frame: Any, event: str, _arg: Any) -> Any:
        return _line if frame.f_globals is vars(_helpers) else None

    sys.settrace(_call)
    return acted


@pytest.mark.parametrize("reader", ["load_client_policy_rules", "decide"])
def test_a_reload_that_drops_the_cache_cannot_break_a_read_under_way(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, reader: str
) -> None:
    """The unlocked path reads the cache once. A reload with nothing to load
    sets it back to ``None``, so a read that found it set and then read it
    again could copy ``None``: a free-threaded build can switch threads
    between the two. A line tracer makes that switch happen here."""
    _configure(monkeypatch, "json", [DISCOUNTS], tmp_path)
    assert [r.rule_id for r in load_client_policy_rules()] == ["CPR-discounts", *BUILTIN_IDS]

    previous = sys.gettrace()
    acted = _drop_the_cache_before_it_is_copied()
    try:
        if reader == "decide":
            vote = _policy_vote(_decide(PROMISE))
            listed = vote["findings"]
            assert vote["error"] is None
        else:
            listed = [r.rule_id for r in load_client_policy_rules()]
    finally:
        sys.settrace(previous)

    assert acted, "the tracer never reached the copy of the cached list"
    assert listed == (
        [DISCOUNTS_FINDING] if reader == "decide" else ["CPR-discounts", *BUILTIN_IDS]
    )


def test_a_reload_reaches_the_next_offline_decision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """A list that loads is kept for the process, as for
    ``screen_client_policy()``, and ``load_client_policy_rules(force_refresh=True)``
    reloads it for the next decision too."""
    _configure(monkeypatch, "json", [DISCOUNTS], tmp_path)
    assert _policy_vote(_decide(PROMISE))["findings"] == [DISCOUNTS_FINDING]

    _configure(monkeypatch, "json", [SLANG], tmp_path)
    assert _policy_vote(_decide(PROMISE))["findings"] == [DISCOUNTS_FINDING]

    load_client_policy_rules(force_refresh=True)
    assert _policy_vote(_decide(PROMISE))["verdict"] == "allow"
    assert _policy_vote(_decide("Ship the widget thingy."))["findings"] == [
        "CPR-slang: No slang in customer email"
    ]
