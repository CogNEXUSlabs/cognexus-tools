"""A failed policy-rules fetch is not a tenant without rules.

With no local source set, ``load_client_policy_rules`` reads the tenant's rules
from ``GET /api/policy-enforcement/rules`` and caches the list for the process.
The fetch answered every failure the way it answers a tenant with no rules,
``[]``: an HTTP error (the 503 the platform sends while it cannot read the
tenant's rules among them), a timeout, a body that is not a rule list. The
loader cached that answer. So one failed fetch, at process start say, left the
process screening on the built-in conduct rules alone until it restarted, and a
failed ``force_refresh=True`` swapped the tenant's rules for them the same way.

What happens now:

* a failed fetch is never cached: a later call fetches again, after a short
  backoff, so a loop that screens while the fetch fails does not hammer the
  API;
* a failed refresh keeps serving the rules fetched last, for the platform's
  last-known-good window (``COGNEXUS_BUNDLE_LAST_GOOD_GRACE_SECONDS``, five
  minutes by default) counted from the first failure; past it, or with nothing
  fetched yet, the conduct rules alone apply until a fetch succeeds;
* an answer that holds no rules is still an answer, and is cached as one.

``fetch_client_policy_rules`` keeps its contract: a list, ``[]`` on failure.

No network: ``urlopen`` is a stub, and the loader's clock is moved by hand.
"""

from __future__ import annotations

import http.client
import io
import json
import logging
import ssl
import threading
import time
import urllib.error
from collections.abc import Callable
from typing import Any, Optional

import pytest

from artzain import _helpers, cloud, credentials
from artzain._helpers import load_client_policy_rules
from artzain.cloud import fetch_client_policy_rules
from artzain.policy_enforcement import ClientPolicyRule, builtin_conduct_rules

KEY = "cnx_rules_fetch_test_0123456789"
BASE = "https://rules.example.test"
URL = BASE + "/api/policy-enforcement/rules"
#: Another tenant's key, and another deployment of the platform.
OTHER_KEY = "cnx_rules_fetch_other_987654321"
OTHER_BASE = "https://rules.other.example.test"
GRACE_ENV = "COGNEXUS_BUNDLE_LAST_GOOD_GRACE_SECONDS"

#: The tenant's own rule, as the platform lists it.
TENANT = ClientPolicyRule(
    rule_id="ACME-discounts",
    title="No discount promises",
    summary="Account managers must not promise discounts to customers.",
    category="communications_legal",
    agent="compliance_monitor",
    violation_patterns=(r"\bguaranteed discount\b",),
    severity="high",
)
#: The other tenant's own rule.
OTHER_TENANT = ClientPolicyRule(
    rule_id="GLOBEX-pricing",
    title="No price quotes by email",
    summary="Sales staff send price quotes through the quoting tool only.",
    category="communications_legal",
    agent="compliance_monitor",
    violation_patterns=(r"\bprice quote attached\b",),
    severity="medium",
)
CONDUCT_IDS = [r.rule_id for r in builtin_conduct_rules()]
TENANT_IDS = [TENANT.rule_id, *CONDUCT_IDS]
OTHER_IDS = [OTHER_TENANT.rule_id, *CONDUCT_IDS]

#: Longer than the longest wait between two attempts at a failing fetch.
PAST_ANY_BACKOFF = 61.0


class _Answer:
    """What ``urlopen`` hands back: a context manager with ``read``."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _Platform:
    """``GET /api/policy-enforcement/rules`` behind a stubbed ``urlopen``.

    Answers with ``rules`` (``OTHER_RULES`` for ``OTHER_KEY``) unless
    ``failure`` is set: a factory for an exception to raise or a body to answer
    with, called per request so each request gets a fresh one. ``hold`` makes a
    request wait until released.
    """

    def __init__(self) -> None:
        self.rules: list[Any] = [TENANT.to_dict()]
        self.other_rules: list[Any] = [OTHER_TENANT.to_dict()]
        self.urls = {URL}
        self.failure: Optional[Callable[[], Any]] = None
        self.hold: Optional[tuple[threading.Event, threading.Event]] = None
        self.requests = 0
        self.timeouts: list[Optional[float]] = []
        self.keys: list[Optional[str]] = []

    def urlopen(self, req: Any, timeout: Optional[float] = None) -> _Answer:
        assert req.full_url in self.urls
        self.requests += 1
        self.timeouts.append(timeout)
        self.keys.append(req.get_header("X-api-key"))
        if self.hold is not None:
            entered, release = self.hold
            entered.set()
            release.wait(5)
        if self.failure is not None:
            outcome = self.failure()
            if isinstance(outcome, BaseException):
                raise outcome
            return _Answer(outcome)
        rules = self.other_rules if self.keys[-1] == OTHER_KEY else self.rules
        return _Answer(json.dumps({"rules": rules}).encode("utf-8"))


def _unavailable() -> urllib.error.HTTPError:
    """The platform's answer while it cannot read the tenant's rules."""
    body = b'{"detail": "Policy rules are temporarily unavailable. Please try again."}'
    return urllib.error.HTTPError(URL, 503, "Service Unavailable", {}, io.BytesIO(body))  # type: ignore[arg-type]


def _server_error() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, 500, "Internal Server Error", {}, io.BytesIO(b""))  # type: ignore[arg-type]


def _unauthorized() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, 401, "Unauthorized", {}, io.BytesIO(b""))  # type: ignore[arg-type]


FAILURES = [
    pytest.param(_unavailable, id="503-rules-unavailable"),
    pytest.param(_server_error, id="500"),
    pytest.param(lambda: TimeoutError("timed out"), id="timeout"),
    pytest.param(
        lambda: urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")),
        id="unreachable",
    ),
    pytest.param(lambda: b"<html>Down for maintenance</html>", id="not-json"),
    pytest.param(lambda: b"\xff\xfe" + '{"rules": []}'.encode("utf-16-le"), id="not-utf8"),
    pytest.param(lambda: b'{"detail": "maintenance"}', id="no-rule-list"),
    pytest.param(
        lambda: http.client.InvalidURL("URL can't contain control characters. 'rules.example.test'"),
        id="invalid-host",
    ),
]


class _Clock:
    """Stands in for ``_helpers.time``: ``monotonic`` reads a time the test
    moves, and everything else is the real module."""

    def __init__(self) -> None:
        self.now = 50_000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """A key for the stub platform only, no local rules, and a fresh cache."""
    for name in (
        "COGNEXUS_POLICY_RULES_JSON",
        "COGNEXUS_POLICY_RULES_PATH",
        "COGNEXUS_API_KEY",
        "MYAPP_API_KEY",
        "COGNEXUS_API_BASE_URL",
        GRACE_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    # No credentials profile: the path names no file.
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "no-profile.toml"))
    cloud.configure(api_key=KEY, base_url=BASE)
    # The loaded list is cached for the process; monkeypatch restores it.
    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)
    yield
    cloud.configure(api_key=None, base_url=None)


@pytest.fixture
def platform(monkeypatch: pytest.MonkeyPatch) -> _Platform:
    stub = _Platform()
    monkeypatch.setattr(cloud.urllib.request, "urlopen", stub.urlopen)
    # The User-Agent's version lookup reads package metadata on every request,
    # which is most of what a stubbed request costs.
    monkeypatch.setattr(cloud, "_package_version", lambda: "test")
    return stub


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(_helpers, "time", fake)
    return fake


def _ids(rules: list[ClientPolicyRule]) -> list[str]:
    return [r.rule_id for r in rules]


# ---------------------------------------------------------------------------
# A failed fetch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("failure", FAILURES)
def test_a_failed_fetch_is_not_cached(
    platform: _Platform, clock: _Clock, failure: Callable[[], Any]
) -> None:
    platform.failure = failure
    # Nothing was fetched before, so there is nothing else to screen on.
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)

    assert _ids(load_client_policy_rules()) == TENANT_IDS, (
        "a failed fetch was cached as a tenant with no rules"
    )


@pytest.mark.parametrize("failure", FAILURES)
def test_a_failed_refresh_keeps_the_last_good_rules(
    platform: _Platform, clock: _Clock, failure: Callable[[], Any]
) -> None:
    """However long ago they were fetched: the process has screened on them
    since, and would have gone on doing so had it not asked to refresh."""
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    clock.advance(3600)
    platform.failure = failure

    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS, (
        "a failed refresh replaced the tenant's rules with the conduct rules alone"
    )
    assert _ids(load_client_policy_rules()) == TENANT_IDS


@pytest.mark.parametrize(
    "rows",
    [
        pytest.param([TENANT.to_dict(), {"rule_id": "ACME-other", "violation_patterns": 5}],
                     id="unreadable-fields"),
        pytest.param([None], id="null"),
        pytest.param(["ACME-discounts"], id="string"),
        pytest.param([[TENANT.to_dict()]], id="nested-list"),
    ],
)
def test_a_row_that_does_not_read_as_a_rule_fails_the_fetch(
    platform: _Platform, clock: _Clock, rows: list[Any]
) -> None:
    """The answer is not a rule list after all, so it is not the tenant's rules,
    nor an answer that they have none."""
    load_client_policy_rules()
    platform.rules = rows

    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS


def test_a_base_url_that_is_not_a_url_is_a_failed_fetch(
    platform: _Platform, clock: _Clock
) -> None:
    """No request can be made, which is not an answer either; and the public
    fetch returns ``[]`` for it, as it does for any request that fails."""
    cloud.configure(api_key=KEY, base_url="rules.example.test")

    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert fetch_client_policy_rules() == []
    assert platform.requests == 0

    cloud.configure(api_key=KEY, base_url=BASE)
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS


def test_an_answer_the_decoder_cannot_follow_is_a_failed_fetch(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The JSON decoder gives up with RecursionError on nesting deeper than it
    follows; that is an answer that is not JSON, like any other."""

    class _Decoder:
        def loads(self, *args: Any, **kwargs: Any) -> Any:
            raise RecursionError("maximum recursion depth exceeded while decoding")

        def __getattr__(self, name: str) -> Any:
            return getattr(json, name)

    load_client_policy_rules()
    monkeypatch.setattr(cloud, "json", _Decoder())

    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS
    assert fetch_client_policy_rules() == []


def test_a_refresh_that_succeeds_replaces_the_rules(platform: _Platform, clock: _Clock) -> None:
    load_client_policy_rules()
    platform.rules = []

    assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS
    assert platform.requests == 2


def test_the_fetch_is_retried_until_it_succeeds(platform: _Platform, clock: _Clock) -> None:
    """Called as ``screen_client_policy`` calls it, without ``force_refresh``."""
    platform.failure = _unavailable
    load_client_policy_rules()
    for _ in range(5):
        clock.advance(PAST_ANY_BACKOFF)
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert platform.requests == 6

    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS

    # Fetched: cached again, as before.
    clock.advance(3600)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert platform.requests == 7


# ---------------------------------------------------------------------------
# The backoff
# ---------------------------------------------------------------------------


def test_a_failing_fetch_is_not_retried_on_every_call(platform: _Platform, clock: _Clock) -> None:
    """A loop that screens, or refreshes, while the fetch fails."""
    platform.failure = _unavailable
    load_client_policy_rules()
    assert platform.requests == 1

    for _ in range(100):
        load_client_policy_rules()
        load_client_policy_rules(force_refresh=True)

    assert platform.requests == 1, "every call fetched again while the fetch was failing"


def test_the_wait_doubles_with_each_failure(platform: _Platform, clock: _Clock) -> None:
    platform.failure = _unavailable
    load_client_policy_rules()  # failure 1: retried after 1 s

    # Steps of halves, which the clock adds exactly.
    clock.advance(0.5)
    load_client_policy_rules()
    assert platform.requests == 1
    clock.advance(0.5)
    load_client_policy_rules()  # failure 2: retried after 2 s
    assert platform.requests == 2

    clock.advance(1.5)
    load_client_policy_rules()
    assert platform.requests == 2
    clock.advance(0.5)
    load_client_policy_rules()  # failure 3: retried after 4 s
    assert platform.requests == 3

    clock.advance(3.5)
    load_client_policy_rules()
    assert platform.requests == 3
    clock.advance(0.5)
    load_client_policy_rules()
    assert platform.requests == 4


def test_the_wait_is_a_minute_once_it_stops_growing(platform: _Platform, clock: _Clock) -> None:
    platform.failure = _unavailable
    load_client_policy_rules()
    for _ in range(9):  # ten failures in a row
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()
    assert platform.requests == 10

    clock.advance(59.5)
    load_client_policy_rules()
    assert platform.requests == 10
    clock.advance(0.5)
    load_client_policy_rules()
    assert platform.requests == 11


def test_the_wait_stops_growing_at_a_minute(platform: _Platform, clock: _Clock) -> None:
    """However long the fetch keeps failing: a day of failures in a row."""
    platform.failure = _unavailable
    load_client_policy_rules()
    for _ in range(1440):
        clock.advance(60)
        load_client_policy_rules()

    assert platform.requests == 1441


def test_a_retry_in_flight_does_not_hold_up_other_callers(
    platform: _Platform, clock: _Clock
) -> None:
    """A fetch may take its whole timeout. While one caller retries, the
    others are served what a failed fetch serves, rather than waiting."""
    platform.failure = _unavailable
    load_client_policy_rules()
    clock.advance(PAST_ANY_BACKOFF)
    platform.failure = None
    entered, release = threading.Event(), threading.Event()
    platform.hold = (entered, release)

    retry = threading.Thread(target=load_client_policy_rules, daemon=True)
    retry.start()
    try:
        assert entered.wait(10), "the fetch was not retried"
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS
        assert platform.requests == 2
    finally:
        release.set()
        retry.join(5)

    platform.hold = None
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert platform.requests == 2


def test_callers_waiting_on_a_failing_first_fetch_do_not_make_it_again(
    platform: _Platform, clock: _Clock
) -> None:
    """The first load has nothing to serve, so callers wait for it, as before.
    One that waited finds the failure recorded and is served for it."""
    platform.failure = _unavailable
    entered, release = threading.Event(), threading.Event()
    platform.hold = (entered, release)
    served: list[list[str]] = []

    def load() -> None:
        served.append(_ids(load_client_policy_rules()))

    first = threading.Thread(target=load, daemon=True)
    first.start()
    assert entered.wait(10), "the fetch was not made"
    second = threading.Thread(target=load, daemon=True)
    second.start()
    # Time for the second caller to reach the lock. One that comes later finds
    # the failure recorded without waiting, which is the same answer.
    time.sleep(0.2)
    platform.hold = None
    release.set()
    first.join(5)
    second.join(5)

    assert served == [CONDUCT_IDS, CONDUCT_IDS]
    assert platform.requests == 1


def test_an_offline_decision_while_failing_screens_what_the_failure_serves(
    platform: _Platform, clock: _Clock
) -> None:
    """Offline ``decide()`` never fetches, not even a retry that is due; while a
    fetch is failing, its policy vote screens the copy that is being served."""
    from artzain._helpers import _offline_policy_rules

    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    clock.advance(PAST_ANY_BACKOFF)

    assert _ids(_offline_policy_rules()) == TENANT_IDS
    assert platform.requests == 2
    clock.advance(400)
    assert _ids(_offline_policy_rules()) == CONDUCT_IDS
    assert platform.requests == 2


@pytest.mark.parametrize("failing", [False, True], ids=["loaded", "failing"])
def test_after_the_key_is_cleared_offline_and_online_screen_one_list(
    platform: _Platform, clock: _Clock, failing: bool
) -> None:
    """The tenant's rules were fetched with a key that configure() has since
    cleared: an offline decision screens what the loader returns now, the
    conduct rules alone, not the rules fetched under the old key."""
    from artzain._helpers import _offline_policy_rules

    load_client_policy_rules()
    if failing:
        platform.failure = _unavailable
        load_client_policy_rules(force_refresh=True)
    cloud.configure(api_key=None, base_url=None)

    assert _ids(_offline_policy_rules()) == CONDUCT_IDS
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert _ids(_offline_policy_rules()) == CONDUCT_IDS


@pytest.mark.parametrize("force_refresh", [True, False], ids=["refresh", "plain"])
def test_a_local_source_is_read_whatever_the_backoff(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch, force_refresh: bool
) -> None:
    """The backoff spares the API; a JSON source is read at once, as before,
    and in place of the rules fetched last."""
    platform.rules = []
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", json.dumps([TENANT.to_dict()]))

    assert _ids(load_client_policy_rules(force_refresh=force_refresh)) == TENANT_IDS
    assert platform.requests == 2


# ---------------------------------------------------------------------------
# The last-known-good window
# ---------------------------------------------------------------------------


def test_the_last_good_rules_give_way_past_the_window(platform: _Platform, clock: _Clock) -> None:
    """Five minutes from the first failure, as the platform bounds its own copy."""
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)  # the first failure

    clock.advance(299)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    clock.advance(1)  # five minutes to the second: still within
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    clock.advance(0.5)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    # And they do not come back while the fetch keeps failing.
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    # A fetch that succeeds does.
    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS


def test_the_window_starts_again_after_a_success(platform: _Platform, clock: _Clock) -> None:
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    clock.advance(200)
    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)
    load_client_policy_rules()  # fetched again

    platform.failure = _unavailable
    clock.advance(200)
    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS
    clock.advance(299)
    assert _ids(load_client_policy_rules()) == TENANT_IDS


def test_the_window_follows_the_platforms_setting(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(GRACE_ENV, "30")
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)

    clock.advance(29)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    clock.advance(2)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS


@pytest.mark.parametrize("setting", ["0", "-30", "five minutes", ""])
def test_a_setting_that_is_not_a_positive_number_means_five_minutes(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    monkeypatch.setenv(GRACE_ENV, setting)
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)

    clock.advance(299)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    clock.advance(2)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS


@pytest.mark.parametrize(
    ("key", "base"),
    [pytest.param(OTHER_KEY, BASE, id="another-key"), pytest.param(KEY, OTHER_BASE, id="another-host")],
)
def test_a_failed_fetch_for_someone_else_is_not_answered_with_the_last_rules(
    platform: _Platform,
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
    key: str,
    base: str,
) -> None:
    """They are the rules of whoever the last key and host belong to."""
    platform.urls.add(OTHER_BASE + "/api/policy-enforcement/rules")
    load_client_policy_rules()
    cloud.configure(api_key=key, base_url=base)
    platform.failure = _unavailable

    with caplog.at_level(logging.INFO):
        assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    assert platform.keys == [KEY, key]
    warnings = _loader_warnings(caplog)
    assert len(warnings) == 1
    assert "fetched with another API key or host" in warnings[0]


def test_the_same_key_configured_again_keeps_the_last_rules(
    platform: _Platform, clock: _Clock
) -> None:
    load_client_policy_rules()
    cloud.configure(api_key=KEY, base_url=BASE)
    platform.failure = _unavailable

    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS


def test_a_key_changed_while_failing_gives_up_the_last_rules_at_once(
    platform: _Platform, clock: _Clock
) -> None:
    """The copy is the old key's; the wait for the next fetch still holds."""
    load_client_policy_rules()
    platform.failure = _unavailable
    assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS
    cloud.configure(api_key=OTHER_KEY, base_url=BASE)

    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS
    assert platform.keys == [KEY, KEY]
    # Once the wait is over, the fetch is the new key's; its failure does not
    # bring the old rules back either.
    clock.advance(1)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert platform.keys == [KEY, KEY, OTHER_KEY]

    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == OTHER_IDS


@pytest.mark.parametrize("failing", [False, True], ids=["healthy", "failing"])
def test_configure_that_leaves_the_key_and_host_as_they_were_fetches_nothing(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch, failing: bool
) -> None:
    """The key is in the environment, and each call sets and clears the same key
    as an override: the key and host the rules were fetched with never change."""
    cloud.configure(api_key=None, base_url=None)
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", BASE)
    load_client_policy_rules()
    if failing:
        platform.failure = _unavailable
        load_client_policy_rules(force_refresh=True)
    requests = platform.requests

    for _ in range(50):
        cloud.configure(api_key=KEY, base_url=BASE)
        assert _ids(load_client_policy_rules()) == TENANT_IDS
        cloud.configure(api_key=None, base_url=None)
        assert _ids(load_client_policy_rules()) == TENANT_IDS

    assert platform.requests == requests


def test_keys_switched_on_every_call_while_failing_wait_as_one_key_would(
    platform: _Platform, clock: _Clock
) -> None:
    """The wait keeps growing across switches: an hour of them makes about
    as many fetches as an hour of one key (65), not one per switch."""
    platform.failure = _unavailable
    load_client_policy_rules()
    for _ in range(3600):
        clock.advance(1)
        for key in (OTHER_KEY, KEY):
            cloud.configure(api_key=key, base_url=BASE)
            load_client_policy_rules()

    assert platform.requests <= 70


def test_the_generation_is_read_before_the_credentials(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configure() that lands while the credentials are being read leaves
    what the fetch brings back marked as the previous key's, so the next call
    fetches for the new one rather than serving it."""
    resolve = cloud._resolve
    switched: list[bool] = []

    def resolve_then_switch() -> Any:
        creds = resolve()
        if not switched:
            switched.append(True)
            cloud.configure(api_key=OTHER_KEY, base_url=BASE)
        return creds

    monkeypatch.setattr(cloud, "_resolve", resolve_then_switch)

    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert _ids(load_client_policy_rules()) == OTHER_IDS
    assert platform.keys == [KEY, OTHER_KEY]


def test_switching_keys_back_and_forth_while_failing_does_not_hammer_the_api(
    platform: _Platform, clock: _Clock
) -> None:
    """configure() per request, with a key per tenant, while the platform fails."""
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    for _ in range(50):
        for key in (OTHER_KEY, KEY):
            cloud.configure(api_key=key, base_url=BASE)
            load_client_policy_rules()

    assert platform.requests == 2


def test_a_key_changed_with_configure_loads_that_keys_rules_at_the_next_call(
    platform: _Platform, clock: _Clock
) -> None:
    """Not only on a refresh: the cached rules were fetched for the old key."""
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    cloud.configure(api_key=OTHER_KEY, base_url=BASE)

    assert _ids(load_client_policy_rules()) == OTHER_IDS
    assert _ids(load_client_policy_rules()) == OTHER_IDS
    assert platform.keys == [KEY, OTHER_KEY]


def test_configure_with_the_same_key_loads_nothing_again(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Called per request, say: not even the credentials are read again."""
    load_client_policy_rules()
    resolve = cloud._resolve
    reads: list[int] = []

    def counted() -> Any:
        reads.append(1)
        return resolve()

    monkeypatch.setattr(cloud, "_resolve", counted)
    for _ in range(3):
        cloud.configure(api_key=KEY, base_url=BASE + "/")
        assert _ids(load_client_policy_rules()) == TENANT_IDS

    assert platform.requests == 1
    assert reads == []


def test_a_refresh_after_a_key_change_waits_for_a_fetch_already_in_flight(
    platform: _Platform, clock: _Clock
) -> None:
    """The old key's retry is under way when configure() switches key and a
    refresh is asked for. The retry succeeds, and it is the old key's rules:
    the refresh waits for it and then fetches for the new key, and the old
    key's rules are not served under the new one afterwards either."""
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    clock.advance(PAST_ANY_BACKOFF)
    platform.failure = None
    entered, release = threading.Event(), threading.Event()
    platform.hold = (entered, release)
    retry = threading.Thread(target=load_client_policy_rules, daemon=True)
    retry.start()
    refreshed: list[list[str]] = []
    try:
        assert entered.wait(10), "the fetch was not retried"
        platform.hold = None
        cloud.configure(api_key=OTHER_KEY, base_url=BASE)
        refresh = threading.Thread(
            target=lambda: refreshed.append(_ids(load_client_policy_rules(force_refresh=True))),
            daemon=True,
        )
        refresh.start()
        # Time for the refresh to reach the lock. One that comes later finds
        # the retry's rules cached under the old key, which is the same case.
        time.sleep(0.2)
    finally:
        release.set()
        retry.join(5)
    refresh.join(5)

    assert refreshed == [OTHER_IDS]
    assert _ids(load_client_policy_rules()) == OTHER_IDS
    assert platform.keys == [KEY, KEY, KEY, OTHER_KEY]


def test_the_old_keys_copy_is_not_served_under_a_new_key_while_its_fetch_is_in_flight(
    platform: _Platform, clock: _Clock
) -> None:
    """A caller that does not wait for the fetch under way is served the
    conduct rules: the copy, and the fetch, are the old key's."""
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)
    clock.advance(PAST_ANY_BACKOFF)
    platform.failure = None
    entered, release = threading.Event(), threading.Event()
    platform.hold = (entered, release)
    retry = threading.Thread(target=load_client_policy_rules, daemon=True)
    retry.start()
    try:
        assert entered.wait(10), "the fetch was not retried"
        platform.hold = None
        cloud.configure(api_key=OTHER_KEY, base_url=BASE)

        assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    finally:
        release.set()
        retry.join(5)

    assert _ids(load_client_policy_rules()) == OTHER_IDS
    assert platform.keys == [KEY, KEY, KEY, OTHER_KEY]


def test_a_key_changed_outside_configure_starts_a_run_of_its_own(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A key from the environment changes without configure(): it is noticed
    when the next fetch is made, whose failure starts a run of its own, logged
    at WARNING again. The wait keeps growing: the platform is still down."""
    cloud.configure(api_key=None, base_url=None)
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", BASE)
    load_client_policy_rules()
    platform.failure = _unavailable
    load_client_policy_rules(force_refresh=True)  # failure 1
    clock.advance(400)
    load_client_policy_rules()  # failure 2: the old key's copy gives way
    monkeypatch.setenv("COGNEXUS_API_KEY", OTHER_KEY)
    clock.advance(PAST_ANY_BACKOFF)
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS  # failure 3: retried after 4 s
        requests = platform.requests
        clock.advance(3.5)
        load_client_policy_rules()
        assert platform.requests == requests
        clock.advance(0.5)
        load_client_policy_rules()

    assert platform.keys[-2:] == [OTHER_KEY, OTHER_KEY]
    assert platform.requests == requests + 1
    assert len(_loader_warnings(caplog)) == 1
    fetch_failures = [
        r for r in caplog.records if r.name == "artzain.cloud" and "failed HTTP 503" in r.getMessage()
    ]
    assert [r.levelno for r in fetch_failures] == [logging.WARNING, logging.DEBUG]


# ---------------------------------------------------------------------------
# Answers that are not failures
# ---------------------------------------------------------------------------


def test_an_answer_without_rules_is_cached(platform: _Platform, clock: _Clock) -> None:
    platform.rules = []

    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    clock.advance(3600)
    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert platform.requests == 1


def test_an_answer_without_rules_retires_the_last_good_rules(
    platform: _Platform, clock: _Clock
) -> None:
    """The tenant took its policy down: a later failure must not bring it back."""
    load_client_policy_rules()
    platform.rules = []
    assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS

    platform.failure = _unavailable
    assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS


def test_no_api_key_is_not_a_failed_fetch(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """No key, no tenant: nothing to fetch, nothing to retry, nothing to warn of."""
    cloud.configure(api_key=None, base_url=None)

    with caplog.at_level(logging.INFO):
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS
        clock.advance(PAST_ANY_BACKOFF)
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    assert platform.requests == 0
    assert _loader_warnings(caplog) == []


def test_conflicting_credentials_are_a_failed_fetch(
    platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile's key was issued for another host, so it is not sent. The
    tenant's rules are unknown, which is not the same as having none."""
    cloud.configure(api_key=None, base_url=None)
    credentials.write_profile(api_key=KEY, base_url=BASE)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", "https://elsewhere.example.test")

    assert _ids(load_client_policy_rules()) == CONDUCT_IDS
    assert platform.requests == 0

    monkeypatch.delenv("COGNEXUS_API_BASE_URL")
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS


# ---------------------------------------------------------------------------
# What is logged
# ---------------------------------------------------------------------------


def _loader_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "artzain.security" and r.levelno >= logging.WARNING
    ]


def test_a_failed_first_fetch_says_the_conduct_rules_apply_alone(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    platform.failure = _unavailable
    with caplog.at_level(logging.INFO):
        load_client_policy_rules()

    warnings = _loader_warnings(caplog)
    assert len(warnings) == 1
    assert "conduct rules" in warnings[0]


def test_a_failed_refresh_says_which_rules_are_served(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    load_client_policy_rules()
    clock.advance(120)
    platform.failure = _unavailable
    with caplog.at_level(logging.INFO):
        load_client_policy_rules(force_refresh=True)
        clock.advance(301)
        load_client_policy_rules()
        for _ in range(5):  # still failing: nothing new to say
            clock.advance(PAST_ANY_BACKOFF)
            load_client_policy_rules()

    warnings = _loader_warnings(caplog)
    assert len(warnings) == 2
    assert "fetched 120s ago" in warnings[0]
    assert "conduct rules" in warnings[1]


def test_a_recovery_is_logged(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    platform.failure = _unavailable
    load_client_policy_rules()
    clock.advance(PAST_ANY_BACKOFF)
    load_client_policy_rules()
    platform.failure = None
    clock.advance(PAST_ANY_BACKOFF)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        load_client_policy_rules()

    assert [
        r.getMessage() for r in caplog.records if r.name == "artzain.security"
    ] == ["policy rules fetched again after 2 failed attempts over 122s"]


def test_a_failing_run_warns_once_however_long_it_lasts(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """The first failure is logged at WARNING, by the fetch and by the loader;
    each retry's failure at DEBUG."""
    platform.failure = _unavailable
    with caplog.at_level(logging.DEBUG):
        load_client_policy_rules()
        for _ in range(100):
            clock.advance(PAST_ANY_BACKOFF)
            load_client_policy_rules()

    assert platform.requests == 101
    fetch_failures = [
        r for r in caplog.records if r.name == "artzain.cloud" and "failed HTTP 503" in r.getMessage()
    ]
    assert [r.levelno for r in fetch_failures] == [logging.WARNING] + [logging.DEBUG] * 100
    assert len(_loader_warnings(caplog)) == 1


def test_a_change_in_how_the_fetch_fails_is_warned_of(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    platform.failure = _unavailable
    with caplog.at_level(logging.INFO):
        load_client_policy_rules()
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()
        platform.failure = _unauthorized
        for _ in range(3):
            clock.advance(PAST_ANY_BACKOFF)
            load_client_policy_rules()

    warnings = _loader_warnings(caplog)
    assert len(warnings) == 2
    assert "(HTTP 503)" in warnings[0]
    assert warnings[1] == "policy rules fetch still failing, now (HTTP 401)"


def test_each_way_of_failing_is_warned_of_once_in_a_run(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A platform that flaps between two errors all day warns of each once."""
    failures = [_unavailable, _server_error]
    with caplog.at_level(logging.INFO):
        for attempt in range(200):
            platform.failure = failures[attempt % 2]
            load_client_policy_rules()
            clock.advance(PAST_ANY_BACKOFF)

    assert platform.requests == 200
    warnings = _loader_warnings(caplog)
    assert len(warnings) == 2
    assert warnings[1] == "policy rules fetch still failing, now (HTTP 500)"


@pytest.mark.parametrize("held", ["no-key", "local"])
def test_a_failure_after_rules_that_were_no_tenants_says_so_plainly(
    platform: _Platform,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    held: str,
) -> None:
    """The rules loaded last came with no key, or from a local source: no
    tenant's rules were held, so there is no other key or host to speak of."""
    if held == "no-key":
        cloud.configure(api_key=None, base_url=None)
        load_client_policy_rules()
        cloud.configure(api_key=KEY, base_url=BASE)
    else:
        monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", json.dumps([TENANT.to_dict()]))
        load_client_policy_rules()
        monkeypatch.delenv("COGNEXUS_POLICY_RULES_JSON")
    platform.failure = _unavailable

    with caplog.at_level(logging.INFO):
        assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS

    assert _loader_warnings(caplog) == [
        "policy rules fetch failed (HTTP 503); screening on the built-in conduct rules "
        "alone until a fetch succeeds"
    ]


def test_a_log_handler_that_raises_loses_neither_a_failure_nor_a_recovery(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """What the loader learnt is recorded before it is logged."""

    class _Broken(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise RuntimeError("the log sink is down")

    logger = logging.getLogger("artzain.security")
    broken = _Broken()
    caplog.set_level(logging.INFO, logger="artzain.security")
    platform.failure = _unavailable
    logger.addHandler(broken)
    try:
        with pytest.raises(RuntimeError):
            load_client_policy_rules()
        for _ in range(10):
            load_client_policy_rules(force_refresh=True)
        assert platform.requests == 1, "the failure was not recorded, so nothing waited"

        platform.failure = None
        clock.advance(PAST_ANY_BACKOFF)
        with pytest.raises(RuntimeError):
            load_client_policy_rules()
        assert _ids(load_client_policy_rules()) == TENANT_IDS
        assert platform.requests == 2, "the recovery was not recorded"
    finally:
        logger.removeHandler(broken)


def test_no_log_line_carries_the_key_or_the_host(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    load_client_policy_rules()
    platform.failure = _unavailable
    with caplog.at_level(logging.DEBUG):
        load_client_policy_rules(force_refresh=True)
        clock.advance(400)
        load_client_policy_rules()
        platform.failure = None
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()

    messages = [r.getMessage() for r in caplog.records]
    assert messages
    assert not [m for m in messages if KEY in m or "rules.example.test" in m]


def test_the_loader_never_names_the_host_even_when_the_failure_does(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A certificate for another name, say. The loader's lines give the kind of
    failure only; the request's own line reports the error as it did before."""
    load_client_policy_rules()
    platform.failure = lambda: urllib.error.URLError(
        ssl.SSLCertVerificationError(
            1, "certificate verify failed: certificate is not valid for 'rules.example.test'"
        )
    )
    with caplog.at_level(logging.DEBUG):
        load_client_policy_rules(force_refresh=True)  # serving the rules fetched last
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()
        clock.advance(400)
        load_client_policy_rules()  # past the window
        platform.failure = None
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()  # fetched again

    loader = [r.getMessage() for r in caplog.records if r.name == "artzain.security"]
    assert len(loader) == 3
    assert not [m for m in loader if KEY in m or "rules.example.test" in m]


def test_a_host_that_no_request_can_carry_is_not_logged(
    platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """``http.client`` quotes the host it refuses; the log names where the
    setting came from instead, the request's own line included."""
    platform.failure = lambda: http.client.InvalidURL(
        "URL can't contain control characters. 'rules.example.test' (found at least ' ')"
    )
    with caplog.at_level(logging.DEBUG):
        load_client_policy_rules()
        clock.advance(PAST_ANY_BACKOFF)
        load_client_policy_rules()

    messages = [r.getMessage() for r in caplog.records]
    assert any("no request can be made" in m for m in messages)
    assert not [m for m in messages if KEY in m or "rules.example.test" in m]


# ---------------------------------------------------------------------------
# The public fetch
# ---------------------------------------------------------------------------


def test_fetch_client_policy_rules_still_answers_a_list(platform: _Platform) -> None:
    assert fetch_client_policy_rules() == [TENANT.to_dict()]

    platform.failure = _unavailable
    assert fetch_client_policy_rules(timeout_sec=3.0) == []
    assert platform.timeouts == [12.0, 3.0]

    platform.failure = None
    cloud.configure(api_key=None, base_url=None)
    assert fetch_client_policy_rules() == []
    assert platform.requests == 2


def test_the_loader_fetches_with_the_default_timeout(platform: _Platform, clock: _Clock) -> None:
    load_client_policy_rules()

    assert platform.timeouts == [12.0]
