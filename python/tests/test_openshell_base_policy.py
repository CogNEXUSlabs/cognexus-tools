"""The base policy the sidecar gives a new sandbox, and what it does without one.

The engine compiles and proves a team's OpenShell base policy and hands it to
the gateway's sidecar. The sidecar had the code to apply one and was never
given one (``main()`` passed none), so a sandbox created with no policy
started on whatever its image held.

* A sidecar with a gateway credential fetches the base policy, keeps it with
  its digest, and patches it into a create that carries no policy.
* Until it has been told what the base policy is, such a create is refused
  without a decision. A create that brings its own policy is decided as usual.
* When the engine says the team has none, a create is decided as it is.
* A copy on disk that does not match its digest is not a policy.
* A sidecar on an account key is given no base policy and changes nothing.
"""

from __future__ import annotations

import copy
import io
import json
import os
import stat
import sys
import urllib.error

import pytest

from artzain.openshell import base_policy as bp
from artzain.openshell import interceptor as osi
from artzain.openshell import sidecar
from artzain.openshell.state import GatewayLedger

DECISION = "01JABCDEFGHJKMNPQRSTVWXYZ0"
POLICY = {"version": "1", "networkPolicies": {"artzain": {
    "binaries": [{"path": "/usr/bin/curl"}],
    "endpoints": [{"host": "db.internal", "port": 5432},
                  {"host": "engine.internal", "port": 443, "protocol": "rest",
                   "enforcement": "NETWORK_ENFORCEMENT_MODE_ENFORCE",
                   "rules": [{"allow": {"method": "POST", "path": "/api/v1/décisions"}}]}]}}}
BUNDLE = {"id": "01BUNDLE", "name": "acme", "version": "1.0.0", "body_sha256": "a" * 64}
CREATE = {"name": "s1", "spec": {"command": ["sleep", "infinity"]},
          "workspaceScope": {"workspace": "default"}}
OWN_POLICY = {"version": "1", "filesystem": {"readOnly": ["/usr"]}}


def _answer(policy=POLICY, **over):
    answer = {"gateway_id": "gw-a", "base_policy": policy,
              "digest": bp.policy_digest(policy) if policy else None,
              "reason": None if policy else "no_openshell_section",
              "bundle": dict(BUNDLE), "prover": {"result": "within_boundary"},
              "refresh_seconds": 300}
    answer.update(over)
    return answer


def _call(phase, body, method="CreateSandbox"):
    return {"method": f"openshell.v1.OpenShell/{method}", "phase": phase,
            "body": copy.deepcopy(body)}


class _Engine:
    def __init__(self):
        self.requests = []

    def __call__(self, payload):
        self.requests.append(dict(payload))
        return {"outcome": "allow", "decision_id": DECISION, "status_code": 200}


@pytest.fixture(autouse=True)
def _sidecar_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    for name in ("OPENSHELL_SIDECAR_BASE_POLICY", "ARTZAIN_DECISION_URL",
                 "OPENSHELL_SIDECAR_LIST_WORKSPACES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_BASE", None)


@pytest.fixture
def cache(tmp_path):
    return str(tmp_path / "sidecar" / "base-policy.json")


def _store(cache_path=None):
    return bp.BasePolicyStore(cache_path=cache_path, gateway_id="gw-a")


# ---------------------------------------------------------------------------
# The digest
# ---------------------------------------------------------------------------


def test_the_digest_is_of_the_policys_canonical_json():
    import hashlib

    canonical = ('{"networkPolicies":{"artzain":{"binaries":[{"path":"/usr/bin/curl"}],'
                 '"endpoints":[{"host":"db.internal","port":5432},{"enforcement":'
                 '"NETWORK_ENFORCEMENT_MODE_ENFORCE","host":"engine.internal","port":443,'
                 '"protocol":"rest","rules":[{"allow":{"method":"POST","path":'
                 '"/api/v1/décisions"}}]}]}},"version":"1"}')
    assert bp.policy_digest(POLICY) == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    reordered = json.loads(json.dumps(POLICY, sort_keys=True))
    assert bp.policy_digest(reordered) == bp.policy_digest(POLICY)
    changed = copy.deepcopy(POLICY)
    changed["networkPolicies"]["artzain"]["endpoints"][0]["port"] = 5433
    assert bp.policy_digest(changed) != bp.policy_digest(POLICY)


# ---------------------------------------------------------------------------
# What the engine says
# ---------------------------------------------------------------------------


def test_a_store_knows_nothing_until_it_is_told():
    store = _store()
    assert store.current() == (bp.UNKNOWN, None) and store.digest == ""


def test_a_delivered_policy_is_kept_with_its_digest():
    store, pristine = _store(), copy.deepcopy(POLICY)
    answer = _answer(copy.deepcopy(POLICY))
    assert store.accept(answer) is True
    state, policy = store.current()
    assert (state, policy) == (bp.HAVE, pristine) and store.digest == bp.policy_digest(pristine)
    # The store's own policy is changed neither through what it hands out
    # nor through the answer it was given.
    policy["version"] = "changed by the caller"
    answer["base_policy"]["version"] = "changed by the sender"
    assert store.current()[1] == pristine


def test_being_told_there_is_none_is_an_answer():
    store = _store()
    store.accept(_answer())
    assert store.accept(_answer(None)) is True
    assert store.current() == (bp.NONE, None) and store.digest == ""


@pytest.mark.parametrize("answer", [
    None, [], "policy", {},
    _answer(gateway_id="gw-other"),
    _answer(digest="0" * 64),
    _answer(digest=None),
    _answer(digest=12),
    _answer(base_policy="a policy"),
    _answer(base_policy={}),
    _answer(base_policy={}, digest=bp.policy_digest({})),
    _answer(None, reason=None),
    _answer(None, reason="  "),
])
def test_an_answer_that_is_not_one_changes_nothing(answer):
    for before in (None, _answer(), _answer(None)):
        store = _store()
        if before is not None:
            store.accept(before)
        was = store.current()
        assert store.accept(answer) is False
        assert store.current() == was


def test_a_base_the_engine_will_not_deliver_is_forgotten(cache):
    store = _store(cache)
    store.accept(_answer())
    store.invalidate()
    assert store.current() == (bp.UNKNOWN, None)
    assert not os.path.exists(cache)
    assert _store(cache).current() == (bp.UNKNOWN, None)
    store.invalidate()  # twice is harmless


# ---------------------------------------------------------------------------
# The copy on disk
# ---------------------------------------------------------------------------


def test_a_restarted_sidecar_has_the_policy_before_the_engine_answers(cache):
    _store(cache).accept(_answer())
    again = _store(cache)
    assert again.current() == (bp.HAVE, POLICY)
    assert again.digest == bp.policy_digest(POLICY)


def test_being_told_there_is_none_is_kept_too(cache):
    _store(cache).accept(_answer(None))
    assert _store(cache).current() == (bp.NONE, None)


def test_the_copy_holds_the_policy_its_digest_and_its_bundle(cache):
    _store(cache).accept(_answer())
    with open(cache, encoding="utf-8") as fh:
        document = json.load(fh)
    assert document == {"version": 1, "gateway_id": "gw-a", "state": "have",
                        "digest": bp.policy_digest(POLICY), "base_policy": POLICY,
                        "bundle": BUNDLE}
    assert not os.path.exists(cache + ".new")


def _rewrite(cache, change):
    with open(cache, encoding="utf-8") as fh:
        document = json.load(fh)
    change(document)
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump(document, fh)


def _widen(document):
    document["base_policy"]["networkPolicies"]["artzain"]["endpoints"].append(
        {"host": "anywhere.example", "port": 443})


@pytest.mark.parametrize("change", [
    _widen,
    lambda d: d.__setitem__("digest", "0" * 64),
    lambda d: d.__setitem__("digest", None),
    lambda d: d.__setitem__("base_policy", {}),
    lambda d: d.__setitem__("base_policy", "a policy"),
    lambda d: d.__setitem__("gateway_id", "gw-other"),
    lambda d: d.__setitem__("version", 2),
    lambda d: d.__setitem__("state", "maybe"),
    lambda d: d.pop("state"),
])
def test_a_copy_that_was_changed_is_not_a_policy(cache, change):
    _store(cache).accept(_answer())
    _rewrite(cache, change)
    assert _store(cache).current() == (bp.UNKNOWN, None)


@pytest.mark.parametrize("content", [b"not json", b"[]", b"\xff\xfe", b""])
def test_a_copy_that_cannot_be_read_is_not_a_policy(cache, content):
    os.makedirs(os.path.dirname(cache))
    with open(cache, "wb") as fh:
        fh.write(content)
    store = _store(cache)
    assert store.current() == (bp.UNKNOWN, None)
    assert store.accept(_answer()) is True  # and the next answer replaces it
    assert _store(cache).current() == (bp.HAVE, POLICY)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_copy_and_its_folder_are_the_owners_alone(cache):
    previous = os.umask(0)
    try:
        store = _store(cache)
        store.accept(_answer())
        store.accept(_answer(None))
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(cache).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(cache)).st_mode) == 0o700


def test_a_copy_that_cannot_be_written_costs_only_the_restart(tmp_path, caplog):
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    store = _store(str(blocker / "base-policy.json"))
    with caplog.at_level("WARNING", logger="artzain.openshell.base_policy"):
        assert store.accept(_answer()) is True
        assert store.accept(_answer(None)) is True
    assert store.current() == (bp.NONE, None)
    assert len([r for r in caplog.records if "not written" in r.getMessage()]) == 1


def test_the_same_answer_again_is_not_written_again(cache):
    store = _store(cache)
    store.accept(_answer())
    stamp = os.stat(cache).st_mtime_ns
    os.utime(cache, ns=(stamp - 10**9, stamp - 10**9))
    store.accept(_answer())
    assert os.stat(cache).st_mtime_ns == stamp - 10**9


# ---------------------------------------------------------------------------
# The rule: a create with no policy needs the base policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phase", ["modify_operation", "validate"])
def test_a_create_with_no_policy_is_refused_while_the_base_is_unknown(phase):
    def never(_payload):
        raise AssertionError("refused before any decision")

    empty = {**CREATE, "spec": {"command": ["sleep"], "policy": {}}}
    for body in (CREATE, empty, {"name": "s1"}, {"name": "s1", "spec": None}):
        out = osi.evaluate(_call(phase, body), decide=never, base_required=True)
        assert out["allowed"] is False and out["status_code"] == 503, body
        assert out["reason"] == "base policy unavailable", body


@pytest.mark.parametrize("phase", ["modify_operation", "validate"])
def test_a_create_that_brings_its_own_policy_is_decided(phase):
    engine = _Engine()
    body = {**CREATE, "spec": {"command": ["sleep"], "policy": OWN_POLICY}}
    out = osi.evaluate(_call(phase, body), decide=engine, base_required=True)
    assert out["allowed"] is True and len(engine.requests) == 1
    assert not any(patch["path"].startswith("/spec") for patch in out.get("patches") or [])


def test_a_create_with_no_policy_gets_the_base_once_it_is_known():
    engine = _Engine()
    out = osi.evaluate(_call("modify_operation", CREATE), decide=engine, base_policy=POLICY,
                       base_required=True)
    assert out["allowed"] is True and len(engine.requests) == 1
    assert out["patches"][0] == {"op": "add", "path": "/spec/policy", "value": POLICY}


def test_without_the_rule_a_create_is_decided_as_before():
    engine = _Engine()
    out = osi.evaluate(_call("modify_operation", CREATE), decide=engine)
    assert out["allowed"] is True and len(engine.requests) == 1
    assert [patch["path"] for patch in out["patches"]] == ["/annotations"]


@pytest.mark.parametrize("method, body", [
    ("UpdateConfig", {"sandbox": "s1", "mergeOperations": [{"addRule": {"ruleName": "r"}}]}),
    ("DeleteSandbox", {"name": "s1"}),
])
def test_the_rule_is_about_creates_only(method, body):
    engine = _Engine()
    for phase in ("modify_operation", "validate"):
        out = osi.evaluate(_call(phase, body, method), decide=engine, base_required=True)
        assert out["allowed"] is True, (method, phase, out)


# ---------------------------------------------------------------------------
# The sidecar holds the store
# ---------------------------------------------------------------------------


def test_a_sidecar_on_an_account_key_has_no_store_and_decides_as_before():
    engine = _Engine()
    out = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=engine)
    assert out["allowed"] is True and len(engine.requests) == 1
    assert [patch["path"] for patch in out["patches"]] == ["/annotations"]


def test_a_connected_sidecar_refuses_until_it_is_told_then_applies(monkeypatch):
    store = _store()
    monkeypatch.setattr(sidecar, "_BASE", store)
    engine = _Engine()

    refused = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=engine)
    assert refused["allowed"] is False and refused["reason"] == "base policy unavailable"
    assert engine.requests == []

    store.accept(_answer())
    applied = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=engine)
    assert applied["allowed"] is True
    assert applied["patches"][0] == {"op": "add", "path": "/spec/policy", "value": POLICY}

    store.accept(_answer(None))
    plain = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=engine)
    assert plain["allowed"] is True
    assert [patch["path"] for patch in plain["patches"]] == ["/annotations"]

    store.invalidate()
    again = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=engine)
    assert again["allowed"] is False and len(engine.requests) == 2


def test_a_policy_passed_in_is_used_in_place_of_the_stores(monkeypatch):
    monkeypatch.setattr(sidecar, "_BASE", _store())
    out = sidecar.handle_evaluate(_call("modify_operation", CREATE), decide=_Engine(),
                                  base_policy=OWN_POLICY)
    assert out["patches"][0]["value"] == OWN_POLICY


# ---------------------------------------------------------------------------
# Fetching it
# ---------------------------------------------------------------------------


def _http_error(code):
    return urllib.error.HTTPError("https://engine.example/x", code, "refused", {}, io.BytesIO(b""))


def test_a_fetched_policy_goes_into_the_store():
    store = _store()
    answer = sidecar.refresh_base_policy(store, lambda: _answer())
    assert answer["digest"] == bp.policy_digest(POLICY)
    assert store.current() == (bp.HAVE, POLICY)


def test_an_engine_that_cannot_be_reached_leaves_the_store_as_it_was():
    store = _store()
    store.accept(_answer())

    def down():
        raise TimeoutError("slow")

    for fetch in (down, lambda: (_ for _ in ()).throw(_http_error(503)),
                  lambda: (_ for _ in ()).throw(_http_error(401)),
                  lambda: _answer(digest="0" * 64)):
        assert sidecar.refresh_base_policy(store, fetch) is None
        assert store.current() == (bp.HAVE, POLICY)


def test_a_base_the_engine_refuses_to_deliver_is_dropped():
    """409: the active bundle's base is not within its boundary. What the
    sidecar holds is an earlier bundle's."""
    store = _store()
    store.accept(_answer())
    assert sidecar.refresh_base_policy(store, lambda: (_ for _ in ()).throw(_http_error(409))) is None
    assert store.current() == (bp.UNKNOWN, None)


def test_the_fetch_asks_for_this_gateways_base_policy(monkeypatch):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example/api/v1/decisions")
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw_01ABC/..")
    seen = {}

    def get(target, key, *, timeout):
        seen.update(target=target, key=key, timeout=timeout)
        return {"ok": True}

    monkeypatch.setattr(sidecar, "_get_engine", get)
    assert sidecar.fetch_base_policy() == {"ok": True}
    assert seen == {
        "target": "https://engine.example/api/v1/openshell/gateways/gw_01ABC%2F../base-policy",
        "key": "cnxg_sidecar_test_credential", "timeout": 10.0}
    monkeypatch.delenv("ARTZAIN_DECISION_URL")
    with pytest.raises(RuntimeError):
        sidecar.fetch_base_policy()


def test_the_engine_is_read_with_a_get_inside_the_deadline(monkeypatch):
    from artzain import cloud

    seen = {}

    class Answer:
        def __init__(self):
            self.chunks = [b'{"gateway_id": "gw-a"}', b""]

        def read(self, _size):
            return self.chunks.pop(0)

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    class Opener:
        def open(self, request, timeout):
            seen.update(method=request.get_method(), url=request.full_url, timeout=timeout,
                        body=request.data, accept=request.get_header("Accept"))
            return Answer()

    monkeypatch.setattr(cloud, "_api_opener", lambda: Opener())
    assert sidecar._get_engine("https://engine.example/x", "k", timeout=10.0) == {
        "gateway_id": "gw-a"}
    assert seen == {"method": "GET", "url": "https://engine.example/x", "timeout": 10.0,
                    "body": None, "accept": "application/json"}


# ---------------------------------------------------------------------------
# The reporter keeps it fresh
# ---------------------------------------------------------------------------


class _Wire:
    def __init__(self):
        self.now = 1000.0
        self.calls = []
        self.answer = _answer()

    def clock(self):
        return self.now

    def post(self, path, _payload):
        self.calls.append(path.rsplit("/", 1)[-1])
        return {}

    def fetch(self):
        self.calls.append("base-policy")
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _reporter(wire, store):
    return sidecar.Reporter(GatewayLedger(gateway_id="gw-a"), post=wire.post, clock=wire.clock,
                            latency=sidecar.LatencyWindow(), undelivered=sidecar.Counter(),
                            base=store, fetch_base=wire.fetch)


def test_the_base_policy_is_fetched_first_and_every_five_minutes():
    wire, store = _Wire(), _store()
    reporter = _reporter(wire, store)
    reporter.step()
    assert wire.calls == ["base-policy", "heartbeat", "inventory"]
    assert store.current()[0] == bp.HAVE
    for second in range(1, 601):
        wire.now = 1000.0 + second
        reporter.step()
    assert wire.calls.count("base-policy") == 3  # at 0, 300, 600


def test_a_fetch_that_fails_is_tried_again_at_its_next_turn():
    wire, store = _Wire(), _store()
    wire.answer = TimeoutError("slow")
    reporter = _reporter(wire, store)
    assert reporter.step() == 60.0
    wire.now += 60
    reporter.step()
    assert wire.calls.count("base-policy") == 1 and store.current()[0] == bp.UNKNOWN
    wire.answer = _answer()
    wire.now += 240
    reporter.step()
    assert wire.calls.count("base-policy") == 2 and store.current()[0] == bp.HAVE


def test_the_engine_may_ask_for_another_refresh_interval():
    wire, store = _Wire(), _store()
    wire.answer = _answer(refresh_seconds=30)
    reporter = _reporter(wire, store)
    assert reporter.step() == 30.0  # the refresh is what is due first
    wire.now += 30
    reporter.step()
    assert wire.calls.count("base-policy") == 2
    assert wire.calls.count("heartbeat") == 1


def test_a_reporter_with_no_store_fetches_nothing():
    wire = _Wire()
    reporter = sidecar.Reporter(GatewayLedger(gateway_id="gw-a"), post=wire.post,
                                clock=wire.clock, latency=sidecar.LatencyWindow(),
                                undelivered=sidecar.Counter(), fetch_base=wire.fetch)
    reporter.step()
    assert wire.calls == ["heartbeat", "inventory"]


def test_only_a_sidecar_with_a_gateway_credential_gets_a_store(monkeypatch, cache):
    ledger = GatewayLedger(gateway_id="gw-a")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_an_account_key")
    assert sidecar.reporter_for_environment(ledger) is None and sidecar._BASE is None

    _store(cache).accept(_answer())
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setenv("OPENSHELL_SIDECAR_BASE_POLICY", cache)
    reporter = sidecar.reporter_for_environment(ledger)
    assert isinstance(reporter, sidecar.Reporter)
    assert sidecar._BASE.current() == (bp.HAVE, POLICY)  # read back from the copy
    assert reporter._base is sidecar._BASE
