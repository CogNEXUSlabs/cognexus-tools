"""The OpenShell sidecar in ``artzain.openshell``.

The rules (``interceptor``) and the process (``sidecar``) moved here from the
engine so a customer can install them with ``pip install artzain``. These
tests carry the engine's coverage over: the fail-closed ``validate``, the
global-policy deny, the base patch, ``post_commit``, the OCSF classification,
the gateway identity and request ids, and the engine deadline and reset
retry, the last against a real loopback server. They add what changed with
the move: the SDK's no-redirect opener, and a refusal of any engine URL that
is not ``http`` or ``https``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from artzain import cloud
from artzain.openshell import interceptor as osi
from artzain.openshell import sidecar

UPDATE = {
    "method": "openshell.v1.OpenShell/UpdateConfig",
    "phase": "validate",
    "body": {"sandbox": "sb-1", "mergeOperations": [{"addRule": {"ruleName": "r"}}]},
}
FINDING = {"class": "FINDING", "activity": "PROPOSED", "sandbox_id": "sb-1",
           "policy_hash": "a" * 64}
#: A compiled base policy, in the gateway's protobuf-JSON shape.
BASE = {"version": "1", "networkPolicies": {"artzain": {"name": "artzain"}}}


def _never(_payload):
    raise AssertionError("decide must not run")


@pytest.fixture(autouse=True)
def _sidecar_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.delenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("OPENSHELL_SIDECAR_TOKEN", raising=False)
    monkeypatch.delenv("ARTZAIN_DECISION_URL", raising=False)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_sidecar_test_key")


def _capture():
    seen = []

    def decide(payload):
        seen.append(dict(payload))
        return {"outcome": "allow", "decision_id": "01ABCDEFGHJKMNPQRSTVWXYZ00"}

    return seen, decide


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


def test_validate_allows_only_an_allow():
    def decide(payload):
        assert payload["action"] == "openshell_policy_change"
        assert payload["surface"] == "openshell"
        assert "never-sent" not in payload["payload"]
        assert '"name": "gh"' in payload["payload"]
        return {"outcome": "allow", "decision_id": "01DECIDE", "status_code": 200}

    out = osi.evaluate(
        {"method": "openshell.v1.OpenShell/UpdateConfig", "phase": "validate",
         "gateway_id": "gw", "sandbox_id": "sb",
         "body": {"policy": {"version": "1",
                             "provider": {"api_token": "never-sent", "name": "gh"}}}},
        decide=decide,
    )
    assert out["allowed"] is True
    assert out["log_annotations"]["decision_id"] == "01DECIDE"


def test_review_deny_and_503_are_interceptor_denies():
    review = osi.evaluate(
        {"method": "UpdateConfig", "phase": "validate", "body": {"sandbox": "sb"}},
        decide=lambda _p: {"outcome": "review", "decision_id": "01R", "status_code": 200},
    )
    assert review["allowed"] is False and review["reason"] == "decision review"
    denied = osi.evaluate(
        {"method": "CreateSandbox", "phase": "validate", "body": {}},
        decide=lambda _p: {"outcome": "deny", "status_code": 200},
    )
    assert denied["allowed"] is False and denied["status_code"] == 403
    closed = osi.evaluate(
        {"method": "ApproveDraftChunk", "phase": "validate", "body": {}},
        decide=lambda _p: {"outcome": "deny", "status_code": 503},
    )
    assert closed["allowed"] is False and closed["status_code"] == 503
    unavailable_allow = osi.evaluate(
        {"method": "ApproveDraftChunk", "phase": "validate", "body": {}},
        decide=lambda _p: {"outcome": "allow", "status_code": 503},
    )
    assert unavailable_allow["allowed"] is False
    assert unavailable_allow["status_code"] == 503
    raised = osi.evaluate(
        {"method": "RejectDraftChunk", "phase": "validate", "body": {}},
        decide=lambda _p: (_ for _ in ()).throw(RuntimeError("down")),
    )
    assert raised["allowed"] is False and raised["status_code"] == 503


def test_an_unbound_method_is_denied_without_a_decision():
    out = osi.evaluate({"method": "DeleteSandbox", "phase": "validate", "body": {}},
                       decide=_never)
    assert out["allowed"] is False
    assert "not an interceptable binding" in out["reason"]


def test_global_update_is_denied_before_decide():
    out = osi.evaluate(
        {"method": "UpdateConfig", "phase": "validate", "body": {"global": True}},
        decide=_never,
    )
    assert out["allowed"] is False
    assert "global" in out["reason"]


def test_modify_applies_the_compiled_base_only_when_the_request_omits_policy():
    applied = osi.evaluate(
        {"method": "CreateSandbox", "phase": "modify_operation", "body": {"name": "new"}},
        decide=_never, base_policy=BASE,
    )
    assert applied["allowed"] is True
    assert applied["patches"] == [{"op": "add", "path": "/spec", "value": {"policy": BASE}}]
    into_spec = osi.evaluate(
        {"method": "CreateSandbox", "phase": "modify_operation",
         "body": {"spec": {"command": ["sleep"]}}},
        decide=_never, base_policy=BASE,
    )
    assert into_spec["patches"] == [{"op": "add", "path": "/spec/policy", "value": BASE}]
    kept = osi.evaluate(
        {"method": "CreateSandbox", "phase": "modify_operation",
         "body": {"spec": {"policy": {"version": "1"}}}},
        decide=_never, base_policy=BASE,
    )
    assert kept["patches"] == []
    without_base = osi.evaluate(
        {"method": "CreateSandbox", "phase": "modify_operation", "body": {"name": "new"}},
        decide=_never,
    )
    assert without_base["allowed"] is True and without_base["patches"] == []


def test_the_patch_never_replaces_an_operators_policy():
    assert osi._create_patches({"spec": {"policy": {"version": "7"}}}, BASE) == []


def test_post_commit_does_not_seal_again():
    out = osi.evaluate(
        {"method": "UpdateConfig", "phase": "post_commit", "decision_id": "01LEAF",
         "body": {"policy_hash": "abc123"}},
        decide=_never,
    )
    assert out["allowed"] is True
    assert out["log_annotations"] == {"policy_hash": "abc123", "decision_id": "01LEAF"}


def test_fetch_failure_fails_closed():
    def fetch(_sandbox_id):
        raise OSError("down")

    out = osi.evaluate(
        {"method": "UpdateConfig", "phase": "validate", "sandbox_id": "sb", "body": {}},
        decide=lambda _p: {"outcome": "allow", "status_code": 200},
        fetch_policy=fetch,
    )
    assert out["allowed"] is False and out["status_code"] == 503


def test_ocsf_seals_findings_and_ignores_allows():
    sealed = osi.classify_ocsf({
        "class_uid": 2004, "activity": "APPROVED",
        "sandbox_id": "sb", "policy_hash": "abc",
    })
    assert sealed["disposition"] == "seal"
    assert sealed["decision"]["target"] == "openshell:sb:abc"
    correlate = osi.classify_ocsf({
        "class": "CONFIG", "activity": "LOADED", "decision_id": "01LEAF",
        "sandbox_id": "sb", "policy_hash": "abc",
    })
    assert correlate["disposition"] == "correlate"
    assert correlate["decision_id"] == "01LEAF"
    assert osi.classify_ocsf({"class": "NET", "activity": "ALLOWED"})["disposition"] == "ignore"
    summary = osi.classify_ocsf({
        "class": "HTTP", "activity": "DENIED",
        "url": "https://example.test/path?token=secret",
        "binary": "/usr/bin/curl", "reason": "not listed",
    })
    assert summary["disposition"] == "summarize"
    assert "token" not in summary["summary"]["host"]
    assert "?" not in summary["summary"]["host"]


# ---------------------------------------------------------------------------
# Identity: the configured gateway, never the request's
# ---------------------------------------------------------------------------


def test_evaluate_targets_the_gateway_the_inventory_names():
    seen, decide = _capture()
    sidecar.handle_evaluate(dict(UPDATE), decide=decide)
    inventory = sidecar.sdk_inventory()
    assert inventory["gateway_id"] == "gw-a"
    assert seen[0]["target"].startswith(f"openshell:{inventory['gateway_id']}:")
    assert seen[0]["agent_did"] == "openshell:gw-a"


def test_a_request_cannot_choose_its_gateway_or_agent():
    seen, decide = _capture()
    sidecar.handle_evaluate({**UPDATE, "gateway_id": "gw-other",
                             "agent_did": "openshell:gw-other"}, decide=decide)
    assert seen[0]["target"] == "openshell:gw-a:sb-1"
    assert seen[0]["agent_did"] == "openshell:gw-a"


def test_an_ocsf_seal_decides_as_the_gateway():
    seen, decide = _capture()
    out = sidecar.handle_ocsf(dict(FINDING), decide=decide)
    assert out["sealed"] is True
    assert seen[0]["agent_did"] == "openshell:gw-a"
    assert seen[0]["request_id"]


def test_an_operation_without_a_request_id_gets_one():
    seen, decide = _capture()
    sidecar.handle_evaluate(dict(UPDATE), decide=decide)
    sidecar.handle_evaluate(dict(UPDATE), decide=decide)
    first, second = seen[0]["request_id"], seen[1]["request_id"]
    assert first and second and first != second


def test_the_operations_own_request_id_is_kept():
    # The gateway sends protobuf-JSON: the operation's id arrives as requestId.
    seen, decide = _capture()
    rid = str(uuid.uuid4())
    body = {**UPDATE["body"], "requestId": rid}
    sidecar.handle_evaluate({**UPDATE, "body": body}, decide=decide)
    sidecar.handle_evaluate({**UPDATE, "body": dict(body)}, decide=decide)
    assert seen[0]["request_id"] == rid
    assert seen[1]["request_id"] == rid


def test_post_commit_reports_the_projection(monkeypatch):
    reports = []
    monkeypatch.setattr(sidecar, "http_report_projection",
                        lambda payload: reports.append(dict(payload)) or True)
    out = sidecar.handle_evaluate(
        {"method": "UpdateConfig", "phase": "post_commit",
         "sandbox_id": "sb1", "decision_id": "01LEAFABCDEFGHIJKLMNOPQRST",
         "body": {"policy_hash": "abc123"}},
        decide=_never,
    )
    assert out["allowed"] is True
    assert reports == [{
        "sandbox_id": "sb1",
        "policy_hash": "abc123",
        "decision_id": "01LEAFABCDEFGHIJKLMNOPQRST",
        "method": "UpdateConfig",
    }]


def test_a_failed_projection_report_still_allows(monkeypatch):
    monkeypatch.setattr(
        sidecar, "http_report_projection",
        lambda payload: (_ for _ in ()).throw(RuntimeError("down")))
    out = sidecar.handle_evaluate(
        {"method": "CreateSandbox", "phase": "post_commit",
         "sandbox_id": "sb1", "decision_id": "01LEAFABCDEFGHIJKLMNOPQRST",
         "body": {"policy_hash": "hash"}},
        decide=_never,
    )
    assert out["allowed"] is True


# ---------------------------------------------------------------------------
# The engine call, against a real loopback server
# ---------------------------------------------------------------------------


class _Engine:
    """A fake Decision API. ``script`` is a list of per-request behaviours:
    ``"allow"`` answers at once, ``("sleep", s)`` answers allow after *s*
    seconds, ``"error"`` answers HTTP 500, ``"redirect"`` answers 302 to
    another path, and ``"drop"`` reads the request and closes the connection
    without answering (the client sees a reset)."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        engine = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return None

            def _allow(self):
                raw = json.dumps({"outcome": "allow",
                                  "decision_id": "01ABCDEFGHJKMNPQRSTVWXYZ00"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):  # noqa: N802 - a followed 302 arrives as GET
                engine.requests.append({"path": self.path, "body": None,
                                        "key": self.headers.get("X-Api-Key")})
                self._allow()

            def do_POST(self):  # noqa: N802 - stdlib hook
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                engine.requests.append({"path": self.path, "body": body,
                                        "key": self.headers.get("X-Api-Key")})
                step = engine.script.pop(0) if engine.script else "allow"
                if step == "drop":
                    self.close_connection = True
                    return
                if step == "error":
                    self.send_error(500)
                    return
                if step == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if isinstance(step, tuple) and step[0] == "sleep":
                    time.sleep(step[1])
                raw = json.dumps({"outcome": "allow",
                                  "decision_id": "01ABCDEFGHJKMNPQRSTVWXYZ00"}).encode()
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except OSError:
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def engine(monkeypatch):
    made = []
    # A proxy in the developer's environment must not carry loopback traffic.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")

    def start(script):
        eng = _Engine(script)
        made.append(eng)
        monkeypatch.setenv("ARTZAIN_DECISION_URL", eng.url)
        return eng

    yield start
    for eng in made:
        eng.close()


def test_the_decision_goes_to_the_engine_with_the_key(engine):
    eng = engine(["allow"])
    result = sidecar.handle_evaluate(dict(UPDATE))
    assert result["allowed"] is True
    assert eng.requests[0]["path"] == "/api/v1/decisions"
    assert eng.requests[0]["key"] == "cnx_sidecar_test_key"


def test_a_slow_engine_is_denied_before_the_gateway_timeout(engine, monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", "300")
    sidecar.warm()  # as main() does before serving
    eng = engine([("sleep", 2.0)])
    started = time.monotonic()
    result = sidecar.handle_evaluate(dict(UPDATE))
    elapsed = time.monotonic() - started
    assert result["allowed"] is False
    assert result["status_code"] == 503
    assert elapsed < 1.0, elapsed  # the registration's timeout is 1500 ms
    assert len(eng.requests) == 1  # a timeout is not retried


def test_the_deadline_covers_building_the_opener(engine, monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", "300")
    eng = engine(["allow"])
    real = cloud._api_opener

    def slow_opener():
        time.sleep(0.5)
        return real()

    monkeypatch.setattr(cloud, "_api_opener", slow_opener)
    started = time.monotonic()
    result = sidecar.handle_evaluate(dict(UPDATE))
    elapsed = time.monotonic() - started
    assert result["allowed"] is False
    assert result["status_code"] == 503
    assert elapsed < 0.9, elapsed
    assert eng.requests == []


def test_the_sidecar_warms_its_opener_before_serving(monkeypatch):
    order = []

    class _Server:
        def __init__(self, address, handler):
            order.append("bind")

        def serve_forever(self):
            order.append("serve")

    monkeypatch.setattr(sidecar, "warm", lambda: order.append("warm"))
    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", _Server)
    sidecar.main()
    assert order == ["warm", "bind", "serve"]


def test_the_default_deadline_stays_under_the_registration_timeout():
    assert 0 < sidecar.decide_timeout_seconds() < 1.5


@pytest.mark.parametrize("raw", ["", "abc", "-5", "0"])
def test_an_unusable_deadline_setting_falls_back_to_the_default(monkeypatch, raw):
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", raw)
    assert sidecar.decide_timeout_seconds() == sidecar.DECIDE_TIMEOUT_MS_DEFAULT / 1000


def test_a_deadline_setting_is_bounded(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", "999999")
    assert sidecar.decide_timeout_seconds() == 30.0
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", "1")
    assert sidecar.decide_timeout_seconds() == 0.05


def test_a_reset_connection_is_retried_once_with_the_same_request_id(engine):
    eng = engine(["drop", "allow"])
    result = sidecar.handle_evaluate(dict(UPDATE))
    assert result["allowed"] is True
    assert len(eng.requests) == 2
    first, second = (r["body"]["request_id"] for r in eng.requests)
    assert first and first == second


def test_a_second_reset_is_not_retried(engine):
    eng = engine(["drop", "drop", "allow"])
    result = sidecar.handle_evaluate(dict(UPDATE))
    assert result["allowed"] is False
    assert result["status_code"] == 503
    assert len(eng.requests) == 2


def test_an_error_answer_is_not_retried(engine):
    eng = engine(["error", "allow"])
    result = sidecar.handle_evaluate(dict(UPDATE))
    assert result["allowed"] is False
    assert result["status_code"] == 503
    assert len(eng.requests) == 1


def test_a_redirect_is_not_followed(engine):
    # The target answers allow, to a GET or a POST, so following it would allow.
    eng = engine(["redirect", "allow"])
    result = sidecar.handle_evaluate(dict(UPDATE))
    assert result["allowed"] is False
    assert result["status_code"] == 503
    assert [r["path"] for r in eng.requests] == ["/api/v1/decisions"]


def test_a_reset_is_not_retried_without_a_request_id(engine):
    eng = engine(["drop", "allow"])
    decision = sidecar.http_decide({"agent_did": "openshell:gw-a", "action": "x",
                                    "target": "t", "payload": "{}",
                                    "payload_kind": "external_content",
                                    "request_id": ""})
    assert decision["outcome"] == "deny"
    assert len(eng.requests) == 1


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://engine.example/",
                                 "engine.example", "https://"])
def test_an_engine_url_that_is_not_http_is_a_deny(monkeypatch, url):
    opened = []
    monkeypatch.setattr(cloud, "_api_opener", lambda: opened.append(url))
    monkeypatch.setenv("ARTZAIN_DECISION_URL", url)
    decision = sidecar.http_decide({"request_id": "r1"})
    assert decision == {"outcome": "deny", "status_code": 503, "decision_id": ""}
    assert opened == []  # refused before any request is attempted


@pytest.mark.parametrize("url, expected", [
    ("https://engine.example", "https://engine.example/api/v1/decisions"),
    ("https://engine.example/", "https://engine.example/api/v1/decisions"),
    ("https://engine.example/api/v1/decisions", "https://engine.example/api/v1/decisions"),
])
def test_the_engine_url_takes_an_origin_or_the_decisions_url(monkeypatch, url, expected):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", url)
    assert sidecar._engine_url("/api/v1/decisions") == expected


# ---------------------------------------------------------------------------
# The HTTP routes and the CLI
# ---------------------------------------------------------------------------


def test_the_routes_answer_inventory_and_deny_a_global_update():
    calls = []

    def decide(payload):
        calls.append(payload)
        return {"outcome": "allow", "decision_id": "01", "status_code": 200}

    handler = sidecar.make_handler(lambda: {"gateway_id": "gw", "sandboxes": []}, decide)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}/artzain/inventory") as resp:
            assert json.load(resp)["gateway_id"] == "gw"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/evaluate",
            data=json.dumps({
                "method": "UpdateConfig", "phase": "validate", "body": {"global": True},
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        with opener.open(req) as resp:
            body = json.load(resp)
        assert body["allowed"] is False
        assert calls == []
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_the_routes_need_the_token_when_one_is_set(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", "sidecar-secret")
    handler = sidecar.make_handler(lambda: {"gateway_id": "gw", "sandboxes": []}, _never)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/artzain/inventory"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with pytest.raises(urllib.error.HTTPError) as refused:
            opener.open(url)
        assert refused.value.code == 401
        good = urllib.request.Request(url, headers={"Authorization": "Bearer sidecar-secret"})
        with opener.open(good) as resp:
            assert resp.status == 200
        # The health probe stays open: it says only that the process is up.
        health = url.replace("/artzain/inventory", "/healthz")
        with opener.open(health) as resp:
            assert resp.status == 200
            assert json.load(resp) == {"ok": True}
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_the_cli_names_the_sidecar():
    out = subprocess.run([sys.executable, "-m", "artzain.cli", "openshell", "sidecar", "--help"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "OPENSHELL_GATEWAY_ID" in out.stdout
