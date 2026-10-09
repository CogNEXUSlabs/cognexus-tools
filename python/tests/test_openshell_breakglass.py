"""Break-glass: governed writes the host allows while ArtzAIn cannot decide.

Every governed write fails closed when the engine cannot answer. Break-glass
(plan S5.3, decision D8) lets the gateway's own host user open a window, at
most 240 minutes long, in which such a write is allowed and journaled
instead. The engine seals each journal entry as a flagged receipt when it
can be reached again.

* Only the host opens a window: the sidecar's loopback route, with its own
  token. No engine answer and no gateway call can open one, or make a write
  count as break-glass.
* A window only covers what ArtzAIn could not answer: no answer at all, or a
  5xx. A deny, a review, a rate limit, a refused credential (401, 403) and
  every local refusal still refuse. A gateway-wide write never goes through.
* A write that cannot be journaled is refused: nothing goes through
  unaccounted.
* The window ends on its own, without the engine, and a clock set back
  ends it.
* The journal goes to the engine in order, and leaves the host only when the
  engine has taken it.
"""

from __future__ import annotations

import hashlib
import io
import json
import ssl
import stat
import sys
import threading
import urllib.error

import pytest

from artzain.openshell import breakglass as bg
from artzain.openshell import connect, sidecar
from artzain.openshell import interceptor as osi
from artzain.openshell.breakglass import BreakGlass, Refused
from artzain.openshell.state import GatewayLedger

DECISION = "01ABCDEFGHJKMNPQRSTVWXYZ00"
PRINCIPAL = {"subject": "user-7", "kind": "user", "provider": "oidc",
             "display_name": "Ada Lovelace", "roles": "admin", "scopes": "all"}
UPDATE = {"method": "openshell.v1.OpenShell/UpdateConfig", "phase": "validate",
          "sandbox_id": "sb-1", "principal": PRINCIPAL, "request_id": "req-1",
          "body": {"sandbox": "sb-1", "mergeOperations": [{"addRule": {"ruleName": "r"}}]}}
CREATE_MODIFY = {"method": "openshell.v1.OpenShell/CreateSandbox", "phase": "modify_operation",
                 "principal": PRINCIPAL,
                 "body": {"name": "sb-new", "spec": {"policy": {"version": "1"}}}}
GLOBAL_SETTING = {"method": "openshell.v1.OpenShell/UpdateConfig", "phase": "validate",
                  "principal": PRINCIPAL,
                  "body": {"global": True, "settingKey": "proposal_approval_mode",
                           "settingValue": {"stringValue": "auto"}}}
BASE = {"version": "1", "networkPolicies": {"artzain": {"name": "artzain"}}}


class Clock:
    """Wall and monotonic time the tests move by hand."""

    def __init__(self, wall: float = 1_800_000_000.0) -> None:
        self.wall = wall
        self.mono = 1000.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def glass(tmp_path, clock):
    return BreakGlass(tmp_path / "state", gateway_id="gw-a", clock=clock.time,
                      monotonic=clock.monotonic)


def _down(_payload):
    """What the sidecar's own client says when the engine gave no answer."""
    return osi.mark_engine_down({"outcome": "deny", "status_code": 503, "decision_id": ""})


def _entries(glass, kind=None):
    return [e for e in glass.journal.pending() if kind is None or e["kind"] == kind]


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


def test_a_window_opens_with_its_length_and_reason_and_is_journaled(glass, clock):
    window = glass.open(30, "engine outage, INC-42", opened_by="ops")
    assert window["minutes"] == 30
    assert window["until_ms"] == int(clock.wall * 1000) + 30 * 60_000
    assert window["reason"] == "engine outage, INC-42"
    assert window["opened_by"] == "ops"
    assert glass.window()["id"] == window["id"]
    [opened] = _entries(glass, bg.KIND_OPEN)
    assert opened["body"] == {"window": window["id"], "minutes": 30,
                              "until_ms": window["until_ms"],
                              "reason": "engine outage, INC-42", "opened_by": "ops"}


@pytest.mark.parametrize("minutes", [0, -5, 241, 10_000, "30", 30.5, True, None])
def test_a_window_lasts_one_to_240_whole_minutes(glass, minutes):
    with pytest.raises(Refused) as refused:
        glass.open(minutes, "outage")
    assert refused.value.status == 400
    assert glass.window() is None and not _entries(glass)


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501, "line\nbreak", "tab\there", None, 42])
def test_a_window_needs_a_short_one_line_reason(glass, reason):
    with pytest.raises(Refused) as refused:
        glass.open(30, reason)
    assert refused.value.status == 400
    assert glass.window() is None


def test_240_minutes_is_the_longest_window(glass, clock):
    window = glass.open(bg.MAX_MINUTES, "long outage")
    assert bg.MAX_MINUTES == 240
    assert window["until_ms"] - int(clock.wall * 1000) == 240 * 60_000


def test_one_window_at_a_time(glass):
    glass.open(30, "outage")
    with pytest.raises(Refused) as refused:
        glass.open(60, "again")
    assert refused.value.status == 409
    assert len(_entries(glass, bg.KIND_OPEN)) == 1


def test_the_window_ends_on_its_own_without_the_engine(glass, clock):
    window = glass.open(10, "outage")
    clock.advance(10 * 60 - 1)
    assert glass.window() is not None
    clock.advance(1)
    assert glass.window() is None
    [closed] = _entries(glass, bg.KIND_CLOSE)
    assert closed["body"] == {"window": window["id"], "closed": "expired", "writes": 0}


def test_the_monotonic_clock_ends_the_window_too(glass, clock):
    glass.open(10, "outage")
    clock.mono += 10 * 60  # ten minutes pass; the wall clock is held back
    assert glass.window() is None


def test_a_clock_set_back_ends_the_window(glass, clock):
    window = glass.open(60, "outage")
    clock.wall -= 3600
    assert glass.window() is None
    [closed] = _entries(glass, bg.KIND_CLOSE)
    assert closed["body"]["window"] == window["id"]
    assert closed["body"]["closed"] == "clock"


def test_the_operator_closes_the_window(glass):
    window = glass.open(60, "outage")
    closed = glass.close()
    assert closed["id"] == window["id"]
    assert glass.window() is None
    [entry] = _entries(glass, bg.KIND_CLOSE)
    assert entry["body"] == {"window": window["id"], "closed": "operator", "writes": 0}
    assert glass.close() is None


def test_the_window_and_its_journal_survive_a_restart(tmp_path, glass, clock):
    window = glass.open(60, "outage")
    again = BreakGlass(tmp_path / "state", gateway_id="gw-a", clock=clock.time,
                       monotonic=clock.monotonic)
    assert again.window()["id"] == window["id"]
    assert [e["kind"] for e in again.journal.pending()] == [bg.KIND_OPEN]


@pytest.mark.parametrize("edit", [
    lambda w: w.update(until_ms=w["opened_ms"] + 600 * 60_000, minutes=600),
    lambda w: w.update(until_ms=w["until_ms"] + 60_000),
    lambda w: w.update(opened_ms=w["opened_ms"] + 3_600_000, until_ms=w["until_ms"] + 3_600_000),
    lambda w: w.update(id=""),
    lambda w: w.pop("reason"),
])
def test_a_window_file_that_does_not_hold_is_not_an_open_window(tmp_path, glass, clock, edit):
    glass.open(30, "outage")
    path = tmp_path / "state" / bg.WINDOW_FILE
    document = json.loads(path.read_text(encoding="utf-8"))
    edit(document["window"])
    path.write_text(json.dumps(document), encoding="utf-8")
    again = BreakGlass(tmp_path / "state", gateway_id="gw-a", clock=clock.time,
                       monotonic=clock.monotonic)
    assert again.window() is None


def test_another_gateways_window_file_is_not_read(tmp_path, glass, clock):
    glass.open(30, "outage")
    other = BreakGlass(tmp_path / "state", gateway_id="gw-b", clock=clock.time,
                       monotonic=clock.monotonic)
    assert other.window() is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_the_files_are_the_owners_alone(tmp_path, glass):
    glass.open(30, "outage")
    folder = tmp_path / "state"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    for name in (bg.WINDOW_FILE, bg.JOURNAL_FILE):
        assert stat.S_IMODE((folder / name).stat().st_mode) == 0o600


def test_without_a_journal_file_no_window_opens(clock):
    memory_only = BreakGlass(None, gateway_id="gw-a", clock=clock.time,
                             monotonic=clock.monotonic)
    assert memory_only.enabled is False
    with pytest.raises(Refused) as refused:
        memory_only.open(30, "outage")
    assert refused.value.status == 409


def test_a_window_whose_journal_cannot_be_written_does_not_open(glass, monkeypatch):
    def broken(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr("artzain.openshell.journal.write_private", broken)
    with pytest.raises(Refused) as refused:
        glass.open(30, "outage")
    assert refused.value.status == 503
    assert glass.window() is None and not _entries(glass)


# ---------------------------------------------------------------------------
# Decisions under a window
# ---------------------------------------------------------------------------


def test_an_open_window_allows_what_artzain_could_not_answer_and_journals_it(glass):
    window = glass.open(30, "outage")
    out = osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    assert out["allowed"] is True
    assert out["log_annotations"] == {"break_glass": window["id"]}
    [write] = _entries(glass, bg.KIND_WRITE)
    asked = osi._decision_request(dict(UPDATE), "UpdateConfig", UPDATE["body"])
    assert write["body"] == {
        "window": window["id"],
        "method": "UpdateConfig",
        "action": asked["action"],
        "target": asked["target"],
        "payload_sha256": hashlib.sha256(asked["payload"].encode("utf-8")).hexdigest(),
        "digest": osi._operation_digest(UPDATE["body"]),
        # The subject id, never a name (plan §9).
        "principal": {"subject": "user-7", "kind": "user", "provider": "oidc"},
        "request_id": "req-1",
    }
    assert glass.window()["writes"] == 1


@pytest.mark.parametrize("answer", [
    {"outcome": "deny", "decision_id": DECISION, "status_code": 200},
    {"outcome": "review", "decision_id": DECISION, "status_code": 200},
    {"outcome": "deny", "status_code": 429, "retry_after": 30},
])
def test_an_answer_from_artzain_still_holds_in_a_window(glass, answer):
    glass.open(30, "outage")
    out = osi.evaluate(dict(UPDATE), decide=lambda _p: dict(answer), breakglass=glass)
    assert out["allowed"] is False
    assert not _entries(glass, bg.KIND_WRITE)


def test_a_refused_credential_is_not_an_outage(glass):
    # http_decide turns a 401 or a 403 into this, without the mark.
    glass.open(30, "outage")
    out = osi.evaluate(dict(UPDATE), breakglass=glass,
                       decide=lambda _p: {"outcome": "deny", "status_code": 503, "decision_id": ""})
    assert out["allowed"] is False and out["reason"] == "decision unavailable"
    assert not _entries(glass, bg.KIND_WRITE)


@pytest.mark.parametrize("claim", [
    {"engine_down": True}, {"__engine_down__": True}, {"break_glass": "w"},
    {"_engine_down": "yes"},
])
def test_no_engine_answer_can_claim_an_outage(glass, claim):
    glass.open(30, "outage")
    out = osi.evaluate(dict(UPDATE), breakglass=glass,
                       decide=lambda _p: {"outcome": "deny", "status_code": 503,
                                          "decision_id": "", **claim})
    assert out["allowed"] is False
    assert not _entries(glass, bg.KIND_WRITE)


def test_a_gateway_wide_write_never_goes_through(glass):
    glass.open(30, "outage")
    out = osi.evaluate(dict(GLOBAL_SETTING), decide=_down, breakglass=glass)
    assert out["allowed"] is False
    assert not _entries(glass, bg.KIND_WRITE)


def test_local_refusals_hold_in_a_window(glass):
    glass.open(30, "outage")
    global_policy = {"method": "UpdateConfig", "phase": "validate",
                     "body": {"global": True, "policy": {"version": "1"}}}
    assert osi.evaluate(global_policy, decide=_down, breakglass=glass)["allowed"] is False
    no_policy = {"method": "CreateSandbox", "phase": "validate", "body": {"name": "sb"}}
    refused = osi.evaluate(no_policy, decide=_down, breakglass=glass, base_required=True)
    assert refused["allowed"] is False and refused["reason"] == "base policy unavailable"
    unbound = {"method": "SubmitPolicyAnalysis", "phase": "validate", "body": {}}
    assert osi.evaluate(unbound, decide=_down, breakglass=glass)["allowed"] is False
    assert not _entries(glass, bg.KIND_WRITE)


def test_without_a_window_an_outage_refuses_as_before(glass):
    out = osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    assert out["allowed"] is False and out["status_code"] == 503
    assert not _entries(glass)


def test_an_expired_window_refuses(glass, clock):
    glass.open(5, "outage")
    clock.advance(5 * 60)
    assert osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)["allowed"] is False
    assert not _entries(glass, bg.KIND_WRITE)


def test_a_create_is_journaled_once_in_validate_and_keeps_the_base_policy(glass):
    glass.open(30, "outage")
    ledger = GatewayLedger(gateway_id="gw-a")
    modify = osi.evaluate({**CREATE_MODIFY, "body": {"name": "sb-new"}}, decide=_down,
                          breakglass=glass, base_policy=BASE, ledger=ledger)
    assert modify["allowed"] is True
    # The base policy goes on; no decision stamp, and nothing journaled yet.
    assert modify["patches"] and all(osi.STAMP_KEY not in json.dumps(p) for p in modify["patches"])
    assert not _entries(glass, bg.KIND_WRITE)
    validate = osi.evaluate({**CREATE_MODIFY, "phase": "validate", "body": {"name": "sb-new"}},
                            decide=_down, breakglass=glass, base_policy=BASE, ledger=ledger)
    assert validate["allowed"] is True
    assert len(_entries(glass, bg.KIND_WRITE)) == 1


def test_a_write_that_cannot_be_journaled_is_refused(tmp_path, clock, monkeypatch):
    glass = BreakGlass(tmp_path / "state", gateway_id="gw-a", clock=clock.time,
                       monotonic=clock.monotonic)
    glass.open(30, "outage")

    def broken(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr("artzain.openshell.journal.write_private", broken)
    out = osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    assert out["allowed"] is False
    assert "not journaled" in out["reason"]
    assert not _entries(glass, bg.KIND_WRITE)


def test_a_full_journal_refuses_the_write(tmp_path, clock):
    glass = BreakGlass(tmp_path / "state", gateway_id="gw-a", clock=clock.time,
                       monotonic=clock.monotonic, max_entries=2)
    glass.open(30, "outage")
    assert osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)["allowed"] is True
    out = osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    assert out["allowed"] is False and "not journaled" in out["reason"]


def test_the_sidecar_decides_with_its_window(glass, monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_BREAKGLASS", glass)
    assert sidecar.handle_evaluate(dict(UPDATE), decide=_down)["allowed"] is False
    glass.open(30, "outage")
    out = sidecar.handle_evaluate(dict(UPDATE), decide=_down)
    assert out["allowed"] is True and out["log_annotations"]["break_glass"]
    # The write is journaled as the gateway's, whatever the request said.
    [write] = _entries(glass, bg.KIND_WRITE)
    assert write["body"]["target"].startswith("openshell:gw-a:")


def test_a_break_glass_write_sends_no_projection_report(glass, monkeypatch):
    glass.open(30, "outage")
    monkeypatch.setattr(sidecar, "_BREAKGLASS", glass)
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    sent = []
    monkeypatch.setattr(sidecar, "http_report_projection", lambda p: sent.append(p) or True)
    sidecar.handle_evaluate({"method": "UpdateConfig", "phase": "post_commit",
                             "sandbox_id": "sb-1",
                             "body": {"policyHash": "a" * 64, "annotations": {}}},
                            decide=_down)
    assert sent == []


# ---------------------------------------------------------------------------
# The sidecar's own client marks only a real outage
# ---------------------------------------------------------------------------


@pytest.fixture
def engine_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    monkeypatch.setattr(sidecar, "_CLIENT", None)


def _http_error(code):
    return urllib.error.HTTPError("https://engine.example/api/v1/decisions", code, "x",
                                  {}, io.BytesIO(b"{}"))


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("refused"), TimeoutError("slow"), ConnectionResetError("reset"),
    _http_error(500), _http_error(502), _http_error(503), _http_error(504), _http_error(522),
])
def test_no_answer_or_a_5xx_is_an_outage(engine_env, monkeypatch, failure):
    def post(*_a, **_k):
        raise failure

    monkeypatch.setattr(sidecar, "_post_engine", post)
    answer = sidecar.http_decide({"request_id": "r"})
    assert answer["outcome"] == "deny" and answer["status_code"] == 503
    assert osi.engine_down(answer) is True


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 413, 422, 301, 302])
def test_a_refusal_or_a_redirect_is_not_an_outage(engine_env, monkeypatch, code):
    def post(*_a, **_k):
        raise _http_error(code)

    monkeypatch.setattr(sidecar, "_post_engine", post)
    answer = sidecar.http_decide({"request_id": "r"})
    assert answer["outcome"] == "deny"
    assert osi.engine_down(answer) is False


@pytest.mark.parametrize("failure", [
    ssl.SSLCertVerificationError("certificate verify failed"),
    urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed")),
])
def test_a_certificate_that_does_not_verify_is_not_an_outage(engine_env, monkeypatch, failure):
    def post(*_a, **_k):
        raise failure

    monkeypatch.setattr(sidecar, "_post_engine", post)
    assert osi.engine_down(sidecar.http_decide({"request_id": "r"})) is False


def test_an_answer_the_engine_gave_is_never_an_outage(engine_env, monkeypatch):
    monkeypatch.setattr(sidecar, "_post_engine", lambda *_a, **_k: {
        "outcome": "deny", "status_code": 503, "__engine_down__": True, "engine_down": True})
    assert osi.engine_down(sidecar.http_decide({"request_id": "r"})) is False


def test_an_unset_engine_is_not_an_outage(monkeypatch):
    monkeypatch.delenv("ARTZAIN_DECISION_URL", raising=False)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    assert osi.engine_down(sidecar.http_decide({"request_id": "r"})) is False


# ---------------------------------------------------------------------------
# The sidecar's loopback routes
# ---------------------------------------------------------------------------


@pytest.fixture
def routes(glass, monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", "local-token")
    monkeypatch.setattr(sidecar, "_BREAKGLASS", glass)
    from http.server import ThreadingHTTPServer

    handler = sidecar.make_handler(lambda: {"sandboxes": []}, _down)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _call(port, method, path, body=None, token="local-token"):
    import urllib.request

    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def test_the_host_opens_reads_and_closes_a_window_over_loopback(routes, glass):
    status, opened = _call(routes, "POST", "/artzain/break-glass",
                           {"minutes": 45, "reason": "engine outage", "opened_by": "ops"})
    assert status == 200 and opened["window"]["minutes"] == 45
    status, state = _call(routes, "GET", "/artzain/break-glass")
    assert status == 200
    assert state["window"]["id"] == opened["window"]["id"] and state["pending"] == 1
    status, closed = _call(routes, "POST", "/artzain/break-glass/close", {})
    assert status == 200 and closed["closed"]["id"] == opened["window"]["id"]
    assert glass.window() is None


def test_the_routes_refuse_a_caller_without_the_token(routes, glass):
    for method, path, body in (("GET", "/artzain/break-glass", None),
                               ("POST", "/artzain/break-glass", {"minutes": 5, "reason": "x"}),
                               ("POST", "/artzain/break-glass/close", {})):
        assert _call(routes, method, path, body, token="")[0] == 401
        assert _call(routes, method, path, body, token="wrong")[0] == 401
    assert glass.window() is None


def test_a_refused_caller_reads_its_401_whatever_it_sent(routes):
    # Answered over a body it never read, the sidecar's refusal could reach
    # the caller as a reset connection instead.
    for _ in range(5):
        status, answer = _call(routes, "POST", "/v1/evaluate", {"filler": "x" * 200_000},
                               token="wrong")
        assert status == 401 and answer["reason"] == "sidecar token rejected"


def test_a_sidecar_without_a_token_opens_no_window(routes, glass, monkeypatch):
    # An account-key sidecar's loopback port is open; break-glass is not.
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_account_key")
    monkeypatch.delenv("OPENSHELL_SIDECAR_TOKEN")
    status, answer = _call(routes, "POST", "/artzain/break-glass",
                           {"minutes": 5, "reason": "x"}, token="")
    assert status == 403 and "OPENSHELL_SIDECAR_TOKEN" in answer["reason"]
    assert glass.window() is None


def test_a_bad_window_request_is_a_400(routes, glass):
    status, answer = _call(routes, "POST", "/artzain/break-glass", {"minutes": 999, "reason": "x"})
    assert status == 400 and answer["reason"]
    assert glass.window() is None


def test_the_gateways_socket_has_no_way_to_open_a_window():
    from artzain.openshell import servicer

    assert not [name for name in dir(servicer) if "break" in name.lower() or "glass" in name.lower()]


# ---------------------------------------------------------------------------
# The journal goes to the engine
# ---------------------------------------------------------------------------


@pytest.fixture
def upload_env(glass, monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    monkeypatch.setattr(sidecar, "_BREAKGLASS", glass)
    monkeypatch.setattr(sidecar, "_CLIENT", None)
    return glass


def test_the_journal_goes_to_the_engine_in_order(upload_env, monkeypatch):
    glass = upload_env
    glass.open(30, "outage")
    osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    glass.close()
    sent = []

    def post(target, key, payload, **_k):
        sent.append((target, payload))
        return {"accepted_seq": payload["entries"][-1]["seq"]}

    monkeypatch.setattr(sidecar, "_post_engine", post)
    assert sidecar.deliver_breakglass() == 3
    [(target, payload)] = sent
    assert target == "https://engine.example/api/v1/openshell/gateways/gw-a/break-glass"
    assert [e["kind"] for e in payload["entries"]] == [bg.KIND_OPEN, bg.KIND_WRITE, bg.KIND_CLOSE]
    assert payload["base"] == {"seq": 0, "hash": "0" * 64}
    assert glass.journal.pending() == []
    assert glass.journal.base == (3, payload["entries"][-1]["hash"])


def test_only_what_the_engine_took_leaves_the_host(upload_env, monkeypatch):
    glass = upload_env
    glass.open(30, "outage")
    osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    monkeypatch.setattr(sidecar, "_post_engine", lambda *_a, **_k: {"accepted_seq": 1})
    assert sidecar.deliver_breakglass() == 1
    assert [e["seq"] for e in glass.journal.pending()] == [2]


@pytest.mark.parametrize("code", [404, 409, 500, 503])
def test_a_refused_upload_keeps_the_journal(upload_env, monkeypatch, code):
    glass = upload_env
    glass.open(30, "outage")

    def post(*_a, **_k):
        raise _http_error(code)

    monkeypatch.setattr(sidecar, "_post_engine", post)
    assert sidecar.deliver_breakglass() == 0
    assert len(glass.journal.pending()) == 1


@pytest.mark.parametrize("answer", [{}, {"accepted_seq": "1"}, {"accepted_seq": 99}, [], None])
def test_an_answer_that_names_nothing_sent_settles_nothing(upload_env, monkeypatch, answer):
    glass = upload_env
    glass.open(30, "outage")
    monkeypatch.setattr(sidecar, "_post_engine", lambda *_a, **_k: answer)
    assert sidecar.deliver_breakglass() == 0
    assert len(glass.journal.pending()) == 1


def test_a_long_journal_goes_in_batches(upload_env, monkeypatch):
    glass = upload_env
    glass.open(240, "outage")
    for _ in range(bg.UPLOAD_BATCH + 5):
        osi.evaluate(dict(UPDATE), decide=_down, breakglass=glass)
    sizes = []

    def post(_target, _key, payload, **_k):
        sizes.append(len(payload["entries"]))
        return {"accepted_seq": payload["entries"][-1]["seq"]}

    monkeypatch.setattr(sidecar, "_post_engine", post)
    assert sidecar.deliver_breakglass() == bg.UPLOAD_BATCH + 6
    assert sizes == [bg.UPLOAD_BATCH, 6]


def test_an_account_key_sidecar_uploads_nothing(upload_env, monkeypatch):
    upload_env.open(30, "outage")
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_account_key")
    monkeypatch.setattr(sidecar, "_post_engine",
                        lambda *_a, **_k: pytest.fail("nothing is sent on an account key"))
    assert sidecar.deliver_breakglass() == 0


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


class Posted:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def __call__(self, port, path, body, token):
        self.calls.append((port, path, body, token))
        return self.answer


@pytest.fixture
def cli(monkeypatch, tmp_path):
    record = {"port": 8099}
    monkeypatch.setattr(connect, "_break_glass_target", lambda host: (record["port"], "tok-1"))
    monkeypatch.setattr(connect.getpass, "getuser", lambda: "ops")
    return record


def test_the_command_opens_a_window_through_the_sidecar(cli, monkeypatch):
    posted = Posted({"window": {"id": "w1", "minutes": 30, "until_ms": 1, "reason": "x"}})
    monkeypatch.setattr(connect, "_sidecar_post", posted)
    answer = connect.break_glass(object(), minutes=30, reason="engine outage")
    assert answer["window"]["id"] == "w1"
    assert posted.calls == [(8099, "/artzain/break-glass",
                             {"minutes": 30, "reason": "engine outage", "opened_by": "ops"},
                             "tok-1")]


def test_the_command_closes_a_window(cli, monkeypatch):
    posted = Posted({"closed": {"id": "w1"}})
    monkeypatch.setattr(connect, "_sidecar_post", posted)
    connect.break_glass(object(), close=True)
    assert posted.calls == [(8099, "/artzain/break-glass/close", {}, "tok-1")]


def test_the_command_refuses_a_window_longer_than_240_minutes(cli, monkeypatch):
    monkeypatch.setattr(connect, "_sidecar_post",
                        lambda *_a: pytest.fail("nothing is sent for a refused length"))
    with pytest.raises(connect.ConnectError):
        connect.break_glass(object(), minutes=241, reason="x")
