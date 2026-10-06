"""The sidecar lists its gateway's sandboxes through the ``openshell`` CLI.

``artzain connect openshell`` installs the sidecar beside a gateway whose CLI
the operator has already registered, and points ``OPENSHELL_SIDECAR_LIST_CLI``
at that CLI. Each inventory is then a listing of every workspace
(``openshell sandbox list --all-workspaces -o json``, page by page). So the
engine is told every sandbox, including those made before the connect and
those gone since, not only what the sidecar has seen commit, which it sent
as partial for ever.

What the sidecar reported, and whether the engine took it, is served on the
gated ``GET /artzain/reports``. ``connect`` reads it after its self-test.
"""

from __future__ import annotations

import copy
import json
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from artzain.openshell import sidecar
from artzain.openshell.journal import Journal
from artzain.openshell.state import GatewayLedger

CLI = "/usr/bin/openshell"
S1 = "1e04e83f-6de7-4f86-b466-2e945af3e724"
S2 = "7c9a1d52-0b1e-4c57-9f0e-3a2f6f1f2b10"
S3 = "3b0c3d1e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
POLICY_HASH = "0402e6704bbdf5abf519e4bfbfb526efb467fc40aeebb8e3b74eb8cdc6b69e74"


def _listed(sandbox_id, name, workspace="default", phase="Ready"):
    """One sandbox as ``sandbox list -o json`` prints it (v0.1.2's
    ``sandbox_to_json``), with the fields the sidecar does not read."""
    return {"id": sandbox_id, "name": name, "workspace": workspace,
            "labels": {"team": "a"}, "annotations": {}, "resource_version": 3,
            "created_at": "2026-10-02 10:00:00", "phase": phase,
            "current_policy_version": 2, "exit_code": None, "conditions": [],
            "endpoint_statuses": [],
            "configuration_admission": {"state": "accepted", "error": "",
                                        "policy_version": 2, "policy_hash": "abc",
                                        "config_revision": 1, "provider_env_revision": 0},
            "provisioning": None, "created_from_workload_template": None}


def _page(sandboxes, token=""):
    return json.dumps({"sandboxes": sandboxes, "next_page_token": token}, indent=2).encode()


class _Cli:
    """``subprocess.run`` for the CLI: one answer per call, in order."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, argv, *, env, stdin, capture_output, timeout, check):
        assert stdin == subprocess.DEVNULL and capture_output and not check and timeout > 0
        self.calls.append({"argv": list(argv), "env": dict(env)})
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        code, out = answer if isinstance(answer, tuple) else (0, answer)
        return subprocess.CompletedProcess(argv, code, out, b"")


@pytest.fixture(autouse=True)
def _sidecar_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    for name in ("OPENSHELL_SIDECAR_LIST_WORKSPACES", "OPENSHELL_SIDECAR_LIST_CLI",
                 "OPENSHELL_SIDECAR_STATE", "OPENSHELL_SIDECAR_TOKEN", "ARTZAIN_DECISION_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_LATENCY", sidecar.LatencyWindow())
    monkeypatch.setattr(sidecar, "_UNDELIVERED", sidecar.Counter())
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal())
    monkeypatch.setattr(sidecar, "_CLIENT", None)


def _ledger(*entries, path=None):
    ledger = GatewayLedger(state_path=path, gateway_id="gw-a")
    for workspace, name, sandbox_id in entries:
        ledger.learn_sandbox(workspace, name, sandbox_id)
    return ledger


# ---------------------------------------------------------------------------
# The listing
# ---------------------------------------------------------------------------


def test_a_listing_reads_every_page_of_every_workspace():
    cli = _Cli(_page([_listed(S1, "s1"), _listed(S2, "s2", "staging", "Provisioning")], "t1"),
               _page([_listed(S3, "s3", "ops")]))
    listed = sidecar.cli_list(CLI, run=cli)
    assert listed == [
        {"workspace": "default", "id": S1, "name": "s1", "phase": "Ready"},
        {"workspace": "staging", "id": S2, "name": "s2", "phase": "Provisioning"},
        {"workspace": "ops", "id": S3, "name": "s3", "phase": "Ready"},
    ]
    base = [CLI, "sandbox", "list", "--all-workspaces", "-o", "json", "--page-size", "100"]
    assert [call["argv"] for call in cli.calls] == [base, base + ["--page-token", "t1"]]


def test_the_cli_is_given_no_credential_and_no_colour(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", "sidecar-secret")
    monkeypatch.setenv("HOME", "/home/op")
    cli = _Cli(_page([]))
    assert sidecar.cli_list(CLI, run=cli) == []
    env = cli.calls[0]["env"]
    assert "COGNEXUS_API_KEY" not in env and "OPENSHELL_SIDECAR_TOKEN" not in env
    assert env["NO_COLOR"] == "1" and env["HOME"] == "/home/op"


def test_an_entry_is_read_for_its_four_fields_and_nothing_else():
    odd = _listed(S1, "s1")
    odd.update({"workspace": "", "phase": 7})
    cli = _Cli(_page([odd, {"id": 5, "name": None}, "not an entry"]))
    assert sidecar.cli_list(CLI, run=cli) == [
        {"workspace": "default", "id": S1, "name": "s1", "phase": ""},
        {"workspace": "default", "id": "", "name": "", "phase": ""},
    ]


@pytest.mark.parametrize("answer, raised", [
    ((1, b"Error: tcp connect error"), RuntimeError),
    ((0, b"not json"), ValueError),
    ((0, b"[]"), ValueError),
    ((0, json.dumps({"next_page_token": ""}).encode()), ValueError),
    ((0, json.dumps({"sandboxes": {}, "next_page_token": ""}).encode()), ValueError),
    ((0, json.dumps({"sandboxes": [], "next_page_token": None}).encode()), ValueError),
    (subprocess.TimeoutExpired(CLI, 30), subprocess.TimeoutExpired),
], ids=["exit", "text", "list", "no-sandboxes", "sandboxes-not-a-list", "no-token", "timeout"])
def test_a_listing_that_cannot_be_read_raises(answer, raised):
    with pytest.raises(raised):
        sidecar.cli_list(CLI, run=_Cli(answer))


def test_a_page_from_a_cli_that_failed_is_not_believed():
    """A CLI that exits non-zero has not said what the gateway holds, even
    when what it printed reads as a page."""
    with pytest.raises(RuntimeError, match="exited 1"):
        sidecar.cli_list(CLI, run=_Cli((1, _page([_listed(S1, "s1")]))))


def test_a_listing_that_never_ends_is_given_up():
    cli = _Cli(_page([_listed(S1, "s1")], "again"))
    with pytest.raises(RuntimeError, match="pages"):
        sidecar.cli_list(CLI, run=cli)
    assert len(cli.calls) == sidecar.LIST_MAX_PAGES


def test_a_listing_is_held_to_its_deadline(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(sidecar.time, "monotonic", lambda: now[0])

    def slow(*args, **kwargs):
        now[0] += 20.0
        return _Cli(_page([], "more"))(*args, **kwargs)

    with pytest.raises(TimeoutError):
        sidecar.cli_list(CLI, run=slow, timeout=30.0)


# ---------------------------------------------------------------------------
# The ledger and the snapshot
# ---------------------------------------------------------------------------


def test_a_whole_listing_makes_the_ledger_exactly_what_was_listed(tmp_path):
    path = str(tmp_path / "state.json")
    ledger = _ledger(("default", "s1", S1), ("staging", "s2", S2), ("ops", "s3", S3), path=path)
    ledger.note_policy_hash(S1, POLICY_HASH)
    ledger.note_policy_hash(S2, POLICY_HASH)
    before = ledger.revision
    ledger.replace_all([("default", "s1", S1), ("staging", "s4", S3), ("", "s5", ""),
                        ("x", "", S2)])
    assert ledger.sandboxes() == [
        {"workspace": "default", "name": "s1", "id": S1, "effective_policy_hash": POLICY_HASH},
        {"workspace": "staging", "name": "s4", "id": S3, "effective_policy_hash": ""},
    ]
    assert ledger.policy_hash(S2) == ""  # a gone sandbox's hash goes with it
    assert ledger.revision == before + 1
    ledger.replace_all([("staging", "s4", S3), ("default", "s1", S1)])
    assert ledger.revision == before + 1  # the same sandboxes: no change
    again = GatewayLedger(state_path=path, gateway_id="gw-a")
    assert again.sandboxes() == ledger.sandboxes()


def test_a_listed_sandbox_with_no_workspace_is_in_the_default_one():
    ledger = _ledger()
    ledger.replace_all([("", "s1", S1)])
    assert ledger.sandboxes()[0]["workspace"] == "default"
    assert ledger.sandbox_id("default", "s1") == S1


def test_a_snapshot_through_the_cli_is_whole_and_holds_every_workspace(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)
    asked = []
    monkeypatch.setattr(sidecar, "cli_list", lambda cli: asked.append(cli) or [
        {"workspace": "default", "id": S1, "name": "s1", "phase": "Ready"},
        {"workspace": "staging", "id": S2, "name": "s2", "phase": "Provisioning"}])
    ledger = _ledger(("default", "s1", S1), ("gone", "s9", S3))
    ledger.note_policy_hash(S1, POLICY_HASH)
    current = sidecar.snapshot(ledger)
    assert asked == [CLI]
    assert current["partial"] is False and "error" not in current
    assert [(s["id"], s["name"], s["phase"], s["effective_policy_hash"])
            for s in current["sandboxes"]] == [(S1, "s1", "Ready", POLICY_HASH),
                                               (S2, "s2", "Provisioning", "")]
    assert ledger.sandboxes()[-1]["workspace"] == "staging"  # "gone" is gone
    assert len(ledger.sandboxes()) == 2


def test_the_inventory_route_is_not_degraded_with_the_cli(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)
    monkeypatch.setattr(sidecar, "cli_list", lambda cli: [
        {"workspace": "default", "id": S1, "name": "s1", "phase": "Ready"}])
    served = sidecar.inventory()
    assert served["degraded"] is False and "error" not in served
    assert [s["id"] for s in served["sandboxes"]] == [S1]


def test_a_failed_cli_listing_leaves_the_ledger_and_says_so(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)

    def down(cli):
        raise subprocess.TimeoutExpired(cli, 30)

    monkeypatch.setattr(sidecar, "cli_list", down)
    ledger = _ledger(("default", "s1", S1))
    revision = ledger.revision
    current = sidecar.snapshot(ledger)
    assert current["partial"] is True and current["error"] == "TimeoutExpired"
    assert [s["id"] for s in current["sandboxes"]] == [S1] and ledger.revision == revision


def test_the_cli_listing_is_used_instead_of_named_workspaces(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_WORKSPACES", "default")
    monkeypatch.setattr(sidecar, "cli_list", lambda cli: [])

    def sdk(_workspaces):
        raise AssertionError("the OpenShell SDK was asked")

    monkeypatch.setattr(sidecar, "sdk_list", sdk)
    assert sidecar.snapshot(_ledger())["partial"] is False


def test_without_the_cli_setting_nothing_is_run(monkeypatch):
    def never(cli):
        raise AssertionError("the CLI was run")

    monkeypatch.setattr(sidecar, "cli_list", never)
    current = sidecar.snapshot(_ledger(("default", "s1", S1)))
    assert current["partial"] is True and "error" not in current


# ---------------------------------------------------------------------------
# What was reported
# ---------------------------------------------------------------------------


class _Wire:
    def __init__(self):
        self.now, self.fail, self.posts = 1000.0, set(), []

    def clock(self):
        return self.now

    def post(self, path, payload):
        name = path.rsplit("/", 1)[-1]
        self.posts.append((name, copy.deepcopy(payload)))
        if name in self.fail:
            raise ConnectionError("down")
        return {}


def _reporter(wire, ledger):
    return sidecar.Reporter(ledger, post=wire.post, clock=wire.clock,
                            latency=sidecar.LatencyWindow(), undelivered=sidecar.Counter())


def test_the_reports_say_what_the_engine_took(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)
    monkeypatch.setattr(sidecar, "cli_list", lambda cli: [
        {"workspace": "default", "id": S1, "name": "s1", "phase": "Ready"},
        {"workspace": "default", "id": S2, "name": "s2", "phase": "Ready"}])
    wire = _Wire()
    reporter = _reporter(wire, _ledger())
    assert reporter.status() == {"reporting": True, "heartbeat": "pending",
                                 "inventory": "pending"}
    reporter.step()
    assert reporter.status() == {"reporting": True, "heartbeat": "ok", "inventory": "ok",
                                 "sandboxes": 2, "partial": False}


def test_a_report_the_engine_did_not_take_says_so_until_one_is_taken(monkeypatch):
    wire = _Wire()
    wire.fail = {"heartbeat", "inventory"}
    reporter = _reporter(wire, _ledger(("default", "s1", S1)))
    reporter.step()
    status = reporter.status()
    assert status["heartbeat"] == "failed" and status["inventory"] == "failed"
    assert status["heartbeat_error"] == status["inventory_error"] == "ConnectionError"
    wire.fail = set()
    wire.now += 400.0
    reporter.step()
    status = reporter.status()
    assert status["heartbeat"] == status["inventory"] == "ok"
    assert "heartbeat_error" not in status and "inventory_error" not in status
    assert status["partial"] is True and status["sandboxes"] == 1


def test_a_partial_inventory_names_why(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)

    def down(cli):
        raise RuntimeError("no")

    monkeypatch.setattr(sidecar, "cli_list", down)
    wire = _Wire()
    reporter = _reporter(wire, _ledger())
    reporter.step()
    assert reporter.status()["partial"] is True
    assert reporter.status()["listing_error"] == "RuntimeError"


def test_a_failed_listing_is_tried_again_shortly(monkeypatch):
    """The next ordinary inventory is five minutes away. A listing that failed
    once — the gateway restarting under ``up`` — is tried again at once."""
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)
    calls = {"n": 0}

    def cli_list(_cli):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("down")
        return [{"workspace": "default", "id": S1, "name": "s1", "phase": "Ready"}]

    monkeypatch.setattr(sidecar, "cli_list", cli_list)
    wire = _Wire()
    reporter = _reporter(wire, _ledger())

    def inventories():
        return [payload for name, payload in wire.posts if name == "inventory"]

    assert reporter.step() == sidecar.LISTING_RETRY_SECONDS
    assert inventories()[0]["partial"] is True
    wire.now += sidecar.LISTING_RETRY_SECONDS - 0.1
    reporter.step()
    assert len(inventories()) == 1
    wire.now += 0.1
    reporter.step()
    assert len(inventories()) == 2
    assert inventories()[-1]["partial"] is False
    assert reporter.status()["partial"] is False
    assert "listing_error" not in reporter.status()


def test_a_listing_that_keeps_failing_returns_to_the_ordinary_interval(monkeypatch):
    """Prompt tries cover a restart. A gateway that stays unlistable is not
    listed every two seconds after that, and the inventory stays partial."""
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", CLI)

    def down(_cli):
        raise RuntimeError("down")

    monkeypatch.setattr(sidecar, "cli_list", down)
    wire = _Wire()
    reporter = _reporter(wire, _ledger())

    def sent():
        return sum(name == "inventory" for name, _payload in wire.posts)

    reporter.step()
    for _ in range(sidecar.LISTING_RETRY_LIMIT):
        wire.now += sidecar.LISTING_RETRY_SECONDS
        reporter.step()
    posted = sent()
    assert posted > 1
    assert reporter.status()["partial"] is True
    assert reporter.status()["listing_error"] == "RuntimeError"
    wire.now += sidecar.LISTING_RETRY_SECONDS
    reporter.step()
    assert sent() == posted
    wire.now += sidecar.INVENTORY_SECONDS - sidecar.LISTING_RETRY_SECONDS
    reporter.step()
    assert sent() == posted + 1


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, headers=headers or {})) as resp:
        return json.load(resp)


def _never(_payload):
    raise AssertionError("no decision expected")


#: This module's sidecar holds a gateway credential, so its routes answer a
#: caller with its token (0.6.41).
SIDECAR_TOKEN = "sidecar-secret"
WITH_TOKEN = {"Authorization": f"Bearer {SIDECAR_TOKEN}"}


def test_the_reports_route_answers_the_reporters_status(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", SIDECAR_TOKEN)
    status = {"reporting": True, "heartbeat": "ok", "inventory": "ok", "sandboxes": 0,
              "partial": False}
    handler = sidecar.make_handler(lambda: {}, _never, reports_fn=lambda: dict(status))
    server, thread, base = _serve(handler)
    try:
        assert _get(base + "/artzain/reports", WITH_TOKEN) == status
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_without_a_reporter_the_route_says_nothing_is_reported(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", SIDECAR_TOKEN)
    server, thread, base = _serve(sidecar.make_handler(lambda: {}, _never))
    try:
        assert _get(base + "/artzain/reports", WITH_TOKEN) == {"reporting": False}
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_the_running_sidecar_serves_its_reporters_status(monkeypatch):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", SIDECAR_TOKEN)
    monkeypatch.delenv("OPENSHELL_SIDECAR_GRPC", raising=False)
    monkeypatch.setattr(sidecar, "_BASE", None)  # main() sets it
    captured = {}

    class _Server:
        def __init__(self, address, handler):
            captured["handler"] = handler

        def serve_forever(self):
            return None

    monkeypatch.setattr(sidecar, "warm", lambda: None)
    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", _Server)
    monkeypatch.setattr(sidecar.Reporter, "run", lambda self, stop: None)
    monkeypatch.setattr(sidecar.Housekeeper, "run", lambda self, stop: None)
    sidecar.main()
    server, thread, base = _serve(captured["handler"])
    try:
        assert _get(base + "/artzain/reports", WITH_TOKEN) == {
            "reporting": True, "heartbeat": "pending", "inventory": "pending"}
    finally:
        server.shutdown()
        thread.join(timeout=2)


needs_unix_datagrams = pytest.mark.skipif(
    not hasattr(__import__("socket"), "AF_UNIX") or __import__("sys").platform == "win32",
    reason="POSIX datagram sockets")


@needs_unix_datagrams
def test_the_sidecar_tells_systemd_it_is_ready(monkeypatch, tmp_path):
    """``Type=notify``: the gateway's unit, ordered after the sidecar's,
    starts once the socket is there, not when the process is."""
    import socket

    path = str(tmp_path / "notify")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind(path)
    listener.settimeout(5)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", path)
        sidecar._notify_ready()
        assert listener.recv(64) == b"READY=1"
    finally:
        listener.close()


@pytest.mark.skipif(not __import__("sys").platform.startswith("linux"),
                    reason="abstract sockets are Linux's")
def test_an_abstract_notify_socket_is_told_too(monkeypatch):
    import os
    import socket

    name = f"artzain-notify-test-{os.getpid()}"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind("\0" + name)
    listener.settimeout(5)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", "@" + name)
        sidecar._notify_ready()
        assert listener.recv(64) == b"READY=1"
    finally:
        listener.close()


def test_without_systemd_nothing_is_told(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    sidecar._notify_ready()  # no socket, no error


def test_a_notify_socket_that_is_gone_does_not_stop_the_sidecar(monkeypatch, tmp_path):
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "gone"))
    sidecar._notify_ready()


def test_the_sidecar_is_ready_once_it_listens_and_before_it_serves(monkeypatch):
    order = []

    class _Server:
        def __init__(self, address, handler):
            order.append("bind")

        def serve_forever(self):
            order.append("serve")

    monkeypatch.delenv("OPENSHELL_SIDECAR_GRPC", raising=False)
    monkeypatch.setattr(sidecar, "warm", lambda: None)
    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", _Server)
    monkeypatch.setattr(sidecar, "_notify_ready", lambda: order.append("ready"))
    sidecar.main()
    assert order == ["bind", "ready", "serve"]


def test_the_reports_route_needs_the_token_when_one_is_set(monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_TOKEN", "sidecar-secret")
    handler = sidecar.make_handler(lambda: {}, _never, reports_fn=lambda: {"reporting": True})
    server, thread, base = _serve(handler)
    try:
        with pytest.raises(urllib.error.HTTPError) as refused:
            _get(base + "/artzain/reports")
        assert refused.value.code == 401
        assert _get(base + "/artzain/reports",
                    {"Authorization": "Bearer sidecar-secret"}) == {"reporting": True}
    finally:
        server.shutdown()
        thread.join(timeout=2)
