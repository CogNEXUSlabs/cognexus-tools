"""The Python scaffolds, run on the frameworks their install lines name.

test_cli_init_scaffolds.py runs each rendered scaffold with its framework
stubbed, and a stub cannot see the framework change. MCP SDK 2.0 dropped the
decorators the MCP scaffold registered its handlers with; the stubbed suite
stayed green while the file failed at import. These tests run the same
rendered files on the real MCP SDK, LangGraph and CrewAI, with
``artzain.decide`` answering a chosen outcome, or, where a test says so,
deciding with the local guard library as it does without an API key.

A framework's tests run only when ``ARTZAIN_SCAFFOLD_FRAMEWORK`` names it, and
then a framework that is missing, or not what the install line names, fails
them. Otherwise they skip, so the SDK suite does not depend on whichever
frameworks a machine happens to have. CI's scaffold job installs the line
and sets the variable; to do the same by hand, in a fresh virtualenv::

    cd pypi-package
    PYTHONPATH=src python tests/scaffold_install_line.py mcp > /tmp/scaffold-req.txt
    pip install -r /tmp/scaffold-req.txt pytest packaging
    ARTZAIN_SCAFFOLD_FRAMEWORK=mcp PYTHONPATH=src python -m pytest tests/test_scaffolds_real_frameworks.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import queue
import subprocess
import sys
import threading
import types
from importlib import metadata
from pathlib import Path

import pytest

import artzain
from artzain import cli
from tests.scaffold_install_line import PYTHON_FRAMEWORKS, requirements
from tests.test_cli_init_scaffolds import BASE_URL, NOT_ALLOW

#: The framework this run exercises, installed from its scaffold's install line.
EXERCISED = os.environ.get("ARTZAIN_SCAFFOLD_FRAMEWORK") or None

#: Seconds a real MCP exchange may take before the test fails instead of hanging.
MCP_TIMEOUT = 60


def test_the_framework_under_test_is_one_these_tests_cover():
    """A mistyped ARTZAIN_SCAFFOLD_FRAMEWORK would skip everything and pass."""
    assert EXERCISED in (None, *PYTHON_FRAMEWORKS)


def test_every_python_scaffold_has_tests_here():
    """A scaffold whose tests were missing here would get a CI leg that runs
    nothing and passes."""
    names = [name for name in globals() if name.startswith("test_")]
    assert [f for f in PYTHON_FRAMEWORKS if not any(n.startswith(f"test_{f}_") for n in names)] == []


def _mismatch(framework: str) -> str | None:
    """Why the installed packages are not what the scaffold's install line
    names, or None when they are."""
    try:
        from packaging.requirements import Requirement
    except ImportError:
        return "packaging is not installed, so the framework's version cannot be checked"
    for line in requirements(framework):
        requirement = Requirement(line)
        try:
            installed = metadata.version(requirement.name)
        except metadata.PackageNotFoundError:
            return f"{requirement.name} is not installed; the {framework} scaffold names {line!r}"
        if not requirement.specifier.contains(installed, prereleases=True):
            return f"{requirement.name} {installed} is installed; the {framework} scaffold names {line!r}"
    return None


def _load_real(monkeypatch, tmp_path: Path, framework: str) -> types.ModuleType:
    """Write the rendered scaffold to a file and import it on the real framework."""
    if EXERCISED != framework:
        pytest.skip(f"runs when ARTZAIN_SCAFFOLD_FRAMEWORK={framework}")
    mismatch = _mismatch(framework)
    if mismatch:
        pytest.fail(mismatch)
    _template, filename = cli._SCAFFOLDS[framework]
    path = tmp_path / filename
    path.write_text(cli.scaffold_contents(framework, BASE_URL), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    # typing and pydantic look a module's annotations up through sys.modules.
    monkeypatch.setitem(sys.modules, path.stem, module)
    spec.loader.exec_module(module)
    return module


def _answer(monkeypatch, outcome) -> list[dict]:
    """Make ``artzain.decide`` answer *outcome*; returns what it was asked.

    The answer is decoded from JSON, as an online decision is, so its strings
    are new objects: a guard comparing ``outcome is "allow"`` would not match.
    """
    asked: list[dict] = []
    wire = json.dumps({"outcome": outcome, "decision_id": "dec-1", "reasons": ["stub reason"]})

    def decide(**kwargs):
        asked.append(kwargs)
        return json.loads(wire)

    monkeypatch.setattr(artzain, "decide", decide)
    return asked


#: Every outcome but allow, and the start of what the caller is told.
NOT_RUN = [("review", "QUEUED FOR REVIEW"), ("deny", "REFUSED: stub reason")] + [
    (outcome, f"REFUSED: unrecognised outcome {outcome!r}") for outcome in NOT_ALLOW
]


# ── MCP: the 2.x server, driven through the SDK's own client ─────────────────

#: How the client connects to the in-process server: the 2025 handshake over
#: JSON-RPC (the path ``Server.run`` serves, as over stdio), and the
#: 2026-07-28 per-request path the 2.x client takes by default.
MCP_MODES = ["legacy", "auto"]


def _mcp_session(app, mode: str, work):
    """Connect the SDK's client to *app* and return ``await work(client)``."""
    from mcp import Client

    async def run():
        async with Client(app, mode=mode) as client:
            return await work(client)

    return asyncio.run(asyncio.wait_for(run(), MCP_TIMEOUT))


def _mcp_call(app, mode: str, name: str, arguments: dict):
    return _mcp_session(app, mode, lambda client: client.call_tool(name, arguments))


def _record_runs(monkeypatch, guard) -> list[str]:
    """Replace the scaffold's ``run_tool``; returns the tools it was asked to run."""
    ran: list[str] = []

    def run_tool(name: str, arguments: dict) -> str:
        ran.append(name)
        return f"ran {name}"

    monkeypatch.setattr(guard, "run_tool", run_tool)
    return ran


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_lists_its_tools(mode, monkeypatch, tmp_path):
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    result = _mcp_session(guard.app, mode, lambda client: client.list_tools())
    assert {
        tool.name: (sorted(tool.input_schema["properties"]), sorted(tool.input_schema["required"]))
        for tool in result.tools
    } == {
        "send_email": (["body", "contact_id"], ["body", "contact_id"]),
        "execute_sql": (["query"], ["query"]),
    }


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_runs_the_tool_on_allow(mode, monkeypatch, tmp_path):
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    asked = _answer(monkeypatch, "allow")
    arguments = {"contact_id": "123", "body": "Following up on the meeting."}

    result = _mcp_call(guard.app, mode, "send_email", arguments)

    assert result.is_error is False
    assert [block.text for block in result.content] == [
        "Sent email to contact 123.\n(sealed as dec-1)"
    ]
    (sent,) = asked
    assert (sent["action"], sent["target"]) == ("send_email", "crm:contact:123")
    assert (sent["kind"], sent["surface"]) == ("tool_call", "mcp")
    assert json.loads(sent["payload"]) == {"tool": "send_email", "arguments": arguments}


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_refuses_a_tool_it_does_not_list(mode, monkeypatch, tmp_path):
    """The 2.x server passes ``call_tool`` any name a client sends."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    asked = _answer(monkeypatch, "allow")
    ran = _record_runs(monkeypatch, guard)

    result = _mcp_call(guard.app, mode, "drop_table", {"table": "users"})

    assert (asked, ran) == ([], [])
    assert result.is_error is True
    assert [block.text for block in result.content] == ["Unknown tool 'drop_table'."]


@pytest.mark.parametrize("mode", MCP_MODES)
@pytest.mark.parametrize("outcome", ["deny", "allow"])
def test_mcp_gates_a_tool_added_to_its_list(outcome, mode, monkeypatch, tmp_path):
    """The gate is in ``call_tool``, not in each tool."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    from mcp.types import Tool

    asked = _answer(monkeypatch, outcome)
    ran = _record_runs(monkeypatch, guard)
    added = Tool(name="delete_rows", input_schema={"type": "object", "properties": {}})
    monkeypatch.setattr(guard, "TOOLS", [*guard.TOOLS, added])

    result = _mcp_call(guard.app, mode, "delete_rows", {"table": "orders"})

    assert [sent["action"] for sent in asked] == ["delete_rows"]
    assert ran == (["delete_rows"] if outcome == "allow" else [])
    assert result.is_error is (outcome != "allow")


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_fails_a_listed_tool_it_has_no_code_for(mode, monkeypatch, tmp_path):
    """A tool added to TOOLS but not to ``run_tool``: once allowed, the call
    comes back failed, not as output that reads like the tool's."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    from mcp.types import Tool

    _answer(monkeypatch, "allow")
    added = Tool(name="delete_rows", input_schema={"type": "object", "properties": {}})
    monkeypatch.setattr(guard, "TOOLS", [*guard.TOOLS, added])

    result = _mcp_call(guard.app, mode, "delete_rows", {"table": "orders"})

    assert result.is_error is True
    assert result.content[0].text.startswith("FAILED"), result.content[0].text


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_reports_a_tool_that_raises_as_a_failed_call(mode, monkeypatch, tmp_path):
    """Without the scaffold's handling, the 2.x server answers with a protocol
    error carrying the exception's text, which for a real tool can quote a
    password or a key."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    _answer(monkeypatch, "allow")

    def run_tool(name: str, arguments: dict) -> str:
        raise RuntimeError("relay smtp://mailer:not-a-real-secret@mail.example refused")

    monkeypatch.setattr(guard, "run_tool", run_tool)

    result = _mcp_call(guard.app, mode, "send_email", {"contact_id": "1", "body": "Hi"})

    assert result.is_error is True
    (block,) = result.content
    assert block.text.startswith("FAILED"), block.text
    assert "not-a-real-secret" not in block.text


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_does_not_run_the_tool_when_the_gate_fails(mode, monkeypatch, tmp_path):
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    ran = _record_runs(monkeypatch, guard)

    def decide(**_kwargs):
        raise RuntimeError("socket closed")

    monkeypatch.setattr(artzain, "decide", decide)

    result = _mcp_call(guard.app, mode, "execute_sql", {"query": "select 1"})

    assert ran == []
    assert result.is_error is True
    assert result.content[0].text.startswith("FAILED"), result.content[0].text


@pytest.mark.parametrize("mode", MCP_MODES)
@pytest.mark.parametrize(("outcome", "told"), NOT_RUN, ids=repr)
def test_mcp_runs_the_tool_on_no_other_outcome(mode, outcome, told, monkeypatch, tmp_path):
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    _answer(monkeypatch, outcome)
    ran: list[str] = []
    monkeypatch.setattr(guard, "run_tool", lambda name, arguments: ran.append(name) or "ran")

    result = _mcp_call(guard.app, mode, "send_email", {"contact_id": "123", "body": "Hi"})

    assert ran == []
    assert result.is_error is True
    (block,) = result.content
    assert block.text.startswith(told), block.text


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_gates_a_call_that_sends_no_arguments(mode, monkeypatch, tmp_path):
    """The SDK's client leaves ``arguments`` out when it has none, and the 2.x
    server hands the handler the params as they came."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    asked = _answer(monkeypatch, "deny")

    result = _mcp_session(guard.app, mode, lambda client: client.call_tool("send_email"))

    assert result.is_error is True
    (block,) = result.content
    assert block.text.startswith("REFUSED: stub reason"), block.text
    (sent,) = asked
    assert json.loads(sent["payload"]) == {"tool": "send_email", "arguments": {}}


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_fails_closed_when_no_decision_comes_back(mode, monkeypatch, tmp_path):
    guard = _load_real(monkeypatch, tmp_path, "mcp")

    def decide(**_kwargs):
        raise artzain.DecisionError("HTTP 503: audit unavailable")

    monkeypatch.setattr(artzain, "decide", decide)
    ran: list[str] = []
    monkeypatch.setattr(guard, "run_tool", lambda name, arguments: ran.append(name) or "ran")

    result = _mcp_call(guard.app, mode, "execute_sql", {"query": "select 1"})

    assert ran == []
    assert result.is_error is True
    (block,) = result.content
    assert block.text.startswith(
        "REFUSED: decision unavailable (HTTP 503: audit unavailable) — failing closed"
    ), block.text


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_serves_concurrent_calls_without_serializing_them(mode, monkeypatch, tmp_path):
    """Two calls in flight, and each one's ``decide()`` waits until the other's
    has begun. Served one at a time (a gate that holds the event loop, or a
    server that waits for one call before reading the next), the first call
    waits for a second that never starts, and the barrier breaks."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    both_deciding = threading.Barrier(2, timeout=10)

    def decide(**kwargs):
        both_deciding.wait()
        return {"outcome": "allow", "decision_id": f"dec-{kwargs['action']}", "reasons": []}

    monkeypatch.setattr(artzain, "decide", decide)

    async def two_calls(client):
        return await asyncio.gather(
            client.call_tool("send_email", {"contact_id": "1", "body": "Hi"}),
            client.call_tool("execute_sql", {"query": "select 1"}),
        )

    email, sql = _mcp_session(guard.app, mode, two_calls)

    assert [block.text for block in email.content] == [
        "Sent email to contact 1.\n(sealed as dec-send_email)"
    ]
    assert [block.text for block in sql.content] == ["Ran query: select 1\n(sealed as dec-execute_sql)"]


@pytest.mark.parametrize("mode", MCP_MODES)
def test_mcp_serves_over_stdio_as_a_program(mode, monkeypatch, tmp_path):
    """``python artzain_mcp_guard.py``, as the docstring says to run it: a
    stdio server in its own process. With no API key the local guard library
    decides, as on a developer's first run, and the note saying so goes to
    stderr: stdout carries the protocol."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    from mcp import Client, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server = StdioServerParameters(
        command=sys.executable,
        args=[guard.__file__],
        env=_program_environment(),
        cwd=str(tmp_path),
    )
    stderr = tmp_path / "stderr.txt"

    async def run():
        with stderr.open("w", encoding="utf-8") as errlog:
            async with Client(stdio_client(server, errlog=errlog), mode=mode) as client:
                tools = await client.list_tools()
                result = await client.call_tool(
                    "send_email", {"contact_id": "123", "body": "Following up on the meeting."}
                )
        return tools, result

    tools, result = asyncio.run(asyncio.wait_for(run(), MCP_TIMEOUT))

    assert sorted(tool.name for tool in tools.tools) == ["execute_sql", "send_email"]
    assert result.is_error is False
    (block,) = result.content
    assert block.text == "Sent email to contact 123.\n(decided offline, not sealed)", block.text
    assert "no API key configured" in stderr.read_text(encoding="utf-8")


def test_mcp_program_writes_only_protocol_messages_to_stdout(monkeypatch, tmp_path):
    """Stdout is the stdio server's JSON-RPC channel, and any other line there
    is a protocol error for a strict client. The SDK's own client skips such a
    line, and the SDK moves stray output to stderr only where it can, so this
    speaks raw JSON-RPC to the program and reads every line it writes."""
    guard = _load_real(monkeypatch, tmp_path, "mcp")
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "scaffold-test", "version": "0"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "send_email", "arguments": {"contact_id": "123", "body": "Hi"},
        }},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "drop_table", "arguments": {},
        }},
    ]
    child = subprocess.Popen(
        [sys.executable, guard.__file__],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **_program_environment()},
        cwd=tmp_path,
    )
    stdout_lines: queue.Queue[bytes] = queue.Queue()
    stderr_lines: queue.Queue[bytes] = queue.Queue()
    readers = [
        threading.Thread(target=_pump, args=(child.stdout, stdout_lines), daemon=True),
        threading.Thread(target=_pump, args=(child.stderr, stderr_lines), daemon=True),
    ]
    for reader in readers:
        reader.start()
    written: list[bytes] = []
    answers: dict[int, dict] = {}
    try:
        for request in requests:
            child.stdin.write(json.dumps(request).encode("utf-8") + b"\n")
            child.stdin.flush()
            while "id" in request and request["id"] not in answers:
                line = stdout_lines.get(timeout=MCP_TIMEOUT)
                written.append(line)
                message = json.loads(line)  # a line that is not JSON fails here
                if "id" in message:
                    answers[message["id"]] = message
        child.stdin.close()
        child.wait(timeout=MCP_TIMEOUT)
        for reader in readers:
            reader.join(timeout=MCP_TIMEOUT)
    finally:
        child.kill()
    written += _drain(stdout_lines)
    stderr = b"".join(_drain(stderr_lines)).decode("utf-8")

    assert all(json.loads(line).get("jsonrpc") == "2.0" for line in written if line.strip()), written
    assert sorted(tool["name"] for tool in answers[2]["result"]["tools"]) == ["execute_sql", "send_email"]
    sent, unknown = answers[3]["result"], answers[4]["result"]
    assert (sent["isError"], sent["content"][0]["text"]) == (
        False, "Sent email to contact 123.\n(decided offline, not sealed)"
    )
    assert (unknown["isError"], unknown["content"][0]["text"]) == (True, "Unknown tool 'drop_table'.")
    assert "no API key configured" in stderr


def _pump(stream, lines: queue.Queue[bytes]) -> None:
    for line in stream:
        lines.put(line)


def _drain(lines: queue.Queue[bytes]) -> list[bytes]:
    drained = []
    while not lines.empty():
        drained.append(lines.get_nowait())
    return drained


def _program_environment() -> dict[str, str]:
    """For a child running the scaffold as a program: the checkout's artzain,
    and this test's empty credentials profile."""
    return {
        "PYTHONPATH": str(Path(artzain.__file__).resolve().parents[1]),
        "COGNEXUS_CREDENTIALS_PATH": os.environ["COGNEXUS_CREDENTIALS_PATH"],
        "PYTHONUTF8": "1",
    }


# ── LangGraph: the compiled graph ────────────────────────────────────────────

#: What each terminal node prints.
LANGGRAPH_NODES = {"act": "✔ acting", "await_human": "⏸ queued", "refused": "✖ denied"}


@pytest.mark.parametrize(
    ("outcome", "node"),
    [("allow", "act"), ("review", "await_human"), ("deny", "refused")]
    + [(outcome, "refused") for outcome in NOT_ALLOW],
    ids=repr,
)
def test_langgraph_graph_reaches_act_only_on_allow(outcome, node, monkeypatch, tmp_path, capsys):
    """Through the real compiled graph, including an outcome sent as a list,
    whose elements LangGraph would follow as separate routes."""
    guard = _load_real(monkeypatch, tmp_path, "langgraph")
    _answer(monkeypatch, outcome)

    guard.build_graph().invoke({})

    printed = capsys.readouterr().out
    assert [name for name, mark in LANGGRAPH_NODES.items() if mark in printed] == [node]


def test_langgraph_demo_acts_on_the_benign_draft_and_refuses_the_injected_one(
    monkeypatch, tmp_path, capsys
):
    """The file's own ``main()``, deciding with the local guard library as it
    does without an API key."""
    guard = _load_real(monkeypatch, tmp_path, "langgraph")

    guard.main()

    out = capsys.readouterr().out
    benign, injected = out.split("2. An injected draft")
    assert [name for name, mark in LANGGRAPH_NODES.items() if mark in benign] == ["act"]
    assert [name for name, mark in LANGGRAPH_NODES.items() if mark in injected] == ["refused"]
    assert "decided offline, not sealed" in benign
    assert "sealed as" not in benign
    assert "no API key configured" in out


# ── CrewAI: the tool object the @tool decorator builds ───────────────────────


def _crewai_guard(monkeypatch, tmp_path) -> types.ModuleType:
    # Nothing here needs CrewAI's telemetry.
    monkeypatch.setenv("CREWAI_DISABLE_TELEMETRY", "true")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    return _load_real(monkeypatch, tmp_path, "crewai")


def test_crewai_tool_keeps_the_name_and_arguments_of_the_function_it_guards(
    monkeypatch, tmp_path
):
    """``@governed`` sits under ``@tool``; CrewAI builds the tool from the
    wrapper, so the wrapper must carry the function's signature and docstring."""
    guard = _crewai_guard(monkeypatch, tmp_path)
    assert guard.send_email.name == "send_email"
    assert "body" in guard.send_email.args_schema.model_json_schema()["properties"]
    assert "follow-up email" in guard.send_email.description


BODY = "Following up on the meeting."


@pytest.mark.parametrize(
    ("outcome", "told"),
    [("allow", f"Sent email ({len(BODY)} chars). (sealed as dec-1)")] + NOT_RUN,
    ids=repr,
)
def test_crewai_tool_runs_its_body_only_on_allow(outcome, told, monkeypatch, tmp_path):
    guard = _crewai_guard(monkeypatch, tmp_path)
    asked = _answer(monkeypatch, outcome)

    result = guard.send_email.run(body=BODY)

    assert str(result).startswith(told), result
    (sent,) = asked
    assert json.loads(sent["payload"]) == {"tool": "send_email", "arguments": {"body": BODY}}
