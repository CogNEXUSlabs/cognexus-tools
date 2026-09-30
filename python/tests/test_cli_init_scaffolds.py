"""Tests for ``artzain init`` — the framework scaffolds (journey plan R3).

The scaffolds are shipped source that a developer runs unmodified, so the bar
is higher than "the file was written": each must be valid in its language,
must carry no unsubstituted placeholders, and must actually demonstrate the
seam it claims to — including the fail-closed rule, which is the one thing a
copied example must not get wrong.

Run::

    cd pypi-package
    PYTHONPATH=src python -m pytest tests/test_cli_init_scaffolds.py -v
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import json
import re
import sys
import threading
import types
from pathlib import Path

import pytest

import artzain
from artzain import cli
from artzain.tool_call_contract import inspect_tool_call
from tests.scaffold_install_line import (
    PYTHON_FRAMEWORKS,
    parse_install_line,
    requirements,
    without_artzain,
)

FRAMEWORKS = sorted(cli._SCAFFOLDS)
BASE_URL = "https://engine.example.com"

#: The scaffolds that gate a structured call with ``kind="tool_call"``.
TOOL_CALL_FRAMEWORKS = ["crewai", "mcp"]

#: Cyrillic, CJK and an emoji. ``json.dumps`` escapes all of it by default, and
#: the injection screen denies four or more ``\uXXXX`` escapes in a row as an
#: encoding attack.
NON_LATIN = "Привет, это сводка 你好 🙂"

#: Outcomes that are not the exact string ``"allow"``: null, empty, cased or
#: spaced differently, a word the guard does not know, and values of the wrong
#: type. A guard must not run the tool on any of them. A list matters to
#: LangGraph, which follows each element of a list a route returns.
NOT_ALLOW = [None, "", "Allow", "ALLOW", " allow", "allowed", "approve", "unknown", True, 1, ["allow"]]


@pytest.fixture(params=FRAMEWORKS)
def scaffold(request) -> tuple[str, str]:
    """(framework, rendered source) for each shipped scaffold."""
    return request.param, cli.scaffold_contents(request.param, BASE_URL)


@pytest.fixture
def decisions(monkeypatch) -> list[dict]:
    """Stand in for ``artzain.decide``: record every call, answer from the local guards.

    The verdict is the SDK's offline evaluation, computed in-process, so no
    API key is looked up and nothing leaves the process.
    """
    decide_module = importlib.import_module("artzain.decide")
    calls: list[dict] = []

    def fake_decide(**kwargs):
        calls.append(kwargs)
        return decide_module._decide_offline(
            action=kwargs["action"],
            target=kwargs["target"],
            payload=kwargs["payload"],
            kind=kwargs["kind"],
            agent_did=kwargs["agent_did"],
            request_id=None,
        )

    monkeypatch.setattr(artzain, "decide", fake_decide)
    return calls


class _StubMCPServer:
    """``mcp.server.Server`` as the MCP SDK 2.x shapes it: the handlers go in
    the constructor (``on_list_tools=``, ``on_call_tool=``), and there are no
    registration decorators. The keywords are kept, so a test calls the
    handlers the server was given."""

    def __init__(self, name: str, **options) -> None:
        self.name = name
        self.options = options


def _framework_stubs(framework: str) -> dict[str, types.ModuleType]:
    """Modules standing in for the names a scaffold imports from its framework."""
    if framework == "crewai":
        crewai = types.ModuleType("crewai")
        crewai.Agent = crewai.Crew = crewai.Task = object
        tools = types.ModuleType("crewai.tools")
        tools.tool = lambda _name: (lambda fn: fn)  # leaves the governed callable in place
        return {"crewai": crewai, "crewai.tools": tools}
    if framework == "mcp":
        server = types.ModuleType("mcp.server")
        server.Server = _StubMCPServer
        server.ServerRequestContext = object
        stdio = types.ModuleType("mcp.server.stdio")
        stdio.stdio_server = None
        mcp_types = types.ModuleType("mcp.types")
        # The results and blocks the scaffold builds, kept keyword for keyword.
        for name in ("CallToolResult", "ListToolsResult", "TextContent", "Tool"):
            setattr(mcp_types, name, types.SimpleNamespace)
        # Named only in the handlers' annotations.
        mcp_types.CallToolRequestParams = mcp_types.PaginatedRequestParams = object
        return {
            "mcp": types.ModuleType("mcp"),
            "mcp.server": server,
            "mcp.server.stdio": stdio,
            "mcp.types": mcp_types,
        }
    if framework == "langgraph":
        graph = types.ModuleType("langgraph.graph")
        graph.END = "__end__"
        graph.StateGraph = object  # the tests call the nodes, not a built graph
        return {"langgraph": types.ModuleType("langgraph"), "langgraph.graph": graph}
    raise KeyError(f"no framework stubs for {framework!r}")


def _load_scaffold(monkeypatch, framework: str) -> types.ModuleType:
    """Run a rendered scaffold as a module, with its framework imports stubbed.

    Neither CrewAI nor the MCP SDK is a test dependency. The stubs replace only
    the framework, so the guard code that runs is the code a developer gets.
    Stubs cannot see a change in the framework's own API, so
    test_scaffolds_real_frameworks.py runs the same files on the real ones.
    """
    for name, stub in _framework_stubs(framework).items():
        monkeypatch.setitem(sys.modules, name, stub)
    module = types.ModuleType(f"artzain_{framework}_guard")
    source = cli.scaffold_contents(framework, BASE_URL)
    exec(compile(source, f"{module.__name__}.py", "exec"), module.__dict__)
    return module


def _mcp_call(guard: types.ModuleType, name: str, arguments: dict | None):
    """Call the handler the MCP scaffold gave its server for ``tools/call``, the
    way the 2.x server calls it: with the request context and the request's
    params, whose ``arguments`` a client may leave out."""
    call_tool = guard.app.options["on_call_tool"]
    params = types.SimpleNamespace(name=name, arguments=arguments)
    return asyncio.run(call_tool(None, params))


def _send_email(monkeypatch, framework: str, body: str) -> str:
    """Invoke the scaffold's guarded send_email the way its framework would."""
    guard = _load_scaffold(monkeypatch, framework)
    if framework == "crewai":
        return guard.send_email(body=body)  # CrewAI passes tool arguments by keyword
    result = _mcp_call(guard, "send_email", {"contact_id": "123", "body": body})
    (content,) = result.content
    return content.text


# ── every scaffold ───────────────────────────────────────────────────────────

def test_all_frameworks_are_registered():
    assert FRAMEWORKS == ["crewai", "langgraph", "mcp", "openclaw", "openshell"]


def test_scaffold_is_valid_python(scaffold):
    framework, src = scaffold
    if framework in ("openclaw", "openshell"):
        pytest.skip("OpenClaw scaffold is TypeScript; OpenShell scaffold is YAML")
    ast.parse(src)  # raises SyntaxError if the template drifted


def test_no_unsubstituted_placeholders(scaffold):
    _framework, src = scaffold
    assert "__COGNEXUS_BASE_URL__" not in src
    assert "__COGNEXUS_PKG_VERSION__" not in src


def test_base_url_is_stamped(scaffold):
    _framework, src = scaffold
    assert BASE_URL in src


def test_scaffold_calls_decide(scaffold):
    framework, src = scaffold
    if framework == "openclaw":
        assert "decide(" in src
        assert 'kind: "tool_call"' in src
        return
    if framework == "openshell":
        assert "artzain.decide(" in src
        return
    assert "artzain.decide(" in src


def test_scaffold_handles_all_three_outcomes(scaffold):
    """allow / deny / review is the contract — an example must show all three.

    Matched as words, not as quoted literals: langgraph routes on all three
    explicitly, while mcp and crewai run the action under `allow`, queue on
    `review` and refuse everything else. The control flow is pinned by running
    the scaffolds (below); this checks coverage.
    """
    _framework, src = scaffold
    for outcome in ("allow", "deny", "review"):
        assert re.search(rf"\b{outcome}\b", src), f"{outcome} not handled"


def test_scaffold_fails_closed_on_decision_error(scaffold):
    """The one rule a copied example must not get wrong."""
    framework, src = scaffold
    assert "DecisionError" in src, "does not catch the SDK's error type"
    if framework == "openclaw":
        assert "block: true" in src
        assert "failing closed" in src
        assert "requireApproval" not in src
        return
    if framework == "openshell":
        assert "fail closed" in src
        return
    tree = ast.parse(src)
    handlers = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and node.type is not None
        and "DecisionError" in ast.unparse(node.type)
    ]
    assert handlers, "DecisionError is mentioned but never caught"
    for handler in handlers:
        body = ast.unparse(handler)
        assert "deny" in body or "REFUSED" in body, (
            "DecisionError handler must fail closed, not fall through to allow"
        )


def test_scaffold_declares_its_install_line(scaffold):
    framework, src = scaffold
    if framework == "openclaw":
        assert "npm install @cognexuslabs/artzain" in src
        assert framework in src
        return
    if framework == "openshell":
        assert "pip install artzain" in src
        assert "artzain init --framework openshell" in src
        return
    assert "pip install artzain" in src
    assert framework in src


@pytest.mark.parametrize("framework", PYTHON_FRAMEWORKS)
def test_scaffold_exit_guidance_matches_its_install_line(framework):
    """Without its framework (or with a version it cannot use) a scaffold exits
    saying what to install. That must be the install line's own requirements,
    or a developer is told two different things."""
    src = cli.scaffold_contents(framework, BASE_URL)
    messages = [
        node.exc.args[0].value
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and ast.unparse(node.exc.func) == "SystemExit"
        and node.exc.args
        and isinstance(node.exc.args[0], ast.Constant)
    ]
    assert messages, "the scaffold never says what to install"
    for message in messages:
        assert "pip install " in message, message
        named = parse_install_line("pip install " + message.split("pip install ", 1)[1])
        assert named == requirements(framework), message


@pytest.mark.parametrize(
    ("line", "names"),
    [
        ('pip install artzain "mcp>=2,<3"', ["artzain", "mcp>=2,<3"]),
        ("pip install artzain langgraph  # the graph library", ["artzain", "langgraph"]),
        ("pip install 'artzain[verify]>=0.6.33' crewai", ["artzain[verify]>=0.6.33", "crewai"]),
    ],
)
def test_install_line_is_read_as_a_shell_reads_it(line, names):
    """CI installs what this reads, so it must read what a developer's shell
    would run: quotes kept together, a comment dropped."""
    assert parse_install_line(line) == names


@pytest.mark.parametrize(
    "line",
    [
        "pip install artzain mcp>=2,<3",  # a shell redirects on the > and <
        "pip install artzain mcp | tee install.log",
        "pip install artzain[verify] crewai",  # zsh: no matches found
        "pip install artzain mcp==2.*",
        "pip install artzain $FRAMEWORK",
        "python -m pip install artzain mcp",
    ],
)
def test_install_line_a_shell_would_not_run_as_written_is_refused(line):
    with pytest.raises(ValueError):
        parse_install_line(line)


def test_artzain_is_recognised_with_extras_or_a_version():
    assert without_artzain(["artzain[verify]>=0.6.33", "crewai"]) == ["crewai"]
    with pytest.raises(ValueError):
        without_artzain(["crewai", "crewai-tools"])


def test_every_python_scaffold_has_its_install_line_read():
    """PYTHON_FRAMEWORKS is the list the real-framework tests and their CI
    legs cover; a Python scaffold missing from it would be run by neither."""
    python_scaffolds = sorted(
        framework for framework, (template, _) in cli._SCAFFOLDS.items() if template.endswith(".py.tpl")
    )
    assert list(PYTHON_FRAMEWORKS) == python_scaffolds


def test_ci_runs_a_leg_for_every_python_scaffold():
    """The scaffold job lists its frameworks by hand: in the engine's workflow
    and the mirror's seed template here, and in the seeded copy on the mirror."""
    root = Path(__file__).resolve().parents[2]
    workflows = [
        path
        for path in (
            root / ".github" / "workflows" / "tests.yml",
            root / "scripts" / "cognexus-tools-seed" / "workflows" / "tests.yml",
        )
        if path.is_file()
    ]
    if not workflows:
        pytest.skip("no workflow beside this checkout")
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        legs = re.findall(r"^\s+framework: \[([^\]]*)\]\s*$", text, re.MULTILINE)
        assert [[name.strip() for name in leg.split(",")] for leg in legs] == [
            list(PYTHON_FRAMEWORKS)
        ], workflow


def test_scaffold_serializes_json_without_ascii_escapes(scaffold):
    """Every ``json.dumps`` passes ``ensure_ascii=False`` (see NON_LATIN)."""
    framework, src = scaffold
    if framework == "openclaw":
        pytest.skip("JSON.stringify leaves non-ASCII text as it is")
    if framework == "openshell":
        pytest.skip("OpenShell scaffold is YAML, not a JSON caller")
    for node in ast.walk(ast.parse(src)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "dumps"
        ):
            assert any(
                k.arg == "ensure_ascii"
                and isinstance(k.value, ast.Constant)
                and k.value.value is False
                for k in node.keywords
            ), f"serialized without ensure_ascii=False: {ast.unparse(node)}"


# ── tool_call scaffolds: run them, check what the engine would receive ──────

@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_tool_call_payload_passes_the_engine_contract_check(framework, monkeypatch, decisions):
    """One call object, ``{"tool": <the action>, "arguments": {...}}``.

    The engine's contract check reads ``args`` as the argument object too, so a
    payload carrying ``"args": [...]`` is a ``high`` finding, and every online
    call goes to review.
    """
    result = _send_email(monkeypatch, framework, "Following up on the meeting.")

    (sent,) = decisions
    assert sent["kind"] == "tool_call"
    call = json.loads(sent["payload"])
    assert set(call) == {"tool", "arguments"}
    assert call["tool"] == sent["action"] == "send_email"
    assert call["arguments"]["body"] == "Following up on the meeting."
    report = inspect_tool_call(sent["payload"])
    assert (report.severity, report.findings) == ("none", [])
    assert result.startswith("Sent email"), result


def test_crewai_payload_names_arguments_however_the_tool_is_called(monkeypatch, decisions):
    """Arguments keyed by parameter name; the tool is the action, not the function name."""
    guard = _load_scaffold(monkeypatch, "crewai")

    @guard.governed(action="send_email", target="crm:contact:9")
    def notify(body: str, cc: str = "") -> str:
        return "sent"

    notify(body="Following up.", cc="ops@example.com")
    notify("Following up.", "ops@example.com")

    by_keyword, by_position = (json.loads(call["payload"]) for call in decisions)
    assert by_keyword == by_position == {
        "tool": "send_email",
        "arguments": {"body": "Following up.", "cc": "ops@example.com"},
    }


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_tool_call_with_non_latin_arguments_is_not_denied(framework, monkeypatch, decisions):
    result = _send_email(monkeypatch, framework, NON_LATIN)

    (sent,) = decisions
    assert NON_LATIN in sent["payload"], "the payload escaped non-ASCII text"
    assert json.loads(sent["payload"])["arguments"]["body"] == NON_LATIN
    assert result.startswith("Sent email"), result


# ── only an explicit allow runs the tool ─────────────────────────────────────

def _decide_answers(monkeypatch, decision: dict) -> None:
    """Make ``artzain.decide`` return *decision*, whatever it is asked.

    Each answer is decoded from JSON, as an online decision is, so its strings
    are new objects: a guard comparing ``outcome is "allow"`` would not match.
    """
    wire = json.dumps(decision)
    monkeypatch.setattr(artzain, "decide", lambda **_kwargs: json.loads(wire))


def _call_guarded_tool(monkeypatch, framework: str) -> tuple[str, list[str]]:
    """Run one guarded tool call through the scaffold's gate.

    Returns what the agent or client is told, and the tool bodies that ran.
    """
    guard = _load_scaffold(monkeypatch, framework)
    ran: list[str] = []
    if framework == "crewai":
        @guard.governed(action="send_email", target="crm:contact:123")
        def send_email(body: str) -> str:
            ran.append("send_email")
            return "Sent email."

        return send_email(body="Following up."), ran

    def run_tool(name: str, arguments: dict) -> str:
        ran.append(name)
        return "Sent email."

    monkeypatch.setattr(guard, "run_tool", run_tool)
    result = _mcp_call(guard, "send_email", {"contact_id": "123", "body": "Hi"})
    (content,) = result.content
    # The model reads a call that did not run as a failed one, not as the tool's output.
    assert result.is_error is (ran == []), (result.is_error, ran)
    return content.text, ran


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_allow_runs_the_tool(framework, monkeypatch):
    _decide_answers(monkeypatch, {"outcome": "allow", "decision_id": "dec-1", "reasons": []})
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == ["send_email"]
    assert told.startswith("Sent email."), told


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_review_queues_the_tool_without_running_it(framework, monkeypatch):
    _decide_answers(monkeypatch, {"outcome": "review", "decision_id": "dec-1", "reasons": ["x"]})
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == []
    assert told.startswith("QUEUED FOR REVIEW"), told


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_deny_refuses_the_tool_with_its_reasons(framework, monkeypatch):
    _decide_answers(monkeypatch, {"outcome": "deny", "decision_id": "dec-1", "reasons": ["no"]})
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == []
    assert told.startswith("REFUSED: no"), told


@pytest.mark.parametrize("outcome", NOT_ALLOW, ids=repr)
@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_any_other_outcome_refuses_the_tool(framework, outcome, monkeypatch):
    """Missing, misspelt or future: whatever is not ``allow`` does not run,
    and the refusal says which outcome it got."""
    _decide_answers(monkeypatch, {"outcome": outcome, "decision_id": "dec-1", "reasons": []})
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == []
    assert told.startswith("REFUSED"), told
    assert f"unrecognised outcome {outcome!r}" in told, told


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_a_decision_without_an_outcome_refuses_the_tool(framework, monkeypatch):
    _decide_answers(monkeypatch, {"decision_id": "dec-1"})
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == []
    assert told.startswith("REFUSED"), told


def test_mcp_decides_off_the_event_loop(monkeypatch):
    """``decide()`` blocks on the network (for up to 10 s). Called on the
    event loop's thread, it would stall every other request the server is
    serving; the loop must stay free while it waits."""
    guard = _load_scaffold(monkeypatch, "mcp")
    deciding = threading.Event()
    released = threading.Event()
    released_while_deciding: list[bool] = []

    def blocking_decide(**_kwargs):
        deciding.set()
        # Generous: only a broken gate waits this long.
        released_while_deciding.append(released.wait(timeout=10))
        return {"outcome": "allow", "decision_id": "dec-1", "reasons": []}

    monkeypatch.setattr(artzain, "decide", blocking_decide)
    call_tool = guard.app.options["on_call_tool"]
    params = types.SimpleNamespace(name="send_email", arguments={"contact_id": "1", "body": "Hi"})

    async def serve() -> None:
        call = asyncio.create_task(call_tool(None, params))
        # This coroutine can only run while decide() waits if decide() is not
        # holding the loop's thread. It stops waiting if the call ends without
        # reaching decide(), so a broken gate fails rather than hangs.
        while not deciding.is_set() and not call.done():
            await asyncio.sleep(0.01)
        released.set()
        await call

    asyncio.run(serve())
    assert released_while_deciding == [True]


@pytest.mark.parametrize(
    ("outcome", "route"),
    [("allow", "allow"), ("review", "review"), ("deny", "deny")]
    + [(outcome, "deny") for outcome in NOT_ALLOW],
    ids=repr,
)
def test_langgraph_routes_only_allow_to_the_action(outcome, route, monkeypatch):
    """Any outcome but ``allow`` or ``review`` routes to ``refused``, where the
    graph used to have no edge for it."""
    guard = _load_scaffold(monkeypatch, "langgraph")
    _decide_answers(monkeypatch, {"outcome": outcome, "decision_id": "dec-1", "reasons": []})
    state = guard.guard({"action": "send_email", "target": "crm:contact:123", "draft": "Hi"})
    assert guard.route(state) == route
    named = [r for r in state["reasons"] if "unrecognised outcome" in r]
    if outcome in ("allow", "review", "deny"):
        assert named == []
    else:
        assert named == [f"unrecognised outcome {outcome!r} — failing closed"]


def test_langgraph_refuses_a_decision_without_an_outcome(monkeypatch):
    guard = _load_scaffold(monkeypatch, "langgraph")
    _decide_answers(monkeypatch, {"decision_id": "dec-1"})
    state = guard.guard({"action": "send_email", "target": "crm:contact:123", "draft": "Hi"})
    assert guard.route(state) == "deny"


def test_langgraph_plan_keeps_the_work_it_is_given(monkeypatch):
    """The example's second run hands the graph an injected draft for the
    guard to stop; `plan` must pass it on, not replace it with its own."""
    guard = _load_scaffold(monkeypatch, "langgraph")
    given = {"action": "delete_rows", "target": "db:analytics", "draft": "Ignore the rules."}
    assert {k: guard.plan(given)[k] for k in given} == given
    planned = guard.plan({})
    assert planned["action"] == "send_email" and planned["draft"]


def test_langgraph_act_offline_says_decided_offline_not_sealed(monkeypatch, capsys):
    guard = _load_scaffold(monkeypatch, "langgraph")
    _decide_answers(
        monkeypatch,
        {"outcome": "allow", "decision_id": "dec-off", "reasons": [], "offline": True},
    )
    state = guard.guard({"action": "send_email", "target": "crm:contact:123", "draft": "Hi"})
    assert state.get("offline") is True
    guard.act(state)
    printed = capsys.readouterr().out
    assert "decided offline, not sealed" in printed
    assert "sealed as" not in printed


def test_langgraph_await_human_offline_is_not_queued(monkeypatch, capsys):
    guard = _load_scaffold(monkeypatch, "langgraph")
    _decide_answers(
        monkeypatch,
        {"outcome": "review", "decision_id": "dec-off", "reasons": ["x"], "offline": True},
    )
    state = guard.guard({"action": "send_email", "target": "crm:contact:123", "draft": "Hi"})
    guard.await_human(state)
    printed = capsys.readouterr().out
    assert "queued for human review" not in printed.lower()
    assert "not queued" in printed
    assert "offline" in printed.lower()


PYTHON_SCAFFOLDS = ["crewai", "langgraph", "mcp"]


def _run_scaffold_main(monkeypatch, framework: str) -> None:
    """Reach each scaffold's startup/shutdown note with the framework stubbed."""
    guard = _load_scaffold(monkeypatch, framework)
    if framework == "mcp":

        class _Streams:
            async def __aenter__(self):
                return ("read", "write")

            async def __aexit__(self, *exc):
                return False

        async def run(read, write, options):
            return None

        monkeypatch.setattr(guard, "stdio_server", _Streams)
        monkeypatch.setattr(guard.app, "run", run, raising=False)
        monkeypatch.setattr(guard.app, "create_initialization_options", lambda: None, raising=False)
        asyncio.run(guard.main())
        return
    if framework == "langgraph":
        monkeypatch.setattr(
            guard, "build_graph", lambda: types.SimpleNamespace(invoke=lambda _state: None)
        )
        guard.main()
        return
    # CrewAI: Agent / Crew / Task only need to accept kwargs and kick off.
    class _CrewBits:
        def __init__(self, *args, **kwargs):
            pass

        def kickoff(self):
            return "ok"

    monkeypatch.setattr(guard, "Agent", _CrewBits)
    monkeypatch.setattr(guard, "Crew", _CrewBits)
    monkeypatch.setattr(guard, "Task", _CrewBits)
    guard.main()


def test_mcp_prints_its_note_to_stderr_not_the_protocol_stream(monkeypatch, capsys):
    """A stdio MCP server speaks JSON-RPC on stdout: a line of prose there is a
    protocol error for the client."""
    _run_scaffold_main(monkeypatch, "mcp")  # no key here (conftest.py)
    out, err = capsys.readouterr()
    assert out == ""
    assert "no API key configured" in err
    assert "not sealed" in err


@pytest.mark.parametrize("framework", PYTHON_SCAFFOLDS)
def test_no_key_note_uses_the_sdk_resolver_not_one_env_var(framework, monkeypatch, capsys, tmp_path):
    """``artzain.decide`` also takes ``MYAPP_API_KEY`` and the profile
    ``artzain login`` writes. Checking only ``COGNEXUS_API_KEY`` printed the
    offline note while calls went online (or failed reaching the profile's
    host). The note must ask the SDK's own resolver, and print only a yes/no
    — never anything derived from the credentials profile."""
    from artzain import credentials

    source = cli.scaffold_contents(framework, BASE_URL)
    assert "has_api_key()" in source
    assert 'os.environ.get("COGNEXUS_API_KEY")' not in source

    # No key anywhere: the note fires.
    _run_scaffold_main(monkeypatch, framework)
    printed = "\n".join(capsys.readouterr())
    assert "no API key configured" in printed
    assert "not sealed" in printed
    assert "`artzain login`" in printed

    # A profile alone (no COGNEXUS_API_KEY) is a configured key: no note.
    profile = tmp_path / "credentials.toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(profile))
    credentials.write_profile(api_key="profile-key", base_url="http://127.0.0.1:9")
    assert artzain.has_api_key() is True
    _run_scaffold_main(monkeypatch, framework)
    printed = "\n".join(capsys.readouterr())
    assert "no API key configured" not in printed
    assert "local guard" not in printed

    # MYAPP_API_KEY alone is also a configured key.
    profile.unlink()
    monkeypatch.setenv("MYAPP_API_KEY", "myapp-key")
    assert artzain.has_api_key() is True
    _run_scaffold_main(monkeypatch, framework)
    printed = "\n".join(capsys.readouterr())
    assert "no API key configured" not in printed


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_allow_offline_says_decided_offline_not_sealed(framework, monkeypatch):
    """Without a key, ``decide()`` answers from the local guard library with
    ``offline=True``. Calling that "sealed" is wrong: nothing was sealed."""
    _decide_answers(
        monkeypatch,
        {"outcome": "allow", "decision_id": "dec-off", "reasons": [], "offline": True},
    )
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == ["send_email"]
    assert "decided offline, not sealed" in told
    assert "sealed as" not in told


@pytest.mark.parametrize("framework", TOOL_CALL_FRAMEWORKS)
def test_review_offline_is_not_queued(framework, monkeypatch):
    """Offline, nothing is queued and nothing would ever run the call. The
    scaffolds must not say ``QUEUED FOR REVIEW`` for that path."""
    _decide_answers(
        monkeypatch,
        {"outcome": "review", "decision_id": "dec-off", "reasons": ["x"], "offline": True},
    )
    told, ran = _call_guarded_tool(monkeypatch, framework)
    assert ran == []
    assert "QUEUED FOR REVIEW" not in told
    assert "not queued" in told
    assert "offline" in told.lower()


def test_mcp_names_the_sdk_version_it_needs(monkeypatch):
    """The example uses the MCP SDK 2.x server, which takes its handlers in the
    ``Server`` constructor. The 1.x SDK registers them with decorators, and its
    ``mcp.server`` has no ``ServerRequestContext``; there the file must say
    what to install rather than fail with a TypeError."""

    class _Server1x:
        def __init__(self, name: str, version=None, instructions=None) -> None:
            self.name = name

        def list_tools(self):
            return lambda fn: fn

        def call_tool(self):
            return lambda fn: fn

    stubs = _framework_stubs("mcp")
    stubs["mcp.server"].Server = _Server1x
    del stubs["mcp.server"].ServerRequestContext
    for name, stub in stubs.items():
        monkeypatch.setitem(sys.modules, name, stub)
    source = cli.scaffold_contents("mcp", BASE_URL)
    with pytest.raises(SystemExit) as exited:
        exec(compile(source, "artzain_mcp_guard.py", "exec"), {"__name__": "artzain_mcp_guard"})
    assert 'pip install "mcp>=2,<3"' in str(exited.value)
    assert 'pip install artzain "mcp>=2,<3"' in source


def test_mcp_gives_its_server_both_handlers(monkeypatch):
    """2.x has no decorators to register a handler after the fact: a handler
    not passed to the constructor is never called."""
    guard = _load_scaffold(monkeypatch, "mcp")
    assert guard.app.options["on_list_tools"] is guard.list_tools
    assert guard.app.options["on_call_tool"] is guard.call_tool


def test_mcp_lists_its_tools(monkeypatch):
    """The 2.x handler returns the whole result, not a bare list of tools, and
    the SDK's field for a tool's argument schema is ``input_schema``."""
    guard = _load_scaffold(monkeypatch, "mcp")
    result = asyncio.run(guard.app.options["on_list_tools"](None, None))
    assert {
        tool.name: (sorted(tool.input_schema["properties"]), sorted(tool.input_schema["required"]))
        for tool in result.tools
    } == {
        "send_email": (["body", "contact_id"], ["body", "contact_id"]),
        "execute_sql": (["query"], ["query"]),
    }
    assert all(tool.input_schema["type"] == "object" for tool in result.tools)


def test_mcp_gates_a_call_that_sends_no_arguments(monkeypatch, decisions):
    """A client may send ``tools/call`` without ``arguments``. The 1.x server
    passed ``{}`` for it; 2.x passes the params as they came, so the scaffold
    supplies ``{}`` itself, and the call is gated rather than crashing."""
    guard = _load_scaffold(monkeypatch, "mcp")
    result = _mcp_call(guard, "send_email", None)

    (sent,) = decisions
    assert json.loads(sent["payload"]) == {"tool": "send_email", "arguments": {}}
    assert len(result.content) == 1


@pytest.mark.parametrize(
    ("tool", "arguments", "target"),
    [
        ("send_email", {"contact_id": "42", "body": "Hi"}, "crm:contact:42"),
        ("execute_sql", {"query": "select 1"}, "db:analytics"),
    ],
)
def test_mcp_decides_on_the_resource_the_call_touches(tool, arguments, target, monkeypatch, decisions):
    guard = _load_scaffold(monkeypatch, "mcp")
    _mcp_call(guard, tool, arguments)
    (sent,) = decisions
    assert (sent["action"], sent["target"]) == (tool, target)


def _recording_mcp_guard(monkeypatch, decision: dict | None = None):
    """The MCP scaffold with ``decide()`` answering *decision* and ``run_tool``
    recorded; returns the guard, the actions decided on and the tools run."""
    guard = _load_scaffold(monkeypatch, "mcp")
    asked: list[str] = []
    ran: list[str] = []
    wire = json.dumps(decision or {"outcome": "allow", "decision_id": "dec-1", "reasons": []})

    def decide(**kwargs):
        asked.append(kwargs["action"])
        return json.loads(wire)

    def run_tool(name: str, arguments: dict) -> str:
        ran.append(name)
        return f"ran {name}"

    monkeypatch.setattr(artzain, "decide", decide)
    monkeypatch.setattr(guard, "run_tool", run_tool)
    return guard, asked, ran


def test_mcp_refuses_a_tool_it_does_not_list(monkeypatch):
    """The 2.x server hands ``call_tool`` any name a client sends. A tool the
    server does not list is refused as a failed call, with no decision asked
    for and nothing run."""
    guard, asked, ran = _recording_mcp_guard(monkeypatch)
    result = _mcp_call(guard, "drop_table", {"table": "users"})
    assert (asked, ran) == ([], [])
    assert result.is_error is True
    assert [block.text for block in result.content] == ["Unknown tool 'drop_table'."]


@pytest.mark.parametrize("outcome", ["deny", "allow"])
def test_mcp_gates_a_tool_added_to_its_list(outcome, monkeypatch):
    """The gate is in ``call_tool``, not in each tool: a tool added to the list
    later is decided on before it runs, like the two the file ships with."""
    guard, asked, ran = _recording_mcp_guard(
        monkeypatch, {"outcome": outcome, "decision_id": "dec-1", "reasons": ["no"]}
    )
    added = types.SimpleNamespace(name="delete_rows", input_schema={"type": "object"})
    monkeypatch.setattr(guard, "TOOLS", [*guard.TOOLS, added])

    result = _mcp_call(guard, "delete_rows", {"table": "orders"})

    assert asked == ["delete_rows"]
    assert ran == (["delete_rows"] if outcome == "allow" else [])
    assert result.is_error is (outcome != "allow")


def test_mcp_fails_a_listed_tool_it_has_no_code_for(monkeypatch, caplog):
    """A tool added to TOOLS but not to ``run_tool``: once allowed, the call
    comes back failed, not as output that reads like the tool's."""
    guard = _load_scaffold(monkeypatch, "mcp")
    _decide_answers(monkeypatch, {"outcome": "allow", "decision_id": "dec-1", "reasons": []})
    added = types.SimpleNamespace(name="delete_rows", input_schema={"type": "object"})
    monkeypatch.setattr(guard, "TOOLS", [*guard.TOOLS, added])

    with caplog.at_level("ERROR"):
        result = _mcp_call(guard, "delete_rows", {"table": "orders"})

    assert result.is_error is True
    assert result.content[0].text.startswith("FAILED"), result.content[0].text


def test_mcp_reports_a_tool_that_raises_as_a_failed_call(monkeypatch, caplog):
    """The 2.x server answers an exception with a protocol error that carries
    its text, which for a real tool can quote a password or a key. The client
    gets a failed call without that text; the traceback goes to the log."""
    guard, asked, _ran = _recording_mcp_guard(monkeypatch)

    def run_tool(name: str, arguments: dict) -> str:
        raise RuntimeError("relay smtp://mailer:not-a-real-secret@mail.example refused")

    monkeypatch.setattr(guard, "run_tool", run_tool)
    with caplog.at_level("ERROR"):
        result = _mcp_call(guard, "send_email", {"contact_id": "1", "body": "Hi"})

    assert asked == ["send_email"]
    assert result.is_error is True
    (block,) = result.content
    assert block.text.startswith("FAILED"), block.text
    assert "not-a-real-secret" not in block.text
    assert any(
        record.exc_info and "not-a-real-secret" in str(record.exc_info[1])
        for record in caplog.records
    ), "the traceback was not logged"


@pytest.mark.parametrize(
    "gate_failure",
    [RuntimeError("socket closed"), None],
    ids=["decide-raises", "decide-returns-no-dict"],
)
def test_mcp_does_not_run_the_tool_when_the_gate_fails(gate_failure, monkeypatch, caplog):
    """An error other than ``DecisionError`` inside the gate, or a decision
    that is not a mapping, still leaves the tool unrun, and comes back as a
    failed call rather than a protocol error."""
    guard, _asked, ran = _recording_mcp_guard(monkeypatch)

    def decide(**_kwargs):
        if gate_failure is not None:
            raise gate_failure
        return None

    monkeypatch.setattr(artzain, "decide", decide)
    with caplog.at_level("ERROR"):
        result = _mcp_call(guard, "execute_sql", {"query": "select 1"})

    assert ran == []
    assert result.is_error is True
    assert result.content[0].text.startswith("FAILED"), result.content[0].text


# ── seam-specific: each framework is gated in the right place ────────────────

def test_langgraph_gates_on_the_edge_not_in_the_action():
    src = cli.scaffold_contents("langgraph", BASE_URL)
    assert "add_conditional_edges" in src
    # Only `allow` may route to the action node.
    assert '{"allow": "act"' in src
    assert '"review": "await_human"' in src
    assert '"deny": "refused"' in src


def test_mcp_gates_inside_call_tool():
    src = cli.scaffold_contents("mcp", BASE_URL)
    # The one handler every tool call reaches, given to the server the 2.x way.
    assert "on_call_tool=call_tool" in src
    # The gate must precede the tool body, not follow it.
    assert src.index("to_thread(gate, name, arguments)") < src.index("run_tool(name, arguments)")
    # Structured calls screen as tool_call, not as prose.
    assert 'kind="tool_call"' in src


def test_crewai_wraps_the_tool():
    src = cli.scaffold_contents("crewai", BASE_URL)
    assert "def governed(" in src
    assert "@governed(" in src
    # The real side effect only runs after the verdict is known.
    assert src.index("artzain.decide(") < src.index("result = fn(*args, **kwargs)")


def test_crewai_returns_refusal_rather_than_raising():
    """The agent should be able to re-plan, not crash."""
    src = cli.scaffold_contents("crewai", BASE_URL)
    assert 'return f"REFUSED:' in src


def test_openclaw_gates_on_before_tool_call():
    src = cli.scaffold_contents("openclaw", BASE_URL)
    assert '"before_tool_call"' in src
    assert "block: true" in src
    assert "requireApproval" not in src
    assert 'kind: "tool_call"' in src
    assert 'surface: "openclaw"' in src
    assert "not a ClawHub plugin" in src
    assert "HOOK_TIMEOUT_MS = 14_000" in src
    assert "definePluginEntry" in src
    assert 'decision.outcome === "review"' in src
    assert 'decision.outcome === "allow"' in src


def test_openclaw_blocks_review_and_errors():
    src = cli.scaffold_contents("openclaw", BASE_URL)
    review_idx = src.index('decision.outcome === "review"')
    allow_idx = src.index('decision.outcome === "allow"')
    block_idx = src.index("return block(")
    assert allow_idx < review_idx
    assert review_idx < src.index("QUEUED FOR REVIEW")
    assert "failing closed" in src[src.index("DecisionError"):]
    assert block_idx > 0


# ── the command itself ───────────────────────────────────────────────────────

def _run(monkeypatch, tmp_path, argv):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["artzain", *argv])
    cli.main(argv)


def test_init_writes_the_expected_filename(monkeypatch, tmp_path, capsys):
    _run(monkeypatch, tmp_path, ["init", "--framework", "langgraph"])
    out = tmp_path / "artzain_langgraph_guard.py"
    assert out.is_file()
    ast.parse(out.read_text(encoding="utf-8"))
    assert "Wrote" in capsys.readouterr().out


def test_init_writes_openclaw_typescript(monkeypatch, tmp_path, capsys):
    _run(monkeypatch, tmp_path, ["init", "--framework", "openclaw"])
    out = tmp_path / "artzain_openclaw_guard.ts"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert '"before_tool_call"' in text
    assert "__COGNEXUS_BASE_URL__" not in text
    captured = capsys.readouterr().out
    assert "Wrote" in captured
    assert "python artzain_openclaw_guard.ts" not in captured
    assert "npm install @cognexuslabs/artzain" in captured
    assert "not a ClawHub plugin" in captured


def test_init_writes_openshell_yaml(monkeypatch, tmp_path, capsys):
    _run(monkeypatch, tmp_path, ["init", "--framework", "openshell"])
    out = tmp_path / "artzain_openshell_policy.yaml"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "enforcement: enforce" in text
    assert "inference.local" in text
    assert "policy.local" in text
    assert "approve your own rule" in text
    assert "__COGNEXUS_BASE_URL__" not in text
    captured = capsys.readouterr().out
    assert "Wrote" in captured
    assert "python artzain_openshell_policy.yaml" not in captured
    assert "does not approve its own rule" in captured


def test_init_refuses_to_clobber(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, ["init", "-f", "mcp"])
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, tmp_path, ["init", "-f", "mcp"])
    assert exc.value.code == 1


def test_force_overwrites(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, ["init", "-f", "mcp"])
    out = tmp_path / "artzain_mcp_guard.py"
    out.write_text("# clobbered", encoding="utf-8")
    _run(monkeypatch, tmp_path, ["init", "-f", "mcp", "--force"])
    assert "artzain.decide(" in out.read_text(encoding="utf-8")


def test_output_path_override(monkeypatch, tmp_path):
    target = tmp_path / "nested" / "guard.py"
    target.parent.mkdir()
    _run(monkeypatch, tmp_path, ["init", "-f", "crewai", "-o", str(target)])
    assert target.is_file()


def test_unknown_framework_is_rejected_by_argparse(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, tmp_path, ["init", "-f", "autogen"])
    assert exc.value.code == 2  # argparse choices


def test_scaffold_contents_rejects_unknown_framework():
    with pytest.raises(KeyError):
        cli.scaffold_contents("autogen", BASE_URL)


def test_every_registered_scaffold_resource_exists():
    """Guards against a _SCAFFOLDS entry whose template was never shipped."""
    for framework in FRAMEWORKS:
        assert cli.scaffold_contents(framework, BASE_URL).strip()


def test_emitted_filenames_are_unique():
    names = [filename for _tpl, filename in cli._SCAFFOLDS.values()]
    assert len(names) == len(set(names))
