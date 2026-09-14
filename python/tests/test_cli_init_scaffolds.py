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
import types

import pytest

import artzain
from artzain import cli
from artzain.tool_call_contract import inspect_tool_call

FRAMEWORKS = sorted(cli._SCAFFOLDS)
BASE_URL = "https://engine.example.com"

#: The scaffolds that gate a structured call with ``kind="tool_call"``.
TOOL_CALL_FRAMEWORKS = ["crewai", "mcp"]

#: Cyrillic, CJK and an emoji. ``json.dumps`` escapes all of it by default, and
#: the injection screen denies four or more ``\uXXXX`` escapes in a row as an
#: encoding attack.
NON_LATIN = "Привет, это сводка 你好 🙂"


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
    """The decorator surface of ``mcp.server.Server`` that the scaffold uses."""

    def __init__(self, name: str) -> None:
        self.name = name

    def list_tools(self):
        return lambda fn: fn

    def call_tool(self):
        return lambda fn: fn


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
        stdio = types.ModuleType("mcp.server.stdio")
        stdio.stdio_server = None
        mcp_types = types.ModuleType("mcp.types")
        mcp_types.TextContent = mcp_types.Tool = dict
        return {
            "mcp": types.ModuleType("mcp"),
            "mcp.server": server,
            "mcp.server.stdio": stdio,
            "mcp.types": mcp_types,
        }
    raise KeyError(f"no framework stubs for {framework!r}")


def _load_scaffold(monkeypatch, framework: str) -> types.ModuleType:
    """Run a rendered scaffold as a module, with its framework imports stubbed.

    Neither CrewAI nor the MCP SDK is a test dependency. The stubs replace only
    the framework, so the guard code that runs is the code a developer gets.
    """
    for name, stub in _framework_stubs(framework).items():
        monkeypatch.setitem(sys.modules, name, stub)
    module = types.ModuleType(f"artzain_{framework}_guard")
    source = cli.scaffold_contents(framework, BASE_URL)
    exec(compile(source, f"{module.__name__}.py", "exec"), module.__dict__)
    return module


def _send_email(monkeypatch, framework: str, body: str) -> str:
    """Invoke the scaffold's guarded send_email the way its framework would."""
    guard = _load_scaffold(monkeypatch, framework)
    if framework == "crewai":
        return guard.send_email(body=body)  # CrewAI passes tool arguments by keyword
    (content,) = asyncio.run(guard.call_tool("send_email", {"contact_id": "123", "body": body}))
    return content["text"]


# ── every scaffold ───────────────────────────────────────────────────────────

def test_all_frameworks_are_registered():
    assert FRAMEWORKS == ["crewai", "langgraph", "mcp", "openclaw"]


def test_scaffold_is_valid_python(scaffold):
    framework, src = scaffold
    if framework == "openclaw":
        pytest.skip("OpenClaw scaffold is TypeScript")
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
    assert "artzain.decide(" in src


def test_scaffold_handles_all_three_outcomes(scaffold):
    """allow / deny / review is the contract — an example must show all three.

    Matched as words, not as quoted literals: langgraph routes on all three
    explicitly, while mcp and crewai early-return the two blocking outcomes and
    let `allow` fall through to the action. Both shapes are correct, so the
    assertion checks coverage rather than control flow.
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
    assert "pip install artzain" in src
    assert framework in src


def test_scaffold_serializes_json_without_ascii_escapes(scaffold):
    """Every ``json.dumps`` passes ``ensure_ascii=False`` (see NON_LATIN)."""
    framework, src = scaffold
    if framework == "openclaw":
        pytest.skip("JSON.stringify leaves non-ASCII text as it is")
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
    assert "@app.call_tool()" in src
    # The gate must precede the tool body, not follow it.
    assert src.index("gate(name, arguments)") < src.index("run_tool(name, arguments)")
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
