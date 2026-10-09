"""The ``artzain`` command line, as a user meets it (survey row 71).

Every subcommand, option, default, choice, help text and the order they come
in is what ``artzain --help`` and each ``artzain <cmd> --help`` print. The
help text itself depends on the Python version (argparse rewords and rewraps
it between releases), so this pins what it is made from: the whole parser
tree that ``cli.main`` builds, read back from argparse, against
``golden/cli-parser.json``, captured before ``main`` was split into one
builder per command group. On any one Python version the same tree prints
the same help, byte for byte.

The dispatch is pinned separately: the parsed arguments reach the command's
function, looked up when ``main`` runs.

After a deliberate change to the command line, recapture the tree with
``cd pypi-package && PYTHONPATH=src python -m tests.test_cli_parser_shape``
and review the diff.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import artzain.cli as cli

GOLDEN = Path(__file__).resolve().parent / "golden" / "cli-parser.json"
RECAPTURE = "cd pypi-package && PYTHONPATH=src python -m tests.test_cli_parser_shape"


def _built_parser() -> argparse.ArgumentParser:
    """The parser ``cli.main`` builds, caught where it is asked to parse."""
    caught: list[argparse.ArgumentParser] = []

    def parse_args(self, args=None, namespace=None):  # noqa: ANN001
        caught.append(self)
        return argparse.Namespace(func=lambda _args: None)

    with mock.patch.object(argparse.ArgumentParser, "parse_args", parse_args):
        cli.main([])
    (parser,) = caught
    return parser


def _plain(value: Any) -> Any:
    """A JSON-comparable form: a callable (a ``type=`` or a command's
    function) by name, a tuple as a list."""
    if callable(value):
        return f"<{getattr(value, '__name__', repr(value))}>"
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _describe(parser: argparse.ArgumentParser) -> dict[str, Any]:
    actions = []
    for action in parser._actions:
        entry: dict[str, Any] = {
            "kind": type(action).__name__,
            "option_strings": list(action.option_strings),
            "dest": action.dest,
            "nargs": action.nargs,
            "const": _plain(action.const),
            "default": _plain(action.default),
            "type": _plain(action.type),
            "required": action.required,
            "help": action.help,
            "metavar": _plain(action.metavar),
        }
        if isinstance(action, argparse._SubParsersAction):
            entry["commands"] = [
                {"name": choice.dest, "help": choice.help,
                 "parser": _describe(action.choices[choice.dest])}
                for choice in action._choices_actions
            ]
            entry["choices"] = list(action.choices)
        else:
            entry["choices"] = _plain(action.choices)
        actions.append(entry)
    return {
        "prog": parser.prog,
        "usage": parser.usage,
        "description": parser.description,
        "epilog": parser.epilog,
        "formatter_class": parser.formatter_class.__name__,
        "add_help": parser.add_help,
        "allow_abbrev": parser.allow_abbrev,
        "defaults": {k: _plain(v) for k, v in parser._defaults.items()},
        "groups": [[a.dest for a in g._group_actions] for g in parser._action_groups],
        "actions": actions,
    }


def test_the_command_line_is_the_captured_one():
    assert GOLDEN.is_file(), f"no captured parser: {RECAPTURE}"
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert _describe(_built_parser()) == golden


def _commands(tree: dict[str, Any], path: tuple[str, ...] = ()):
    for action in tree["actions"]:
        for command in action.get("commands") or []:
            yield path + (command["name"],), command["parser"]
            yield from _commands(command["parser"], path + (command["name"],))


def test_every_command_prints_its_help(capsys, monkeypatch):
    """Each command the tree names answers ``--help`` through ``main``."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    tree = json.loads(GOLDEN.read_text(encoding="utf-8"))
    paths = [()] + [path for path, _ in _commands(tree)]
    assert len(paths) > 40
    for path in paths:
        with pytest.raises(SystemExit) as exit_:
            cli.main([*path, "--help"])
        assert exit_.value.code == 0, path
        out = capsys.readouterr().out
        assert out.startswith("usage: artzain" + "".join(f" {p}" for p in path)), (path, out[:80])


@pytest.mark.parametrize(("argv", "command", "parsed"), [
    (["quickstart"], "cmd_quickstart", {"command": "quickstart"}),
    (["init", "-f", "mcp", "--force"], "cmd_init",
     {"command": "init", "framework": "mcp", "output": None, "force": True}),
    (["gui", "--port", "8123"], "cmd_gui", {"command": "gui", "port": 8123, "no_browser": False}),
    (["audit", "verify", "b.zip", "--json"], "cmd_audit_verify",
     {"command": "audit", "audit_command": "verify", "bundle": "b.zip", "json": True,
      "root_fingerprint": None}),
    (["audit", "export", "--from", "2026-01-01"], "cmd_audit_export",
     {"command": "audit", "audit_command": "export", "profile": None, "from_": "2026-01-01",
      "to": None, "out": None}),
    (["licence", "install", "c.json", "--offline-only"], "cmd_licence_install",
     {"command": "licence", "licence_command": "install", "certificate": "c.json",
      "chain": None, "root_key": None, "issuing": None, "root_fingerprint": None,
      "offline_only": True, "dir": None, "base_url": None, "allow_remote": False}),
    (["licence", "anchors"], "cmd_licence_anchors",
     {"command": "licence", "licence_command": "anchors", "out": "anchors.json", "limit": 1000,
      "base_url": None, "allow_remote": False}),
    (["policy", "diff", "a1", "b2"], "cmd_policy_diff",
     {"command": "policy", "policy_command": "diff", "a": "a1", "b": "b2"}),
    (["registry", "findings"], "cmd_registry_findings",
     {"command": "registry", "registry_command": "findings", "status": "open", "kind": None,
      "json": False}),
    (["local", "activate", "c.json", "--chain", "ch.json"], "cmd_local_activate",
     {"command": "local", "local_command": "activate", "certificate": "c.json",
      "chain": "ch.json", "root_key": None, "issuing": None, "root_fingerprint": None}),
    (["local", "up", "--no-browser"], "cmd_local_up",
     {"command": "local", "local_command": "up", "manifest": None, "no_browser": True,
      "port": None}),
    (["openshell", "sidecar"], "cmd_openshell_sidecar",
     {"command": "openshell", "openshell_command": "sidecar"}),
    (["connect", "openshell", "up", "--port", "9000"], "cmd_connect_openshell",
     {"command": "connect", "connect_runtime": "openshell", "connect_command": "up",
      "config_digest": "", "engine": "https://app.cognexuslabs.ai", "proxy": "",
      "ca_bundle": "", "port": 9000, "install_openshell": False}),
    (["connect", "openshell", "doctor", "--json"], "cmd_connect_openshell",
     {"command": "connect", "connect_runtime": "openshell", "connect_command": "doctor",
      "json": True}),
])
def test_the_parsed_arguments_reach_the_command(monkeypatch, argv, command, parsed):
    """The function is looked up when ``main`` runs, so a patched one is the
    one called, once, with the parsed arguments."""
    calls: list[argparse.Namespace] = []
    monkeypatch.setattr(cli, command, calls.append)
    cli.main(argv)
    (args,) = calls
    seen = vars(args)
    assert seen.pop("func") == calls.append
    assert seen == parsed


def _recapture() -> None:
    GOLDEN.write_text(json.dumps(_describe(_built_parser()), indent=1, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    _recapture()
