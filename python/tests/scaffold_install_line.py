"""What a Python scaffold's install line names, read from the rendered file.

Each scaffold's docstring tells a developer what to install (``pip install
artzain ...``). CI's scaffold job installs exactly that, printed by this
module, so the framework a scaffold is run against is the one its install line
names, and changing the line changes what CI runs::

    cd pypi-package
    PYTHONPATH=src python tests/scaffold_install_line.py mcp    # one per line

``artzain`` itself is left out: CI runs the checkout's copy.
"""

from __future__ import annotations

import re
import shlex
import sys

from artzain import cli

#: The scaffolds that are Python files with a framework to install.
PYTHON_FRAMEWORKS = ("crewai", "langgraph", "mcp")

#: What a shell treats as an operator when it is not quoted.
_SHELL_OPERATOR = re.compile(r"[<>|;&()]+")

#: What a shell expands in a word that is not quoted: a glob (zsh, the macOS
#: default, refuses one that matches no file) or a substitution.
_SHELL_EXPANSION = re.compile(r"[*?\[\]$`]")


def parse_install_line(line: str) -> list[str]:
    """The packages a ``pip install`` line names, split as sh or bash splits it.

    A ``#`` comment is dropped. A ``<``, ``>``, ``|``, ``;``, ``&`` or
    parenthesis outside quotes is refused, as is a word that a shell would
    glob or substitute (``[``, ``*``, ``?``, ``$``) unless it is quoted: a
    developer pasting the line would not install what CI installs.
    """
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    words = list(lexer)
    operators = [word for word in words if _SHELL_OPERATOR.fullmatch(word)]
    if operators:
        raise ValueError(f"unquoted shell operator {operators[0]!r} in {line!r}")
    # The same split with the quotes kept, to tell a quoted word from a bare one.
    raw = shlex.shlex(line, posix=False, punctuation_chars=True)
    raw.whitespace_split = True
    expanded = [word for word in raw if word[:1] not in "\"'" and _SHELL_EXPANSION.search(word)]
    if expanded:
        raise ValueError(f"unquoted {expanded[0]!r} in {line!r}: a shell would expand it")
    if words[:2] != ["pip", "install"] or len(words) < 3:
        raise ValueError(f"not a pip install line: {line!r}")
    return words[2:]


def without_artzain(names: list[str]) -> list[str]:
    """The requirements other than ``artzain``, which CI takes from the checkout."""
    rest = [name for name in names if re.split(r"[\[<>=!~;@\s]", name, maxsplit=1)[0] != "artzain"]
    if len(rest) == len(names):
        raise ValueError(f"the install line does not name artzain: {names!r}")
    return rest


def install_line(framework: str) -> list[str]:
    """The packages the scaffold's ``pip install`` line names, in order."""
    source = cli.scaffold_contents(framework, "https://engine.example.com")
    lines = [line.strip() for line in source.splitlines()]
    installs = [line for line in lines if line.startswith("pip install ")]
    if len(installs) != 1:
        raise ValueError(f"the {framework} scaffold has {len(installs)} install lines, not one")
    return parse_install_line(installs[0])


def requirements(framework: str) -> list[str]:
    """The install line's requirements other than ``artzain``."""
    return without_artzain(install_line(framework))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in PYTHON_FRAMEWORKS:
        raise SystemExit(f"usage: scaffold_install_line.py {{{','.join(PYTHON_FRAMEWORKS)}}}")
    print("\n".join(requirements(sys.argv[1])))
