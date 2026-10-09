"""``artzain.openshell`` is the SDK's own, and runs on the standard library.

The sidecar is installed beside a customer's gateway, from the public
package. It must not need the engine's code to import, and the parts that
decide, report and talk to the engine must not need anything that
``pip install artzain`` does not bring. gRPC, protobuf and ``cryptography``
come with the ``[openshell]`` extra and are needed only by the gRPC servicer.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import artzain.openshell

PACKAGE = Path(artzain.openshell.__file__).resolve().parent
#: The engine's top-level packages. None of them is in the SDK.
ENGINE = {"api", "application", "connectors", "domain", "security", "services"}
#: What the ``[openshell]`` extra installs, and the OpenShell SDK itself.
EXTRA = {"cryptography", "google", "grpc", "openshell"}
#: The modules that import the extra at all, and only inside a function or
#: behind the servicer.
MAY_USE_THE_EXTRA = {"servicer.py", "_wire.py", "sidecar.py"}
#: Standard library from Python 3.11 on, which the SDK's 3.10 floor does not
#: name. ``connect`` imports it inside the functions that need it, after
#: refusing to run on 3.10.
STDLIB_FROM_3_11 = {"tomllib"}


def _imports(path):
    """``(top-level name, at module level)`` for every import in *path*."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    top_level = {id(node) for node in tree.body}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{path.name}: a relative import"
            names = [node.module or ""]
        else:
            continue
        for name in names:
            yield name.split(".")[0], id(node) in top_level


def _modules():
    return sorted(PACKAGE.glob("*.py"))


def test_the_package_has_the_modules_this_test_knows():
    assert {path.name for path in _modules()} == {
        "__init__.py", "_wire.py", "base_policy.py", "bootstrap.py", "breakglass.py", "connect.py",
        "interceptor.py",
        "journal.py", "registration.py", "servicer.py", "sidecar.py", "state.py",
        "templates.py", "transport.py"}


@pytest.mark.parametrize("path", _modules(), ids=lambda path: path.name)
def test_no_module_imports_the_engine(path):
    assert {name for name, _top in _imports(path)} & ENGINE == set()


@pytest.mark.parametrize("path", _modules(), ids=lambda path: path.name)
def test_every_import_is_the_standard_library_the_sdk_or_the_extra(path):
    allowed = set(sys.stdlib_module_names) | {"artzain", "__future__"} | STDLIB_FROM_3_11
    if path.name in MAY_USE_THE_EXTRA:
        allowed |= EXTRA
    assert {name for name, _top in _imports(path)} - allowed == set()


@pytest.mark.parametrize("name", ["sidecar.py", "transport.py", "journal.py", "state.py",
                                  "interceptor.py", "base_policy.py", "__init__.py",
                                  "registration.py", "connect.py", "templates.py",
                                  "breakglass.py"])
def test_importing_the_sidecar_needs_nothing_but_the_standard_library(name):
    at_module_level = {module for module, top in _imports(PACKAGE / name) if top}
    assert at_module_level - set(sys.stdlib_module_names) - {"artzain", "__future__"} == set()


def test_the_sidecar_imports_with_the_extra_and_the_engine_out_of_reach():
    """In a new interpreter, with every optional and engine package made
    unimportable: the sidecar, its client and its journal still import."""
    blocked = sorted(ENGINE | EXTRA)
    code = (
        "import sys\n"
        "class Blocked:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        f"        if name.split('.')[0] in {blocked!r}:\n"
        "            raise ImportError('blocked for the test: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocked())\n"
        "from artzain.openshell import sidecar, transport, journal, state, base_policy\n"
        "from artzain.openshell import connect, registration\n"
        "from artzain.openshell import interceptor, breakglass\n"
        f"assert not set(sys.modules) & set({blocked!r}), sorted(set(sys.modules) & set({blocked!r}))\n"
        "print('imported')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            timeout=120, env=_environment())
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


def _environment():
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = str(PACKAGE.parents[1])
    return env
