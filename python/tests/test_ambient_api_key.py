"""A key exported in the developer's shell reaches no test through the environment.

``conftest.py`` tells developers to export ``COGNEXUS_API_KEY`` to run
``test_api_key_integration.py``. Each test here starts pytest in a child
process with ``COGNEXUS_API_KEY``, ``MYAPP_API_KEY`` and
``COGNEXUS_API_BASE_URL`` exported, as that shell would start the suite, and
checks what the tests in it are given. The exported host is a loopback port,
so a test that leaked in the child would send nothing off this machine.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parents[1]
_SRC_DIR = _PKG_DIR / "src"

_EXPORTED = {
    "COGNEXUS_API_KEY": "cnx_exported_in_the_shell_0000000",
    "MYAPP_API_KEY": "cnx_exported_in_the_shell_1111111",
    "COGNEXUS_API_BASE_URL": "http://127.0.0.1:9",
}

_PROBE = f"""
import os
import unittest
from pathlib import Path

import pytest

from artzain import cloud

NAMES = {sorted(_EXPORTED)!r}


def exported():
    return [name for name in NAMES if name in os.environ]


# Read at import, as test_api_key_integration.py reads its key. That the child
# started with all three is the premise of every other test here.
AT_IMPORT = exported()


# Autouse: set up with the first test, after the suite's session fixtures and
# before any module-scoped one.
@pytest.fixture(autouse=True, scope="session")
def exported_at_session_setup():
    return exported()


@pytest.fixture(scope="module")
def exported_at_module_setup():
    return exported()


def test_the_probe_runs_this_tree():
    assert Path(cloud.__file__).resolve().is_relative_to(Path({str(_SRC_DIR)!r}).resolve())


def test_code_run_at_import_sees_them():
    assert AT_IMPORT == NAMES


def test_no_test_and_no_session_or_module_fixture_sees_them(
    exported_at_session_setup, exported_at_module_setup
):
    assert (exported_at_session_setup, exported_at_module_setup, exported()) == ([], [], [])


def test_no_key_and_no_host_are_resolved():
    creds = cloud._resolve()
    assert (creds.api_key, creds.base_source) == (None, "default")


class UnittestStyle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exported_at_class_setup = exported()

    def test_neither_set_up_class_nor_the_test_sees_them(self):
        self.assertEqual((self.exported_at_class_setup, exported()), ([], []))


@pytest.fixture(scope="class")
def class_key():
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("COGNEXUS_API_KEY", "cnx_set_up_for_a_class_000000")
        yield


@pytest.mark.usefixtures("class_key")
class TestAKeyThatClassSetupSets:
    def test_its_tests_still_see_it(self):
        assert os.environ.get("COGNEXUS_API_KEY") == "cnx_set_up_for_a_class_000000"


def test_code_under_test_sets_a_key_in_the_environment():
    os.environ["COGNEXUS_API_KEY"] = "cnx_set_by_code_under_test_0000"


def test_the_next_test_does_not_see_it():
    assert exported() == []
"""


def _child_pytest(*args: str, exported: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """``python -m pytest *args`` from the package directory, started with
    the variables of *exported* exported."""
    env = {name: value for name, value in os.environ.items() if name != "PYTEST_ADDOPTS"}
    env.update(exported)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(_SRC_DIR), str(_PKG_DIR), env.get("PYTHONPATH")])
    )
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *args],
        cwd=str(_PKG_DIR),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def test_an_exported_key_reaches_no_test(tmp_path: Path) -> None:
    """The suite's fixtures, loaded from ``tests/conftest.py``, keep the key
    and the host the shell exported from the session: code run at import sees
    them, but a test, a session- or module-scoped fixture, a unittest
    ``setUpClass``, and a test run after one whose code put a key in
    ``os.environ`` see none. A key that a class's own setup puts there stays
    for its tests."""
    probe = tmp_path / "test_probe.py"
    probe.write_text(_PROBE, encoding="utf-8")
    ini = tmp_path / "pytest.ini"
    ini.write_text("[pytest]\n", encoding="utf-8")
    # The probe's tests run in file order: one of them writes a key for the
    # next to not see, so pytest-randomly is kept out.
    proc = _child_pytest(
        "-p", "tests.conftest", "-p", "no:randomly",
        "-c", str(ini), "--confcutdir", str(tmp_path), str(probe),
        exported=_EXPORTED,
    )
    assert proc.returncode == 0 and "8 passed" in proc.stdout, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    "exported",
    [
        pytest.param(_EXPORTED, id="as-documented"),
        # As in the SDK, a blank COGNEXUS_API_KEY falls back to MYAPP_API_KEY.
        pytest.param({**_EXPORTED, "COGNEXUS_API_KEY": "   "}, id="blank-primary-key"),
    ],
)
def test_the_integration_tests_still_run_with_an_exported_key(exported: dict[str, str]) -> None:
    """``test_api_key_integration.py`` reads the key when it is imported, so
    it runs, and its post is captured, with the variables cleared."""
    proc = _child_pytest(
        "tests/test_api_key_integration.py::test_static_prompt_audit_flags_weak_prompt",
        exported=exported,
    )
    assert proc.returncode == 0 and "1 passed" in proc.stdout, proc.stdout + proc.stderr
