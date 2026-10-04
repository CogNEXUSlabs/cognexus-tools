"""The connect script: one command that installs ``artzain`` and runs
``artzain connect openshell up``.

``artzain.openshell.bootstrap`` renders ``connect-<version>.sh``, which each
``python-v<version>`` release publishes. These tests hold what it says and,
on a POSIX host, run it under ``sh`` with stand-ins for ``uname``, ``id``,
``curl``, ``tar``, ``sha256sum`` and uv on ``PATH``:

* it refuses another OS, another machine, and root;
* it runs the uv it downloaded only when its SHA-256 is the pinned one;
* it installs ``artzain[openshell]==<version>`` as a uv tool, on a Python
  uv manages, and passes its own arguments to ``connect openshell up``;
* ``ARTZAIN_PACKAGE`` replaces what it installs, to try a build;
* it ends with the status ``up`` ended with, and leaves no folder behind.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from artzain.openshell import bootstrap

VERSION = "0.6.37"
FILE = Path(bootstrap.__file__)


def test_the_script_names_its_version_and_the_pinned_uv():
    script = bootstrap.render(VERSION)
    assert script.startswith("#!/bin/sh\n") and "\nset -eu\n" in script
    assert f'ARTZAIN_VERSION="{VERSION}"' in script
    assert f'UV_VERSION="{bootstrap.UV_VERSION}"' in script
    for arch, digest in bootstrap.UV_SHA256.items():
        assert f'arch={arch}; uv_sha256="{digest}"' in script
    assert re.search(r"@[A-Z0-9_]+@", script) is None  # every placeholder filled
    assert "\r" not in script
    assert "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/$asset" in script
    assert "--proto '=https' --tlsv1.2" in script


@pytest.mark.parametrize("version", ["", "0.6", "0.6.37a", "0.6.37; rm -rf /", " 0.6.37",
                                     "0.6.35", "0.5.99"])
def test_a_version_that_is_not_one_with_connect_is_refused(version):
    with pytest.raises(ValueError):
        bootstrap.render(version)


@pytest.mark.parametrize("version", ["0.6.36", "0.7.0", "1.0.0"])
def test_each_version_with_connect_renders(version):
    assert f'ARTZAIN_VERSION="{version}"' in bootstrap.render(version)


def test_the_digest_is_the_scripts_own():
    assert bootstrap.sha256(VERSION) == hashlib.sha256(
        bootstrap.render(VERSION).encode("utf-8")).hexdigest()
    assert bootstrap.sha256(VERSION) == bootstrap.sha256(VERSION)  # one script per version
    assert bootstrap.sha256(VERSION) != bootstrap.sha256("0.6.38")


def test_the_file_prints_the_script_and_needs_nothing_but_the_standard_library():
    """The release job runs it by its path, with no artzain installed."""
    done = subprocess.run([sys.executable, "-I", str(FILE), VERSION], capture_output=True,
                          timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout == bootstrap.render(VERSION).encode("utf-8")
    for bad in ([], ["0.6"], [VERSION, "extra"]):
        refused = subprocess.run([sys.executable, "-I", str(FILE), *bad], capture_output=True,
                                 timeout=60, check=False)
        assert refused.returncode == 2 and refused.stdout == b""


def test_the_file_imports_only_the_standard_library():
    import ast

    tree = ast.parse(FILE.read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom)}
    assert imported <= {"__future__", "hashlib", "re", "sys"}


def _sh():
    return shutil.which("sh") if sys.platform != "win32" else None


def test_the_script_is_valid_shell():
    shell = _sh() or shutil.which("bash")
    if not shell:
        pytest.skip("no shell")
    done = subprocess.run([shell, "-n"], input=bootstrap.render(VERSION).encode("utf-8"),
                          capture_output=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr


# ---------------------------------------------------------------------------
# Running it, with stand-ins on PATH
# ---------------------------------------------------------------------------

needs_posix_sh = pytest.mark.skipif(_sh() is None, reason="a POSIX sh")


def _stub(folder: Path, name: str, body: str) -> None:
    path = folder / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class _Host:
    """A PATH of stand-ins, each recording its arguments in ``log``. The uv
    the archive holds answers ``tool dir --bin`` with ``tools``, where an
    ``artzain`` waits that ends with *up_status*."""

    def __init__(self, root: Path, *, system="Linux", machine="x86_64", uid="1000",
                 digest=None, up_status=0, installs=True):
        self.root, self.bin, self.log = root, root / "bin", root / "log"
        self.tools, self.tmp = root / "tools", root / "tmp"
        for folder in (self.bin, self.tools, self.tmp):
            folder.mkdir()
        self.log.write_text("", encoding="utf-8")
        arch = machine.replace("amd64", "x86_64").replace("arm64", "aarch64")
        digest = digest or bootstrap.UV_SHA256.get(arch, "0" * 64)
        log, tools = self.log.as_posix(), self.tools.as_posix()
        _stub(self.bin, "uname", '[ "$1" = -s ] && echo ' + system + " || echo " + machine)
        _stub(self.bin, "id", "echo " + uid)
        _stub(self.bin, "sha256sum", 'echo "' + digest + '  $1"')
        lines = chr(10).join  # one shell line each
        _stub(self.bin, "curl", lines([
            'echo "curl $*" >> ' + log,
            'while [ $# -gt 1 ]; do [ "$1" = -o ] && out="$2"; shift; done',
            'echo uv-archive > "$out"']))
        uv = ["#!/bin/sh", 'echo "uv $*" >> ' + log,
              'if [ "$1 $2" = "tool dir" ]; then echo ' + tools + "; fi"]
        _stub(self.bin, "tar", lines([
            'echo "tar $*" >> ' + log,
            'while [ $# -gt 1 ]; do [ "$1" = -C ] && to="$2"; shift; done',
            'd="$to/uv-' + arch + '-unknown-linux-musl"; mkdir -p "$d"',
            "printf '%s" + chr(92) + "n' " + " ".join("'" + line + "'" for line in uv)
            + ' > "$d/uv"',
            'chmod +x "$d/uv"']))
        if installs:
            _stub(self.tools, "artzain", lines([
                'echo "artzain $*" >> ' + log,
                'echo "argc $#" >> ' + log,
                'echo "token-length ${#ARTZAIN_ENROLL_TOKEN}" >> ' + log,
                "exit " + str(up_status)]))

    def run(self, *args, env=None):
        script = self.root / "connect.sh"
        script.write_bytes(bootstrap.render(VERSION).encode("utf-8"))
        environ = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root),
                   "TMPDIR": str(self.tmp)}
        environ.update(env or {})
        return subprocess.run([_sh(), str(script), *args], capture_output=True, text=True,
                              env=environ, timeout=60, check=False)

    def calls(self, name):
        return [line[len(name) + 1:] for line in self.log.read_text(encoding="utf-8").splitlines()
                if line.startswith(name + " ")]


@needs_posix_sh
def test_it_installs_the_pinned_artzain_and_runs_up_with_its_arguments(tmp_path):
    host = _Host(tmp_path)
    done = host.run("--config-digest", "ab" * 32, "--engine", "https://engine.example",
                    "--ca-bundle", "/etc/our certs/ca.pem")
    assert done.returncode == 0, done.stderr
    [download] = host.calls("curl")
    assert download.startswith("--proto =https --tlsv1.2 -fsSL -o ")
    assert download.endswith("https://github.com/astral-sh/uv/releases/download/"
                             f"{bootstrap.UV_VERSION}/uv-x86_64-unknown-linux-musl.tar.gz")
    assert host.calls("uv") == [
        f"tool install --force --managed-python --python >=3.11 artzain[openshell]=={VERSION}",
        "tool dir --bin"]
    assert host.calls("artzain") == [
        "connect openshell up --config-digest " + "ab" * 32 + " --engine https://engine.example"
        " --ca-bundle /etc/our certs/ca.pem"]
    assert host.calls("argc") == ["9"]  # an argument with a space in it stays one
    assert f"artzain is {host.tools}/artzain" in done.stderr
    assert list(host.tmp.iterdir()) == []  # its folder is gone


@needs_posix_sh
@pytest.mark.parametrize("machine, arch", [("amd64", "x86_64"), ("aarch64", "aarch64"),
                                           ("arm64", "aarch64")])
def test_each_machine_gets_its_own_pinned_build(tmp_path, machine, arch):
    host = _Host(tmp_path, machine=machine)
    assert host.run().returncode == 0
    assert host.calls("curl")[0].endswith(f"/uv-{arch}-unknown-linux-musl.tar.gz")


@needs_posix_sh
def test_a_download_that_is_not_the_pinned_build_is_not_run(tmp_path):
    host = _Host(tmp_path, digest="f" * 64)
    done = host.run()
    assert done.returncode == 1
    assert "is not the build its SHA-256 names: not running it" in done.stderr
    assert host.calls("tar") == [] and host.calls("uv") == [] and host.calls("artzain") == []
    assert list(host.tmp.iterdir()) == []


@needs_posix_sh
@pytest.mark.parametrize("change, says", [
    ({"system": "Darwin"}, "on Linux"),
    ({"machine": "riscv64"}, "no pinned uv for riscv64"),
    ({"uid": "0"}, "not as root"),
], ids=["macos", "riscv", "root"])
def test_a_host_it_does_not_connect_is_refused_before_anything_is_fetched(tmp_path, change,
                                                                          says):
    host = _Host(tmp_path, **change)
    done = host.run()
    assert done.returncode == 1 and says in done.stderr
    assert host.calls("curl") == []


@needs_posix_sh
@pytest.mark.parametrize("missing, says", [
    ("curl", "curl is needed"), ("tar", "tar is needed"), ("mktemp", "mktemp is needed"),
    ("sha256sum", "sha256sum or shasum is needed")])
def test_a_host_without_a_tool_it_needs_is_told_so_before_anything_is_fetched(tmp_path, missing,
                                                                               says):
    host = _Host(tmp_path)
    mktemp = shutil.which("mktemp")
    if mktemp:
        (host.bin / "mktemp").symlink_to(mktemp)
    (host.bin / missing).unlink(missing_ok=True)
    done = host.run(env={"PATH": str(host.bin)})  # the stand-ins, and nothing else
    assert done.returncode == 1 and says in done.stderr, done.stderr
    assert host.calls("curl") == [] and host.calls("uv") == []


@needs_posix_sh
def test_a_build_under_test_is_installed_in_place_of_the_published_one(tmp_path):
    host = _Host(tmp_path)
    wheel = "artzain[openshell] @ file:///work/artzain-0.6.37-py3-none-any.whl"
    assert host.run(env={"ARTZAIN_PACKAGE": wheel}).returncode == 0
    assert host.calls("uv")[0] == f"tool install --force --managed-python --python >=3.11 {wheel}"


@needs_posix_sh
def test_it_ends_as_up_ended(tmp_path):
    host = _Host(tmp_path, up_status=3)
    done = host.run()
    assert done.returncode == 3
    assert "artzain is " in done.stderr  # still says where artzain is
    assert list(host.tmp.iterdir()) == []


@needs_posix_sh
def test_the_token_reaches_up_through_the_environment_only(tmp_path):
    host = _Host(tmp_path)
    token = "cnxt_" + "t" * 43
    done = host.run(env={"ARTZAIN_ENROLL_TOKEN": token})
    assert done.returncode == 0
    assert host.calls("token-length") == [str(len(token))]  # up has it
    assert token not in host.log.read_text(encoding="utf-8")  # and no argument does
    assert token not in done.stdout + done.stderr


@needs_posix_sh
def test_a_uv_that_installs_no_artzain_is_said(tmp_path):
    host = _Host(tmp_path, installs=False)
    done = host.run()
    assert done.returncode == 1 and "uv did not install artzain" in done.stderr
    assert list(host.tmp.iterdir()) == []
