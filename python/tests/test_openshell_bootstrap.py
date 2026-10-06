"""The connect script: one command that installs ``artzain`` and runs
``artzain connect openshell up``.

``artzain.openshell.bootstrap`` renders ``connect-<version>.sh``, which each
``python-v<version>`` release publishes. These tests hold what it says and,
on a POSIX host, run it under ``sh`` with stand-ins for ``uname``, ``id``,
``curl``, ``tar``, ``sha256sum`` and uv on ``PATH``:

* it refuses another OS, another machine, and root;
* it runs the uv it downloaded only when its SHA-256 is the pinned one;
* it installs ``artzain`` and what it needs into an environment of its own,
  on a Python uv manages, every wheel named by its SHA-256 (0.6.41: uv's
  tool install does not check hashes), and passes its own arguments to
  ``connect openshell up``;
* after a good ``up`` it points ``~/.local/bin/artzain`` there, and takes
  away an earlier version's environment and uv tool;
* ``ARTZAIN_PACKAGE`` replaces the artzain it installs, to try a build;
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

VERSION = "0.6.41"
WHEEL = "ab" * 32
FILE = Path(bootstrap.__file__)
#: The image's lock: what the deb connect installs is what the image runs. It
#: sits in the engine's seed templates, or at the mirror's root once seeded.
_ROOT = Path(__file__).resolve().parents[2]
IMAGE_LOCKS = [path for path in (
    _ROOT / "scripts" / "cognexus-tools-seed" / "images" / "openshell-sidecar" / "requirements.lock",
    _ROOT / "images" / "openshell-sidecar" / "requirements.lock",
) if path.is_file()]


def test_the_script_names_its_version_and_the_pinned_uv():
    script = bootstrap.render(VERSION, WHEEL)
    assert script.startswith("#!/bin/sh\n") and "\nset -eu\n" in script
    assert f'ARTZAIN_VERSION="{VERSION}"' in script
    assert f'UV_VERSION="{bootstrap.UV_VERSION}"' in script
    for arch, digest in bootstrap.UV_SHA256.items():
        assert f'arch={arch}; uv_sha256="{digest}"' in script
    assert re.search(r"@[A-Z0-9_]+@", script) is None  # every placeholder filled
    assert "\r" not in script
    assert "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/$asset" in script
    assert "--proto '=https' --tlsv1.2" in script


def test_the_script_carries_every_wheel_by_its_sha256():
    """What it installs is named, wheel by wheel: the dependencies as the
    sidecar image installs them, and artzain by the hash its release gave."""
    script = bootstrap.render(VERSION, WHEEL)
    lock = bootstrap.REQUIREMENTS.read_text(encoding="utf-8")
    assert lock.rstrip("\n") + "\nARTZAIN_LOCK\n" in script
    assert f"artzain=={VERSION} \\\n    --hash=sha256:{WHEEL}\nARTZAIN_LOCK\n" in script
    assert "uv\" tool install" not in script


def test_the_sdk_installs_what_the_image_installs():
    """One set of dependency wheels, held in two places: the image builds
    from its own folder, the connect script from the SDK's. In the engine's
    tree and the mirror's alike."""
    if not IMAGE_LOCKS:
        pytest.skip("no image folder beside this checkout")
    for image_lock in IMAGE_LOCKS:
        assert bootstrap.REQUIREMENTS.read_bytes() == image_lock.read_bytes(), image_lock
    assert "--hash=sha256:" in bootstrap.REQUIREMENTS.read_text(encoding="utf-8")


def test_the_python_is_the_one_the_lock_was_made_for():
    assert f"on Python {bootstrap.PYTHON}." in bootstrap.REQUIREMENTS.read_text(encoding="utf-8")


@pytest.mark.parametrize("version", ["", "0.6", "0.6.41a", "0.6.41; rm -rf /", " 0.6.41",
                                     "0.6.40", "0.5.99"])
def test_a_version_that_is_not_one_with_a_locked_install_is_refused(version):
    with pytest.raises(ValueError):
        bootstrap.render(version, WHEEL)


@pytest.mark.parametrize("wheel", ["", "AB" * 32, "ab" * 31, "ab" * 32 + "\n", "zz" * 32])
def test_a_wheel_hash_that_is_not_a_sha256_is_refused(wheel):
    with pytest.raises(ValueError):
        bootstrap.render(VERSION, wheel)


@pytest.mark.parametrize("version", ["0.6.41", "0.7.0", "1.0.0"])
def test_each_version_with_a_locked_install_renders(version):
    assert f'ARTZAIN_VERSION="{version}"' in bootstrap.render(version, WHEEL)


def test_the_digest_is_the_scripts_own():
    assert bootstrap.sha256(VERSION, WHEEL) == hashlib.sha256(
        bootstrap.render(VERSION, WHEEL).encode("utf-8")).hexdigest()
    assert bootstrap.sha256(VERSION, WHEEL) == bootstrap.sha256(VERSION, WHEEL)
    assert bootstrap.sha256(VERSION, WHEEL) != bootstrap.sha256("0.6.42", WHEEL)
    assert bootstrap.sha256(VERSION, WHEEL) != bootstrap.sha256(VERSION, "cd" * 32)


def test_the_file_prints_the_script_and_needs_nothing_but_the_standard_library():
    """The release job runs it by its path, with no artzain installed."""
    done = subprocess.run([sys.executable, "-I", str(FILE), VERSION, WHEEL],
                          capture_output=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout == bootstrap.render(VERSION, WHEEL).encode("utf-8")
    for bad in ([], [VERSION], ["0.6", WHEEL], [VERSION, "nothex"], [VERSION, WHEEL, "x"]):
        refused = subprocess.run([sys.executable, "-I", str(FILE), *bad], capture_output=True,
                                 timeout=60, check=False)
        assert refused.returncode == 2 and refused.stdout == b"", bad


def test_the_file_imports_only_the_standard_library():
    import ast

    tree = ast.parse(FILE.read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom)}
    assert imported <= {"__future__", "hashlib", "pathlib", "re", "sys"}


def _sh():
    return shutil.which("sh") if sys.platform != "win32" else None


def test_the_script_is_valid_shell():
    shell = _sh() or shutil.which("bash")
    if not shell:
        pytest.skip("no shell")
    done = subprocess.run([shell, "-n"], input=bootstrap.render(VERSION, WHEEL).encode("utf-8"),
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
    """A PATH of stand-ins, each recording its arguments in ``log``.

    The uv the archive holds makes an environment for ``venv``: a ``python``
    that says whether artzain is installed there, and, once ``pip install``
    has installed artzain, an ``artzain`` that ends with *up_status*. Each
    lock file it is given is kept in ``locks``. ``tool list`` names an
    artzain when *old_tool* is set."""

    def __init__(self, root: Path, *, system="Linux", machine="x86_64", uid="1000",
                 digest=None, up_status=0, installs=True, old_tool=False):
        self.root, self.bin, self.log = root, root / "bin", root / "log"
        self.tmp, self.locks = root / "tmp", root / "locks"
        self.data = root / ".local" / "share" / "artzain" / "openshell"
        self.venv = self.data / f"venv-{VERSION}"
        self.link = root / ".local" / "bin" / "artzain"
        for folder in (self.bin, self.tmp, self.locks):
            folder.mkdir()
        self.log.write_text("", encoding="utf-8")
        arch = machine.replace("amd64", "x86_64").replace("arm64", "aarch64")
        digest = digest or bootstrap.UV_SHA256.get(arch, "0" * 64)
        log, locks = self.log.as_posix(), self.locks.as_posix()
        _stub(self.bin, "uname", '[ "$1" = -s ] && echo ' + system + " || echo " + machine)
        _stub(self.bin, "id", "echo " + uid)
        _stub(self.bin, "sha256sum", 'echo "' + digest + '  $1"')
        lines = chr(10).join  # one shell line each
        _stub(self.bin, "curl", lines([
            'echo "curl $*" >> ' + log,
            'while [ $# -gt 1 ]; do [ "$1" = -o ] && out="$2"; shift; done',
            'echo uv-archive > "$out"']))
        up = lines(['#!/bin/sh', 'echo "artzain $*" >> ' + log,
                    'echo "argc $#" >> ' + log,
                    'echo "token-length ${#ARTZAIN_ENROLL_TOKEN}" >> ' + log,
                    "exit " + str(up_status)])
        (self.root / "up.sh").write_text(up + "\n", encoding="utf-8")
        python = lines(['#!/bin/sh', 'echo "python $*" >> ' + log,
                        '[ -f "$(dirname "$0")/../installed" ]'])
        (self.root / "python.sh").write_text(python + "\n", encoding="utf-8")
        uv = [
            "#!/bin/sh",
            'echo "uv $*" >> ' + log,
            # As uv 0.8.15 does: an environment is kept as it is, and a
            # folder that is not one is refused.
            'if [ "$1" = venv ]; then for v; do venv="$v"; done;'
            ' if [ -e "$venv" ] && [ ! -f "$venv/pyvenv.cfg" ]; then'
            ' echo "error: A directory already exists at: $venv" >&2; exit 2; fi;'
            ' mkdir -p "$venv/bin"; touch "$venv/pyvenv.cfg";'
            ' cp ' + (self.root / "python.sh").as_posix() + ' "$venv/bin/python";'
            ' chmod +x "$venv/bin/python"; fi',
            'if [ "$1 $2" = "pip install" ]; then'
            ' while [ $# -gt 0 ]; do case "$1" in'
            ' --python) py="$2"; shift;;'
            ' -r) cp "$2" ' + locks + '/"$(basename "$2")"; req="$2"; shift;;'
            ' *) last="$1";; esac; shift; done;'
            ' venv="$(dirname "$(dirname "$py")")";'
            ' if [ "' + ("1" if installs else "0") + '" = 1 ] && { [ "${req##*/}" = artzain.lock ]'
            ' || [ "$last" = "$ARTZAIN_PACKAGE" ]; }; then'
            ' cp ' + (self.root / "up.sh").as_posix() + ' "$venv/bin/artzain";'
            ' chmod +x "$venv/bin/artzain"; touch "$venv/installed"; fi; fi',
            'if [ "$1 $2" = "tool list" ]; then ' + (
                'echo "artzain v0.6.40"; echo "- artzain"' if old_tool
                else 'echo "No tools installed"') + "; fi",
        ]
        _stub(self.bin, "tar", lines([
            'echo "tar $*" >> ' + log,
            'while [ $# -gt 1 ]; do [ "$1" = -C ] && to="$2"; shift; done',
            'd="$to/uv-' + arch + '-unknown-linux-musl"; mkdir -p "$d"',
            "printf '%s" + chr(92) + "n' " + " ".join("'" + line + "'" for line in uv)
            + ' > "$d/uv"',
            'chmod +x "$d/uv"']))

    def run(self, *args, env=None):
        script = self.root / "connect.sh"
        script.write_bytes(bootstrap.render(VERSION, WHEEL).encode("utf-8"))
        environ = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root),
                   "TMPDIR": str(self.tmp)}
        environ.update(env or {})
        return subprocess.run([_sh(), str(script), *args], capture_output=True, text=True,
                              env=environ, timeout=60, check=False)

    def calls(self, name):
        return [line[len(name) + 1:] for line in self.log.read_text(encoding="utf-8").splitlines()
                if line.startswith(name + " ")]


def _locked(venv):
    python = f"{venv}/bin/python"
    return [f"venv --quiet --managed-python --python {bootstrap.PYTHON} {venv}",
            f"pip install --quiet --python {python} --require-hashes --only-binary :all: -r",
            f"pip install --quiet --python {python} --no-deps --require-hashes "
            "--only-binary :all: -r"]


def _uv_calls(host):
    """uv's calls, each lock file's temporary path cut off."""
    return [re.sub(r" -r \S+$", " -r", call) for call in host.calls("uv")]


@needs_posix_sh
def test_it_installs_every_wheel_by_its_hash_and_runs_up_with_its_arguments(tmp_path):
    host = _Host(tmp_path)
    done = host.run("--config-digest", "ab" * 32, "--engine", "https://engine.example",
                    "--ca-bundle", "/etc/our certs/ca.pem")
    assert done.returncode == 0, done.stderr
    [download] = host.calls("curl")
    assert download.startswith("--proto =https --tlsv1.2 -fsSL -o ")
    assert download.endswith("https://github.com/astral-sh/uv/releases/download/"
                             f"{bootstrap.UV_VERSION}/uv-x86_64-unknown-linux-musl.tar.gz")
    assert _uv_calls(host) == _locked(host.venv) + ["tool list"]
    # The two lock files it was given: the dependencies, and artzain itself.
    assert (host.locks / "requirements.lock").read_text(encoding="utf-8") == (
        bootstrap.REQUIREMENTS.read_text(encoding="utf-8"))
    assert (host.locks / "artzain.lock").read_text(encoding="utf-8") == (
        f"artzain=={VERSION} \\\n    --hash=sha256:{WHEEL}\n")
    assert host.calls("artzain") == [
        "connect openshell up --config-digest " + "ab" * 32 + " --engine https://engine.example"
        " --ca-bundle /etc/our certs/ca.pem"]
    assert host.calls("argc") == ["9"]  # an argument with a space in it stays one
    assert host.link.is_symlink() and Path(host.link.resolve()) == (host.venv / "bin" / "artzain").resolve()
    assert f"artzain is {host.link}" in done.stderr
    assert list(host.tmp.iterdir()) == []  # its folder is gone


@needs_posix_sh
def test_after_a_good_up_an_earlier_install_goes(tmp_path):
    """0.6.40 and earlier installed artzain as a uv tool, and a later
    script into an environment of its own: once `up` has moved the service
    here, neither is left behind."""
    host = _Host(tmp_path, old_tool=True)
    older = host.data / "venv-0.6.40"
    (older / "bin").mkdir(parents=True)
    done = host.run()
    assert done.returncode == 0, done.stderr
    assert _uv_calls(host)[-2:] == ["tool list", "tool uninstall artzain"]
    assert not older.exists() and host.venv.is_dir()


@needs_posix_sh
def test_after_an_up_that_failed_the_earlier_install_stays(tmp_path):
    """The service may still run from it."""
    host = _Host(tmp_path, old_tool=True, up_status=3)
    older = host.data / "venv-0.6.40"
    (older / "bin").mkdir(parents=True)
    done = host.run()
    assert done.returncode == 3
    assert "tool list" not in _uv_calls(host) and older.is_dir()
    assert not host.link.exists()
    assert f"artzain is {host.venv}/bin/artzain" in done.stderr  # still says where it is
    assert list(host.tmp.iterdir()) == []


@needs_posix_sh
def test_this_version_installed_already_is_used_as_it_is(tmp_path):
    """Running the script again does not pull the service's files away from
    under it."""
    host = _Host(tmp_path)
    assert host.run().returncode == 0
    first = len(host.calls("uv"))
    done = host.run()
    assert done.returncode == 0, done.stderr
    assert not any(call.startswith(("venv", "pip")) for call in host.calls("uv")[first:])
    assert "installed in" in done.stderr


@needs_posix_sh
def test_an_environment_that_does_not_hold_this_artzain_is_made_again(tmp_path):
    """An install that stopped part way leaves a folder that is not a whole
    environment: it goes, and a new one is made (uv makes none over it)."""
    host = _Host(tmp_path)
    (host.venv / "bin").mkdir(parents=True)
    (host.venv / "bin" / "stray").write_text("left over", encoding="utf-8")
    done = host.run()
    assert done.returncode == 0, done.stderr
    assert not (host.venv / "bin" / "stray").exists()
    assert (host.venv / "bin" / "artzain").exists()


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
    for tool in ("mktemp", "dirname", "basename", "cp", "chmod", "mkdir", "touch", "rm", "ln",
                 "cat", "grep"):
        found = shutil.which(tool)
        if found and not (host.bin / tool).exists():
            (host.bin / tool).symlink_to(found)
    (host.bin / missing).unlink(missing_ok=True)
    done = host.run(env={"PATH": str(host.bin)})  # the stand-ins, and nothing else
    assert done.returncode == 1 and says in done.stderr, done.stderr
    assert host.calls("curl") == [] and host.calls("uv") == []


@needs_posix_sh
def test_a_build_under_test_is_installed_in_place_of_the_published_one(tmp_path):
    """The dependencies stay the locked ones; only artzain is the build."""
    host = _Host(tmp_path)
    wheel = "artzain[openshell] @ file:///work/artzain-0.6.41-py3-none-any.whl"
    assert host.run(env={"ARTZAIN_PACKAGE": wheel}).returncode == 0
    python = f"{host.venv}/bin/python"
    assert _uv_calls(host)[:3] == _locked(host.venv)[:2] + [
        f"pip install --quiet --python {python} --no-deps {wheel}"]
    # Each run installs the build again, even over one of the same version.
    first = len(host.calls("uv"))
    assert host.run(env={"ARTZAIN_PACKAGE": wheel}).returncode == 0
    assert any(call.startswith("pip install") for call in host.calls("uv")[first:])


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
