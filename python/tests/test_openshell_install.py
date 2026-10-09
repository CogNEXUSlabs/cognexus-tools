"""Installing OpenShell on a host that has none (OpenShell plan S3.2, step 3).

``artzain connect openshell up`` binds the gateway OpenShell's deb or rpm
package installs. On a host without it, ``up`` stopped with "openshell is
not on PATH". :mod:`artzain.openshell.install` installs NVIDIA's packages of
the release this artzain binds, each checked against a SHA-256 this release
pins before anything runs as root, then starts the gateway's user service
and registers it with the CLI, the steps NVIDIA's own ``install.sh`` takes.

These run against :class:`_Bare`, a systemd host with no OpenShell whose
commands are scripted: what ``curl`` fetches, what the package manager
installs, and when the gateway answers.

What has to hold:

* nothing runs as root unless every package is the build its SHA-256 names;
* the packages are the release this artzain is pinned to, for this
  host's architecture and package format;
* without sudo or root, nothing is tried, and the commands are said.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from artzain.openshell import install, interceptor

#: What a download serves, by file name, unless a test says otherwise.
BODY = b"a package"
SHA = hashlib.sha256(BODY).hexdigest()


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def _table(names):
    return tuple((name, SHA) for name in names)


@pytest.fixture(autouse=True)
def pinned(monkeypatch):
    """The pins, as tests can serve them: every package hashes to SHA."""
    monkeypatch.setattr(install, "DEB", {
        "amd64": _table(["openshell_0.1.2-1_amd64.deb"]),
        "arm64": _table(["openshell_0.1.2-1_arm64.deb"])})
    monkeypatch.setattr(install, "RPM", {
        "x86_64": _table(["openshell-0.1.2-1.fc44.x86_64.rpm",
                          "openshell-gateway-0.1.2-1.fc44.x86_64.rpm",
                          "openshell-prover-0.1.2-1.fc44.x86_64.rpm"]),
        "aarch64": _table(["openshell-0.1.2-1.fc44.aarch64.rpm",
                           "openshell-gateway-0.1.2-1.fc44.aarch64.rpm",
                           "openshell-prover-0.1.2-1.fc44.aarch64.rpm"])})


class _Bare:
    """A Debian or Fedora host with systemd and no OpenShell."""

    def __init__(self, kind="deb", arch=None, uid=1000, tools=None):
        self.kind = kind
        self.arch = arch or ("amd64" if kind == "deb" else "x86_64")
        self.uid = uid
        self.tools = set(tools if tools is not None else (
            {"systemctl", "sudo", "curl", "apt-get", "dpkg"} if kind == "deb"
            else {"systemctl", "sudo", "curl", "dnf", "rpm"}))
        self.calls = []
        self.served = {}          # file name -> bytes, over BODY
        self.download_fails = set()
        self.install_code = 0
        self.installed = False
        self.installed_from = []  # the package files as the installer read them
        self.registered = False
        self.add_says = ""        # what `gateway add` fails with, if anything
        self.answers_after = 0    # `settings get` fails this many times first
        self.enabled = False

    def which(self, name):
        if name in ("openshell", "openshell-gateway"):
            return f"/usr/bin/{name}" if self.installed else None
        return f"/usr/bin/{name}" if name in self.tools else None

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        name, args = argv[0], argv[1:]
        if argv == ["dpkg", "--print-architecture"]:
            return _done(0, self.arch + "\n")
        if argv == ["rpm", "--eval", "%{_arch}"]:
            return _done(0, self.arch + "\n")
        if name == "curl":
            url, path = args[-1], Path(args[args.index("-o") + 1])
            file = url.rsplit("/", 1)[-1]
            if file in self.download_fails:
                return _done(22, "", "curl: (22) The requested URL returned error: 404")
            path.write_bytes(self.served.get(file, BODY))
            return _done()
        rooted = argv[1:] if name == "sudo" else argv
        if name == "sudo":
            assert "sudo" in self.tools
        if rooted[:3] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"] or rooted[:1] in (
                ["dnf"], ["yum"], ["zypper"], ["rpm"], ["dpkg"]):
            files = [Path(arg) for arg in rooted if arg.endswith((".deb", ".rpm"))]
            self.installed_from = [(f.name, f.read_bytes(), oct(f.stat().st_mode & 0o777),
                                    oct(f.parent.stat().st_mode & 0o777)) for f in files]
            if self.install_code == 0:
                self.installed = True
            return _done(self.install_code, "", "E: broken" if self.install_code else "")
        if name == "systemctl":
            assert args[0] == "--user"
            if args[1:] == ["enable", "--now", "openshell-gateway"]:
                self.enabled = True
            return _done()
        if name == "openshell" and args[:2] == ["gateway", "add"]:
            if self.add_says:
                return _done(1, "", self.add_says)
            self.registered = True
            return _done()
        if name == "openshell" and args[:2] == ["settings", "get"]:
            if not (self.registered and self.enabled):
                return _done(1, "", "no gateway")
            if self.answers_after > 0:
                self.answers_after -= 1
                return _done(1, "", "tcp connect error")
            return _done(0, "proposal_approval_mode = manual\n")
        raise AssertionError(f"unexpected command {argv}")

    def host(self, **overrides):
        from artzain.openshell import connect

        settings = dict(environ={"HOME": "/home/op", "PATH": "/usr/bin"}, runner=self.run,
                        which=self.which, sleep=lambda _s: None, platform="linux", uid=self.uid)
        settings.update(overrides)
        return connect.Host(**settings)

    def rooted(self):
        """The commands that ran as root."""
        return [c for c in self.calls if c[0] == "sudo"]


# ---------------------------------------------------------------------------
# What is installed
# ---------------------------------------------------------------------------


def test_the_release_is_the_one_this_artzain_binds():
    assert "v" + install.RELEASE == interceptor.PINNED_OPENSHELL
    assert install.BASE_URL == "https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/"


def test_the_real_pins_name_each_package_once_by_a_whole_sha256(monkeypatch):
    monkeypatch.undo()  # the module's own tables
    tables = [*install.DEB.values(), *install.RPM.values()]
    assert sorted(install.DEB) == ["amd64", "arm64"]
    assert sorted(install.RPM) == ["aarch64", "x86_64"]
    for packages in tables:
        for name, sha in packages:
            assert install.RELEASE in name
            assert len(sha) == 64 and int(sha, 16) >= 0
    assert [len(p) for p in install.RPM.values()] == [3, 3]
    # The amd64 deb is the one the conformance run installs.
    assert install.DEB["amd64"] == (
        ("openshell_0.1.2-1_amd64.deb",
         "1f5416ea08f32fdc621f20a2cc0324298e60aba8bbe996459d9e3b44195f23df"),)


@pytest.mark.parametrize("kind, arch, files", [
    ("deb", "amd64", ["openshell_0.1.2-1_amd64.deb"]),
    ("deb", "arm64", ["openshell_0.1.2-1_arm64.deb"]),
    ("rpm", "x86_64", ["openshell-0.1.2-1.fc44.x86_64.rpm", "openshell-gateway-0.1.2-1.fc44.x86_64.rpm",
                       "openshell-prover-0.1.2-1.fc44.x86_64.rpm"]),
    ("rpm", "aarch64", ["openshell-0.1.2-1.fc44.aarch64.rpm", "openshell-gateway-0.1.2-1.fc44.aarch64.rpm",
                        "openshell-prover-0.1.2-1.fc44.aarch64.rpm"]),
])
def test_the_plan_is_this_hosts_format_and_architecture(kind, arch, files):
    bare = _Bare(kind, arch)
    plan = install.plan(bare.host())
    assert (plan.kind, plan.arch) == (kind, arch)
    assert [name for name, _sha in plan.packages] == files


@pytest.mark.parametrize("kind, arch", [("deb", "i386"), ("rpm", "ppc64le")])
def test_an_architecture_nvidia_publishes_nothing_for_is_refused(kind, arch):
    with pytest.raises(install.InstallError, match=f"no OpenShell {install.RELEASE} package for {arch}"):
        install.plan(_Bare(kind, arch).host())


def test_a_package_manager_that_does_not_say_the_architecture_is_refused():
    bare = _Bare()
    real = bare.run

    def run(argv, env, timeout):
        if argv == ["dpkg", "--print-architecture"]:
            return _done(2, "amd64\n", "dpkg: error")  # what a failed command says is not taken
        return real(argv, env, timeout)

    with pytest.raises(install.InstallError, match="did not say this host's architecture"):
        install.plan(bare.host(runner=run))


def test_a_host_with_neither_dpkg_nor_rpm_is_refused():
    with pytest.raises(install.InstallError, match="neither dpkg nor rpm"):
        install.plan(_Bare(tools={"systemctl", "sudo", "curl"}).host())


def test_the_commands_said_for_a_person_check_each_package_first():
    plan = install.plan(_Bare().host())
    lines = plan.by_hand()
    deb = "openshell_0.1.2-1_amd64.deb"
    assert lines[0] == f"curl -fsSLO {install.BASE_URL}{deb}"
    assert lines[1] == f"echo '{SHA}  {deb}' | sha256sum -c -"
    assert lines[-1] == f"sudo apt-get install -y --no-install-recommends ./{deb}"


# ---------------------------------------------------------------------------
# Installing
# ---------------------------------------------------------------------------


def test_the_deb_is_checked_then_installed_then_its_gateway_started_and_registered():
    bare = _Bare()
    said = []
    install.install(bare.host(), install.plan(bare.host()), say=said.append)

    downloads = [c for c in bare.calls if c[0] == "curl"]
    assert len(downloads) == 1
    assert downloads[0][:6] == ["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry"]
    assert downloads[0][-1] == install.BASE_URL + "openshell_0.1.2-1_amd64.deb"
    assert bare.rooted() == [["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install",
                              "-y", "--no-install-recommends", bare.rooted()[0][-1]]]
    assert [(name, body) for name, body, *_modes in bare.installed_from] == [
        ("openshell_0.1.2-1_amd64.deb", BODY)]
    tail = [" ".join(c) for c in bare.calls if c[0] != "curl" and c[0] != "sudo"]
    assert tail[:4] == ["dpkg --print-architecture", "systemctl --user daemon-reload",
                        "systemctl --user enable --now openshell-gateway",
                        "openshell gateway add https://127.0.0.1:17670 --local --name openshell"]
    assert tail[-1] == "openshell settings get --global"
    # The downloads are gone afterwards.
    assert not Path(bare.rooted()[0][-1]).exists()
    assert any("sudo" in line for line in said)


def test_the_rpms_go_in_with_one_dnf_call():
    bare = _Bare("rpm")
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    (call,) = bare.rooted()
    assert call[:4] == ["sudo", "dnf", "install", "-y"]
    assert [Path(p).name for p in call[4:]] == [
        "openshell-0.1.2-1.fc44.x86_64.rpm", "openshell-gateway-0.1.2-1.fc44.x86_64.rpm",
        "openshell-prover-0.1.2-1.fc44.x86_64.rpm"]


@pytest.mark.parametrize("tools, command", [
    ({"dpkg", "apt-get"}, ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"]),
    ({"rpm", "dnf", "yum", "zypper"}, ["dnf", "install", "-y"]),
    ({"rpm", "yum", "zypper"}, ["yum", "install", "-y"]),
    ({"dpkg"}, ["dpkg", "-i"]),
    ({"rpm", "yum"}, ["yum", "install", "-y"]),
    ({"rpm", "zypper"}, ["zypper", "--non-interactive", "install", "--allow-unsigned-rpm"]),
    ({"rpm"}, ["rpm", "-Uvh", "--replacepkgs"]),
])
def test_without_the_usual_installer_the_next_one_is_used(tools, command):
    bare = _Bare("deb" if "dpkg" in tools else "rpm", tools={"systemctl", "sudo", "curl", *tools})
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    (call,) = bare.rooted()
    assert call[1:1 + len(command)] == command


def test_root_installs_without_sudo():
    bare = _Bare(uid=0, tools={"systemctl", "curl", "apt-get", "dpkg"})
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert bare.rooted() == [] and bare.installed
    assert any(c[:3] == ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get"] for c in bare.calls)


def test_a_package_that_is_not_the_build_its_sha256_names_is_not_installed():
    bare = _Bare("rpm")
    bare.served["openshell-gateway-0.1.2-1.fc44.x86_64.rpm"] = b"something else"
    with pytest.raises(install.InstallError,
                       match="openshell-gateway-0.1.2-1.fc44.x86_64.rpm is not the build its SHA-256 names"):
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert bare.rooted() == [] and not bare.installed


def test_a_download_that_fails_says_which():
    bare = _Bare()
    bare.download_fails.add("openshell_0.1.2-1_amd64.deb")
    with pytest.raises(install.InstallError, match="downloading openshell_0.1.2-1_amd64.deb.*404"):
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert bare.rooted() == []


def test_a_download_curl_says_failed_is_not_used_even_when_its_file_is_whole():
    bare = _Bare()
    real = bare.run

    def run(argv, env, timeout):
        done = real(argv, env, timeout)
        return _done(18, "", "curl: (18) transfer closed") if argv[0] == "curl" else done

    with pytest.raises(install.InstallError, match="downloading openshell_0.1.2-1_amd64.deb failed"):
        install.install(bare.host(runner=run), install.plan(bare.host()), say=lambda _m: None)
    assert bare.rooted() == []


def test_without_sudo_nothing_is_tried_and_the_commands_are_said():
    bare = _Bare(tools={"systemctl", "curl", "apt-get", "dpkg"})
    with pytest.raises(install.InstallError, match="sudo is not on PATH") as caught:
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert "apt-get install -y --no-install-recommends ./openshell_0.1.2-1_amd64.deb" in str(caught.value)
    assert [c for c in bare.calls if c[0] in ("curl", "apt-get", "env")] == []


def test_without_curl_nothing_is_tried():
    bare = _Bare(tools={"systemctl", "sudo", "apt-get", "dpkg"})
    with pytest.raises(install.InstallError, match="curl is not on PATH"):
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert bare.rooted() == []


def test_an_installer_that_fails_says_so_and_starts_nothing():
    bare = _Bare()
    bare.install_code = 100
    with pytest.raises(install.InstallError, match="apt-get.*E: broken"):
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert not any(c[0] == "systemctl" for c in bare.calls)


def test_a_gateway_registered_before_is_fine():
    bare = _Bare()
    bare.add_says = "Error: gateway 'openshell' already exists"
    bare.registered = True
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)


def test_a_registration_that_fails_otherwise_says_why():
    bare = _Bare()
    bare.add_says = "Error: permission denied"
    with pytest.raises(install.InstallError, match="openshell gateway add.*permission denied"):
        install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)


def test_the_gateway_is_waited_for():
    bare = _Bare()
    bare.answers_after = 5
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    gets = [c for c in bare.calls if c[:3] == ["openshell", "settings", "get"]]
    assert len(gets) == 6


def test_a_gateway_that_never_answers_says_where_to_look():
    bare = _Bare()
    bare.answers_after = 10_000
    clock = iter(range(0, 10_000, 5))
    with pytest.raises(install.InstallError, match="journalctl --user -u openshell-gateway"):
        install.install(bare.host(clock=lambda: float(next(clock))), install.plan(bare.host()),
                        say=lambda _m: None)


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_the_download_folder_is_this_users_alone_to_write():
    """apt's own user reads the file: the folder and the file are readable,
    and neither is writable but by this user."""
    bare = _Bare()
    install.install(bare.host(), install.plan(bare.host()), say=lambda _m: None)
    assert bare.installed_from[0][2:] == ("0o644", "0o755")
