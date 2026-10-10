"""``artzain connect openshell upgrade``: a newer artzain, only from the signed list.

The mirror publishes the OpenShell compatibility manifest at each
``compat-v<serial>`` release, signed keyless as its ``openshell-compat.yml``
at that tag (the engine's ``integrations/openshell/compat/``). ``upgrade``:

* finds the newest ``compat-v`` tag, downloads the manifest and its bundle;
* verifies the bundle with cosign, itself downloaded by a SHA-256 pinned
  here and kept for the next run;
* refuses a manifest whose serial is not its tag's, or is lower than the
  last one this host read;
* picks the newest artzain listed with the installed OpenShell release;
* downloads that release's connect script, checks it against the SHA-256
  the manifest names, and runs it, which installs that artzain and runs its
  ``up`` (no token: the gateway is connected).

These run against :class:`_Host`, a connected deb gateway whose commands and
downloads are scripted. Nothing here reaches GitHub.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from artzain.openshell import connect, upgrade

#: upgrade, like every connect verb, stops at once on Python 3.10 (connect
#: reads TOML); the tests that run it need 3.11, as the connect tests do.
needs_tomllib = pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML")

ENGINE = "https://engine.example"
COSIGN_BYTES = b"a cosign binary"
GOOD_BUNDLE = b'{"a": "bundle cosign accepts"}'
SCRIPT = {"0.6.43": b"#!/bin/sh\n# connect 0.6.43\n", "0.6.44": b"#!/bin/sh\n# connect 0.6.44\n",
          "0.6.45": b"#!/bin/sh\n# connect 0.6.45\n"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pair(artzain, openshell, run=1):
    return {"artzain": artzain, "openshell": openshell, "verified": "2026-10-09",
            "conformance_run": run, "connect_script_sha256": _sha(SCRIPT[artzain])}


def _manifest(serial=3, pairs=None):
    return {"kind": "artzain.openshell.compat", "version": 2, "serial": serial,
            "pairs": pairs if pairs is not None else [
                _pair("0.6.45", "0.1.3"), _pair("0.6.44", "0.1.2"), _pair("0.6.43", "0.1.2")]}


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class _Host:
    """A connected deb gateway, OpenShell *openshell*, and what it can download."""

    def __init__(self, tmp: Path, *, openshell="0.1.2", arch="x86_64", serials=(3,),
                 manifest=None, connected=True):
        self.home = tmp / "home"
        self.root = tmp / "root"
        unit = self.root / "usr" / "lib" / "systemd" / "user" / connect.GATEWAY_UNIT
        unit.parent.mkdir(parents=True)
        unit.write_text("[Service]\n")
        self.openshell = openshell
        self.arch = arch
        self.calls = []
        self.executed = []
        self.exit_code = 0
        self.cosign_says = None     # None: verify the bundle; or an exit code
        manifest = manifest if manifest is not None else _manifest(serial=max(serials or [0]))
        self.served = {upgrade.TAGS_URL: json.dumps(
            [{"ref": f"refs/tags/compat-v{n}"} for n in serials]).encode()}
        for n in serials:
            base = f"{upgrade.RELEASES}compat-v{n}/"
            self.served[base + upgrade.MANIFEST] = json.dumps(manifest).encode()
            self.served[base + upgrade.BUNDLE] = GOOD_BUNDLE
        for version, body in SCRIPT.items():
            self.served[f"{upgrade.RELEASES}python-v{version}/connect-{version}.sh"] = body
        name = upgrade.COSIGN[arch][0] if arch in upgrade.COSIGN else "cosign-linux-x"
        self.served[f"{upgrade.COSIGN_RELEASE}{name}"] = COSIGN_BYTES
        self.downloads = []
        if connected is not None:
            self.paths.record.parent.mkdir(parents=True, exist_ok=True)
            record = connect.Record(self.paths.record)
            record.mark("redeemed", gateway_id="gw_01X", engine=ENGINE, port=8090)
            if connected:
                record.mark("self-test", self_test_decision_id="01JBCDEFGHJKMNPQRSTVWXYZ00",
                            connected=True)

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        name = argv[0]
        if argv == ["openshell-gateway", "--version"]:
            return _done(0, f"openshell-gateway {self.openshell}\n")
        if argv == ["uname", "-m"]:
            return _done(0, self.arch + "\n")
        if name == "curl":
            url, path = argv[-1], Path(argv[argv.index("-o") + 1])
            self.downloads.append(url)
            if url not in self.served:
                return _done(22, "", "curl: (22) The requested URL returned error: 404")
            path.write_bytes(self.served[url])
            return _done()
        if name.endswith(upgrade.COSIGN_NAME) and argv[1] == "verify-blob":
            assert Path(name).read_bytes() == COSIGN_BYTES, "the pinned cosign runs"
            if self.cosign_says is not None:
                return _done(self.cosign_says, "", "Error: none of the expected identities matched")
            bundle = Path(argv[argv.index("--bundle") + 1]).read_bytes()
            return _done(0 if bundle == GOOD_BUNDLE else 1, "", "Verified OK")
        raise AssertionError(f"unexpected command {argv}")

    def execute(self, argv, env, timeout):
        self.executed.append((list(argv), Path(argv[1]).read_bytes()))
        return self.exit_code

    def host(self, **overrides):
        settings = dict(environ={"HOME": str(self.home), "PATH": "/usr/bin",
                                 "XDG_RUNTIME_DIR": "/run/user/1000"},
                        root=str(self.root), runner=self.run, executor=self.execute,
                        which=lambda name: f"/usr/bin/{name}", sleep=lambda _s: None,
                        platform="linux", uid=1000)
        settings.update(overrides)
        return connect.Host(**settings)

    @property
    def paths(self):
        return connect.layout(self.host())

    def record(self):
        return json.loads(self.paths.record.read_text(encoding="utf-8"))

    def cosign_runs(self):
        return [c for c in self.calls if c[0].endswith(upgrade.COSIGN_NAME)]


@pytest.fixture(autouse=True)
def pinned_cosign(monkeypatch):
    """The pins as tests serve them: the cosign binary hashes to its pin."""
    monkeypatch.setattr(upgrade, "COSIGN", {
        "x86_64": ("cosign-linux-amd64", _sha(COSIGN_BYTES)),
        "aarch64": ("cosign-linux-arm64", _sha(COSIGN_BYTES))})


def _upgrade(host_, **kwargs):
    said = []
    kwargs.setdefault("current", "0.6.43")
    result = connect.upgrade(host_.host(), out=said.append, **kwargs)
    return result, said


# ---------------------------------------------------------------------------
# What is pinned
# ---------------------------------------------------------------------------


def test_the_signer_is_the_mirrors_compat_workflow_at_a_compat_tag():
    assert upgrade.ISSUER == "https://token.actions.githubusercontent.com"
    assert upgrade.IDENTITY == (
        r"^https://github\.com/CogNEXUSlabs/cognexus-tools/\.github/workflows/"
        r"openshell-compat\.yml@refs/tags/compat-v[0-9]+$")
    assert upgrade.TAGS_URL == ("https://api.github.com/repos/CogNEXUSlabs/cognexus-tools/"
                                "git/matching-refs/tags/compat-v")
    assert upgrade.RELEASES == "https://github.com/CogNEXUSlabs/cognexus-tools/releases/download/"


def test_cosign_is_the_2x_release_the_mirror_signs_with_pinned_by_sha256(monkeypatch):
    monkeypatch.undo()
    assert upgrade.COSIGN_VERSION == "v2.6.5"
    assert upgrade.COSIGN_RELEASE == "https://github.com/sigstore/cosign/releases/download/v2.6.5/"
    assert upgrade.COSIGN == {
        "x86_64": ("cosign-linux-amd64",
                   "c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"),
        "aarch64": ("cosign-linux-arm64",
                    "426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7"),
    }


# ---------------------------------------------------------------------------
# Moving to a listed pair
# ---------------------------------------------------------------------------


@needs_tomllib
def test_it_moves_to_the_newest_artzain_listed_with_the_installed_openshell(tmp_path):
    gw = _Host(tmp_path)
    result, said = _upgrade(gw)
    # 0.6.45 is listed with OpenShell 0.1.3 only: not this gateway's.
    assert result["upgraded"] is True and result["to"] == "0.6.44" and result["from"] == "0.6.43"
    ((argv, body),) = gw.executed
    assert body == SCRIPT["0.6.44"]
    assert argv[0] == "sh" and Path(argv[1]).name == "connect-0.6.44.sh"
    assert argv[2:] == ["--engine", ENGINE, "--port", "8090"]
    assert f"{upgrade.RELEASES}python-v0.6.44/connect-0.6.44.sh" in gw.downloads
    record = gw.record()
    assert record["compat_serial"] == 3
    assert (record["upgraded_from"], record["upgraded_to"]) == ("0.6.43", "0.6.44")
    assert any("0.6.44" in line and "serial 3" in line for line in said)


@needs_tomllib
def test_the_bundle_is_verified_with_the_pinned_identity_before_anything_runs(tmp_path):
    gw = _Host(tmp_path)
    _upgrade(gw)
    (verify,) = gw.cosign_runs()
    manifest_at = verify[-1]
    assert verify[1:-1] == ["verify-blob", "--bundle", str(Path(manifest_at).with_name(upgrade.BUNDLE)),
                            "--certificate-oidc-issuer", upgrade.ISSUER,
                            "--certificate-identity-regexp", upgrade.IDENTITY]
    assert Path(manifest_at).name == upgrade.MANIFEST
    verified = gw.calls.index(verify)
    script = next(i for i, call in enumerate(gw.calls)
                  if call[0] == "curl" and call[-1].endswith("/connect-0.6.44.sh"))
    assert verified < script, "nothing the manifest names is fetched before it verifies"


@needs_tomllib
def test_it_reads_the_newest_compat_tag(tmp_path):
    gw = _Host(tmp_path, serials=(1, 12, 3))
    result, _said = _upgrade(gw)
    assert result["serial"] == 12
    assert f"{upgrade.RELEASES}compat-v12/{upgrade.MANIFEST}" in gw.downloads


@needs_tomllib
def test_up_to_date_runs_nothing_and_remembers_the_serial(tmp_path):
    gw = _Host(tmp_path)
    result, said = _upgrade(gw, current="0.6.44")
    assert result["upgraded"] is False and gw.executed == []
    assert gw.record()["compat_serial"] == 3
    assert any("newest" in line for line in said)


@needs_tomllib
def test_check_says_what_it_would_do_and_runs_nothing(tmp_path):
    gw = _Host(tmp_path)
    result, said = _upgrade(gw, check=True)
    assert result == {"upgraded": False, "from": "0.6.43", "to": "0.6.44", "serial": 3,
                      "openshell": "0.1.2", "check": True}
    assert gw.executed == []
    assert not any(url.endswith(".sh") for url in gw.downloads)


@needs_tomllib
@pytest.mark.parametrize("to, ok", [("0.6.44", True), ("0.6.45", False), ("0.6.46", False),
                                    ("0.6.43", False), ("0.6.42", False)])
def test_to_names_a_version_listed_with_this_openshell_and_newer(tmp_path, to, ok):
    gw = _Host(tmp_path)
    if ok:
        result, _said = _upgrade(gw, to=to)
        assert result["to"] == to and len(gw.executed) == 1
    else:
        with pytest.raises(connect.ConnectError):
            _upgrade(gw, to=to)
        assert gw.executed == []


@needs_tomllib
def test_a_failed_script_says_so_and_is_not_recorded_as_done(tmp_path):
    gw = _Host(tmp_path)
    gw.exit_code = 3
    with pytest.raises(connect.ConnectError, match=r"connect-0\.6\.44\.sh stopped \(exit 3\)"):
        _upgrade(gw)
    assert "upgraded_to" not in gw.record()


# ---------------------------------------------------------------------------
# What is refused
# ---------------------------------------------------------------------------


@needs_tomllib
def test_a_bundle_cosign_does_not_accept_stops_everything(tmp_path):
    gw = _Host(tmp_path)
    gw.served[f"{upgrade.RELEASES}compat-v3/{upgrade.BUNDLE}"] = b'{"forged": true}'
    with pytest.raises(connect.ConnectError, match="signature"):
        _upgrade(gw)
    assert gw.executed == [] and not any(url.endswith(".sh") for url in gw.downloads)
    assert "compat_serial" not in gw.record()


@needs_tomllib
def test_a_signature_from_another_identity_stops_everything(tmp_path):
    gw = _Host(tmp_path)
    gw.cosign_says = 1
    with pytest.raises(connect.ConnectError, match="none of the expected identities"):
        _upgrade(gw)
    assert gw.executed == []


@needs_tomllib
def test_a_serial_lower_than_one_this_host_read_is_refused(tmp_path):
    """A rollback: an older signed manifest, served again."""
    gw = _Host(tmp_path)
    connect.Record.load(gw.paths.record).mark("compat", compat_serial=7)
    with pytest.raises(connect.ConnectError, match="serial 3.*7"):
        _upgrade(gw)
    assert gw.executed == [] and gw.record()["compat_serial"] == 7


@needs_tomllib
def test_a_manifest_whose_serial_is_not_its_tags_is_refused(tmp_path):
    """An older signed manifest attached to a newer tag's release."""
    gw = _Host(tmp_path, serials=(4,), manifest=_manifest(serial=2))
    with pytest.raises(connect.ConnectError, match="serial 2.*compat-v4"):
        _upgrade(gw)
    assert gw.executed == []


@needs_tomllib
@pytest.mark.parametrize("change", [
    {"kind": "something.else"}, {"version": 1}, {"pairs": "none"},
    {"pairs": [{"artzain": "0.6.44", "openshell": "0.1.2"}]},
    {"pairs": [{**_pair("0.6.44", "0.1.2"), "connect_script_sha256": "not-a-sha"}]},
    {"pairs": [{**_pair("0.6.44", "0.1.2"), "artzain": "0.6.44; rm -rf /"}]},
])
def test_a_manifest_that_is_not_one_is_refused(tmp_path, change):
    gw = _Host(tmp_path, manifest={**_manifest(), **change})
    with pytest.raises(connect.ConnectError, match="not a compatibility manifest"):
        _upgrade(gw)
    assert gw.executed == []


@needs_tomllib
def test_a_script_that_is_not_the_one_the_manifest_names_is_not_run(tmp_path):
    gw = _Host(tmp_path)
    gw.served[f"{upgrade.RELEASES}python-v0.6.44/connect-0.6.44.sh"] = b"#!/bin/sh\nsomething else\n"
    with pytest.raises(connect.ConnectError, match="connect-0.6.44.sh is not the script"):
        _upgrade(gw)
    assert gw.executed == []


@needs_tomllib
def test_no_compat_release_yet_says_so(tmp_path):
    gw = _Host(tmp_path, serials=())
    with pytest.raises(connect.ConnectError, match="no signed compatibility manifest"):
        _upgrade(gw)


@needs_tomllib
def test_a_gateway_that_is_not_connected_is_told_to_run_up(tmp_path):
    gw = _Host(tmp_path, connected=False)
    with pytest.raises(connect.ConnectError, match="connect openshell up"):
        _upgrade(gw)
    assert gw.downloads == []


@needs_tomllib
def test_nothing_listed_for_the_installed_openshell_says_so(tmp_path):
    gw = _Host(tmp_path, openshell="0.2.0")
    with pytest.raises(connect.ConnectError, match="lists no artzain for OpenShell 0.2.0"):
        _upgrade(gw)


# ---------------------------------------------------------------------------
# cosign
# ---------------------------------------------------------------------------


@needs_tomllib
def test_cosign_is_downloaded_once_by_its_pin_and_kept(tmp_path):
    gw = _Host(tmp_path)
    _upgrade(gw, check=True)
    _upgrade(gw, check=True)
    fetched = [u for u in gw.downloads if u.startswith(upgrade.COSIGN_RELEASE)]
    assert fetched == [f"{upgrade.COSIGN_RELEASE}cosign-linux-amd64"]
    kept = gw.paths.state_dir / "bin" / f"cosign-{upgrade.COSIGN_VERSION}"
    assert kept.read_bytes() == COSIGN_BYTES


@needs_tomllib
def test_a_kept_cosign_that_changed_is_downloaded_again(tmp_path):
    gw = _Host(tmp_path)
    _upgrade(gw, check=True)
    kept = gw.paths.state_dir / "bin" / f"cosign-{upgrade.COSIGN_VERSION}"
    kept.write_bytes(b"tampered")
    _upgrade(gw, check=True)
    assert kept.read_bytes() == COSIGN_BYTES
    assert len([u for u in gw.downloads if u.startswith(upgrade.COSIGN_RELEASE)]) == 2


@needs_tomllib
def test_a_cosign_download_that_is_not_its_pin_is_never_run(tmp_path):
    gw = _Host(tmp_path)
    gw.served[f"{upgrade.COSIGN_RELEASE}cosign-linux-amd64"] = b"not cosign"
    with pytest.raises(connect.ConnectError, match="cosign-linux-amd64 is not the build"):
        _upgrade(gw)
    assert gw.cosign_runs() == [] and gw.executed == []


@needs_tomllib
def test_the_arm64_build_on_an_arm64_host(tmp_path):
    gw = _Host(tmp_path, arch="aarch64")
    _upgrade(gw, check=True)
    assert f"{upgrade.COSIGN_RELEASE}cosign-linux-arm64" in gw.downloads


@needs_tomllib
def test_an_architecture_with_no_pinned_cosign_is_refused(tmp_path):
    gw = _Host(tmp_path, arch="riscv64")
    with pytest.raises(connect.ConnectError, match="no pinned cosign for riscv64"):
        _upgrade(gw)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_upgrade_runs_from_the_command_line(monkeypatch, capsys):
    from artzain import cli

    seen = []
    monkeypatch.setattr(connect, "upgrade", lambda host, **kw: seen.append(kw) or {"upgraded": False})
    cli.main(["connect", "openshell", "upgrade"])
    cli.main(["connect", "openshell", "upgrade", "--check", "--to", "0.6.44"])
    assert [(kw["to"], kw["check"]) for kw in seen] == [(None, False), ("0.6.44", True)]

    def refused(host, **kw):
        raise connect.ConnectError("no signed compatibility manifest yet")

    monkeypatch.setattr(connect, "upgrade", refused)
    with pytest.raises(SystemExit) as stopped:
        cli.main(["connect", "openshell", "upgrade"])
    assert str(stopped.value) == ("artzain connect openshell upgrade: "
                                  "no signed compatibility manifest yet")


@pytest.mark.skipif(sys.version_info >= (3, 11), reason="the refusal on Python 3.10")
def test_on_python_3_10_it_refuses_before_it_downloads_anything(tmp_path):
    gw = _Host(tmp_path)
    with pytest.raises(connect.ConnectError, match="needs Python 3.11"):
        connect.upgrade(gw.host(), current="0.6.43", out=lambda _s: None)
    assert gw.downloads == [] and gw.executed == []

