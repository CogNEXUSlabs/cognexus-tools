"""`artzain local` (WS-B): manifest pinning, workspace rules, doctor, upgrade.

No Docker daemon needed — subprocess and HTTP are stubbed. One optional test
validates the rendered compose file with `docker compose config` when a
docker CLI is present (it parses without a daemon).
"""

from __future__ import annotations

import gzip
import io
import json
import shutil
import subprocess
import urllib.error
from types import SimpleNamespace

import pytest

import artzain.local as local


@pytest.fixture(autouse=True)
def _workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNEXUS_LOCAL_HOME", str(tmp_path / "ws"))
    monkeypatch.delenv("COGNEXUS_CHANNEL_MANIFEST", raising=False)
    yield tmp_path / "ws"


def _manifest(**over):
    base = {
        "channel": "stable",
        "version": "2026.08.25-e7faeee",
        "registry": "public.ecr.aws/n7c0i6o5",
        "source_commit": "e" * 40,
        "images": {
            "cognexus-core": {"tag": "2026.08.25-e7faeee",
                              "digest": "sha256:" + "d" * 64},
            "cognexus-frontend": {"tag": "2026.08.25-e7faeee",
                                  "digest": "sha256:" + "e" * 64},
        },
    }
    base.update(over)
    return base


class _FakeDumpProc:
    """A Popen stand-in emitting raw bytes — including ones no text codec
    survives, which is the point of the binary-dump contract."""

    def __init__(self, payload: bytes, returncode: int = 0):
        self.stdout = io.BytesIO(payload)
        self.stderr = io.BytesIO(b"" if returncode == 0 else b"pg down")
        self._rc = returncode

    def wait(self, timeout=None):
        return self._rc


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def test_manifest_source_precedence(monkeypatch):
    assert local.manifest_source("x.json") == "x.json"
    monkeypatch.setenv("COGNEXUS_CHANNEL_MANIFEST", "env.json")
    assert local.manifest_source(None) == "env.json"
    monkeypatch.delenv("COGNEXUS_CHANNEL_MANIFEST")
    assert local.manifest_source(None) == local.DEFAULT_MANIFEST_URL


def test_load_manifest_from_file(tmp_path):
    p = tmp_path / "stable.json"
    p.write_text(json.dumps(_manifest()), encoding="utf-8")
    got = local.load_manifest(str(p))
    assert got["version"] == "2026.08.25-e7faeee"


def test_manifest_without_digest_is_refused(tmp_path):
    bad = _manifest()
    bad["images"]["cognexus-core"] = {"tag": "latest"}
    p = tmp_path / "stable.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(local.LocalError, match="no sha256 digest"):
        local.load_manifest(str(p))


def test_manifest_with_malformed_digest_is_refused(tmp_path):
    bad = _manifest()
    bad["images"]["cognexus-frontend"]["digest"] = "sha256:short"
    p = tmp_path / "stable.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(local.LocalError, match="no sha256 digest"):
        local.load_manifest(str(p))


def test_missing_manifest_file_names_the_fix(tmp_path):
    with pytest.raises(local.LocalError, match="--manifest"):
        local.load_manifest(str(tmp_path / "nope.json"))


def test_image_refs_pin_digests_never_tags():
    refs = local.image_refs(_manifest())
    assert refs["cognexus-core"] == (
        "public.ecr.aws/n7c0i6o5/cognexus-core@sha256:" + "d" * 64)
    for ref in refs.values():
        assert "@sha256:" in ref and ":2026" not in ref


# ---------------------------------------------------------------------------
# Rendering + workspace rules
# ---------------------------------------------------------------------------


def test_render_compose_bakes_digests_and_keeps_frontend_unconditional():
    text = local.render_compose(_manifest())
    assert "cognexus-core@sha256:" + "d" * 64 in text
    assert "cognexus-frontend@sha256:" + "e" * 64 in text
    assert "__CORE_IMAGE__" not in text and "__FRONTEND_IMAGE__" not in text
    assert "build:" not in text, "the installer never builds from source"
    assert "profiles:" not in text, "the dashboard must not hide behind a profile"
    assert "COGNEXUS_BOOTSTRAP_TOKEN" in text


def test_every_image_in_the_rendered_compose_is_digest_pinned():
    """Including the postgres base — 'never a bare tag' has no exceptions
    for the container holding the system of record."""
    for line in local.render_compose(_manifest()).splitlines():
        stripped = line.strip()
        if stripped.startswith("image:"):
            assert "@sha256:" in stripped, stripped


def test_env_is_generated_once_and_never_overwritten(_workspace):
    state = local.ensure_workspace(_manifest())
    assert state["env_created"] is True
    first = local.read_env()
    assert len(first["JWT_SECRET_KEY"]) >= 32
    assert len(first["COGNEXUS_API_KEY_PEPPER"]) >= 32
    assert first["JWT_SECRET_KEY"] != first["COGNEXUS_API_KEY_PEPPER"]

    # Re-pin to a new release: compose rewritten, secrets untouched.
    newer = _manifest(version="2026.09.01-abc1234")
    newer["images"]["cognexus-core"]["digest"] = "sha256:" + "f" * 64
    state2 = local.ensure_workspace(newer)
    assert state2["env_created"] is False
    assert local.read_env() == first
    assert "sha256:" + "f" * 64 in (local.workspace_dir() / "compose.yaml").read_text(encoding="utf-8")
    assert local.applied_pins()["version"] == "2026.09.01-abc1234"


def test_partial_env_is_repaired_not_trusted(_workspace):
    """A hand-created .env (someone setting the port before first run) must
    not leave the stack without a Postgres password — that bricked installs."""
    ws = local.workspace_dir()
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".env").write_text("COGNEXUS_UI_PORT=9090\n", encoding="utf-8")
    state = local.ensure_workspace(_manifest())
    assert state["env_repaired"] is True
    env = local.read_env()
    assert env["COGNEXUS_UI_PORT"] == "9090", "the operator's choice survives"
    for key, _ in local._ENV_SECRET_KEYS:
        assert env.get(key), f"{key} was not filled in"


def test_port_flag_overrides_and_persists(_workspace):
    local.ensure_workspace(_manifest(), ui_port_choice=9191)
    assert local.ui_port() == 9191
    # A later run without the flag keeps the stored choice.
    local.ensure_workspace(_manifest())
    assert local.ui_port() == 9191


def test_read_env_strips_dotenv_quotes(_workspace):
    ws = local.workspace_dir()
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".env").write_text('COGNEXUS_UI_PORT="9090"\n', encoding="utf-8")
    assert local.read_env()["COGNEXUS_UI_PORT"] == "9090"
    assert local.ui_port() == 9090


def test_generated_secrets_differ_between_installs():
    a, _ = local._render_env({}, None)
    b, _ = local._render_env({}, None)
    assert a != b


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------


def test_doctor_missing_docker_names_the_fix(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    checks = {name: (ok, remedy) for name, ok, remedy in local.doctor_checks(port=8080)}
    ok, remedy = checks["docker installed"]
    assert ok is False
    assert "docs.docker.com" in remedy
    # Daemon/compose checks are skipped when docker itself is absent.
    assert "docker daemon running" not in checks


def test_doctor_reports_each_failure_with_one_remedy(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(local, "_run", lambda cmd, timeout=30: SimpleNamespace(
        returncode=1, stdout="", stderr=""))
    monkeypatch.setattr(local, "_stack_running", lambda: False)
    for name, ok, remedy in local.doctor_checks(port=8080):
        if not ok:
            assert remedy.strip(), f"{name} has no remedy"
            assert "\n" not in remedy.strip(), f"{name} remedy is not one sentence-ish line"


def test_doctor_port_remedy_names_the_flag_and_the_real_env_path(monkeypatch):
    """The remedy must not hardcode ~/.cognexus when COGNEXUS_LOCAL_HOME
    points elsewhere, and must offer --port so a first run needs no file
    edit at all."""
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(local, "_run", lambda cmd, timeout=30: SimpleNamespace(
        returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(local, "_port_free", lambda port: False)
    monkeypatch.setattr(local, "_stack_running", lambda: False)
    remedy = {n: r for n, ok, r in local.doctor_checks(port=8080)}["port 8080 available"]
    assert "--port" in remedy
    assert str(local._env_path()) in remedy


def test_doctor_port_check_tolerates_own_running_stack(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(local, "_run", lambda cmd, timeout=30: SimpleNamespace(
        returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(local, "_port_free", lambda port: False)
    monkeypatch.setattr(local, "_stack_running", lambda: True)
    checks = {name: ok for name, ok, _ in local.doctor_checks(port=8080)}
    assert checks["port 8080 available"] is True


def test_doctor_output_is_ascii_safe():
    """Redirected stdout on Windows is cp1252-strict; a remedy that cannot
    be piped into a support ticket is a remedy that crashes mid-diagnosis."""
    for name, _ok, remedy in local.doctor_checks(port=8080):
        (name + remedy).encode("cp1252")


# ---------------------------------------------------------------------------
# Upgrade ordering — the dump comes first, and its failure aborts
# ---------------------------------------------------------------------------


def _prime_installed():
    local.ensure_workspace(_manifest())


def test_upgrade_dumps_before_repinning(_workspace, monkeypatch, tmp_path):
    _prime_installed()
    order: list[str] = []
    payload = ("-- PostgreSQL database dump\n".encode() * 64) + b"\x81\xff caf\xc3\xa9\n"

    def fake_popen(cmd, stdout=None, stderr=None):
        order.append("dump")
        return _FakeDumpProc(payload)

    def fake_compose(args, check=True, timeout=900):
        order.append("compose:" + args[0])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local, "_compose", fake_compose)
    monkeypatch.setattr(local, "wait_healthy",
                        lambda log=None: order.append("healthy") or {"status": "healthy"})
    newer = _manifest(version="2026.09.01-abc1234")
    manifest_file = tmp_path / "next.json"
    manifest_file.write_text(json.dumps(newer), encoding="utf-8")

    local.run_upgrade(str(manifest_file), out=io.StringIO())

    assert order[0] == "dump", "the dump must run before anything changes"
    assert "compose:up" in order
    dumps = list(local.backups_dir().glob("pre-upgrade-*.sql.gz"))
    assert len(dumps) == 1
    with gzip.open(dumps[0], "rb") as fh:
        assert fh.read() == payload, "byte-exact — no text-mode decode may touch it"


def test_upgrade_aborts_without_a_dump(_workspace, monkeypatch, tmp_path):
    _prime_installed()
    compose_calls: list[str] = []
    monkeypatch.setattr(local.subprocess, "Popen",
                        lambda cmd, stdout=None, stderr=None: _FakeDumpProc(b"", returncode=1))
    monkeypatch.setattr(local, "_compose",
                        lambda args, check=True, timeout=900: compose_calls.append(args[0])
                        or SimpleNamespace(returncode=0, stdout="", stderr=""))
    newer = _manifest(version="2026.09.01-abc1234")
    manifest_file = tmp_path / "next.json"
    manifest_file.write_text(json.dumps(newer), encoding="utf-8")

    with pytest.raises(local.LocalError, match="refusing to upgrade"):
        local.run_upgrade(str(manifest_file), out=io.StringIO())
    assert compose_calls == [], "nothing may change after a failed dump"
    assert local.applied_pins()["version"] == "2026.08.25-e7faeee"
    assert not list(local.backups_dir().glob("pre-upgrade-*.sql.gz")), \
        "a failed dump must not leave a bogus backup behind"


def test_upgrade_is_a_noop_on_the_same_version(_workspace, monkeypatch, tmp_path, capsys):
    _prime_installed()
    monkeypatch.setattr(local, "_compose", lambda *a, **k: pytest.fail("no compose call expected"))
    manifest_file = tmp_path / "same.json"
    manifest_file.write_text(json.dumps(_manifest()), encoding="utf-8")
    local.run_upgrade(str(manifest_file))
    assert "nothing to do" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# down --purge confirmation, and the lock
# ---------------------------------------------------------------------------


def test_purge_requires_the_typed_confirmation(_workspace, monkeypatch, capsys):
    _prime_installed()
    compose_calls: list[list[str]] = []
    monkeypatch.setattr(local, "_compose",
                        lambda args, check=True, timeout=900: compose_calls.append(args)
                        or SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(local, "fetch_health", lambda timeout=5.0: {"install_id": "inst-42"})

    local.run_down(purge=True, confirm=lambda prompt: "wrong")
    assert compose_calls == [], "a wrong confirmation must destroy nothing"
    assert "nothing was destroyed" in capsys.readouterr().out.lower()

    local.run_down(purge=True, confirm=lambda prompt: "inst-42")
    assert ["down", "--volumes"] in compose_calls
    assert not local._env_path().is_file(), "purge removes the stale secrets"


def test_purge_demands_the_persisted_install_id_when_the_stack_is_down(
        _workspace, monkeypatch):
    """The guard must not degrade to a public constant just because the
    stack was stopped first — the normal purge precondition."""
    _prime_installed()
    local._remember_install_id({"install_id": "inst-99"})
    monkeypatch.setattr(local, "fetch_health", lambda timeout=5.0: None)
    monkeypatch.setattr(local, "_compose",
                        lambda args, check=True, timeout=900: SimpleNamespace(
                            returncode=0, stdout="", stderr=""))
    prompts: list[str] = []

    def confirm(prompt):
        prompts.append(prompt)
        return "nope"

    local.run_down(purge=True, confirm=confirm, out=io.StringIO())
    assert "inst-99" in prompts[0]
    assert "destroy-cognexus" not in prompts[0]


def test_mutating_commands_take_the_workspace_lock(_workspace, monkeypatch):
    _prime_installed()
    lock = local.workspace_dir() / ".lock"
    lock.write_text("pid=held\n", encoding="utf-8")
    try:
        with pytest.raises(local.LocalError, match="appears to be running"):
            local.run_down(purge=False, out=io.StringIO())
    finally:
        lock.unlink()


# ---------------------------------------------------------------------------
# First-run plan + create-admin wire format
# ---------------------------------------------------------------------------


def test_first_run_plan_branches(_workspace, monkeypatch):
    _prime_installed()
    token = local.read_env()["COGNEXUS_BOOTSTRAP_TOKEN"]

    monkeypatch.setattr(local, "bootstrap_state",
                        lambda retries=3, sleep=None: {"available": True, "reason": "ok"})
    url, _ = local.first_run_plan()
    assert url.endswith(f"/welcome?token={token}")

    monkeypatch.setattr(local, "bootstrap_state",
                        lambda retries=3, sleep=None: {"available": False,
                                                       "reason": "already_bootstrapped"})
    url, note = local.first_run_plan()
    assert url.endswith("/login") and "already has an account" in note

    # A transient probe failure must NOT hide the one-time welcome URL.
    monkeypatch.setattr(local, "bootstrap_state",
                        lambda retries=3, sleep=None: {"available": False,
                                                       "reason": "unreachable"})
    url, note = local.first_run_plan()
    assert f"/welcome?token={token}" in url
    assert "create-admin" in note


def test_create_admin_posts_the_workspace_token(_workspace, monkeypatch, capsys):
    _prime_installed()
    token = local.read_env()["COGNEXUS_BOOTSTRAP_TOKEN"]
    seen = {}

    def fake_post(path, body, timeout=30.0):
        seen.update(path=path, body=body)
        return 200, {"ok": True, "token": "jwt", "user": {}}

    monkeypatch.setattr(local, "_api_post", fake_post)
    local.run_create_admin("op@example.test", "long-enough-pw")
    assert seen["path"] == "/api/auth/bootstrap-admin"
    assert seen["body"] == {"token": token, "email": "op@example.test",
                            "password": "long-enough-pw"}
    assert "Platform admin created" in capsys.readouterr().out


def test_create_admin_translates_the_gate_codes(_workspace, monkeypatch):
    _prime_installed()
    monkeypatch.setattr(local, "_api_post", lambda *a, **k: (
        403, {"detail": {"error": "already_bootstrapped"}}))
    with pytest.raises(local.LocalError, match="already has an account"):
        local.run_create_admin("op@example.test", "long-enough-pw")


def test_api_post_preserves_non_json_error_bodies(_workspace, monkeypatch):
    """A gateway's HTML 502 page is the only diagnostic the user has —
    flattening it to {} printed 'Bootstrap failed (HTTP 502): None'."""
    _prime_installed()
    html = b"<html>502 Bad Gateway from nginx</html>"

    def fake_urlopen(req, timeout=30.0):
        raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway",
                                     hdrs=None, fp=io.BytesIO(html))

    monkeypatch.setattr(local.urllib.request, "urlopen", fake_urlopen)
    status, payload = local._api_post("/api/auth/bootstrap-admin", {})
    assert status == 502
    assert "502 Bad Gateway" in payload["detail"]


def test_login_session_returns_token_and_names_mfa_limit(_workspace, monkeypatch):
    _prime_installed()
    monkeypatch.setattr(local, "_api_post",
                        lambda *a, **k: (200, {"token": "jwt-123", "user": {}}))
    assert local.login_session("a@b.c", "pw") == "jwt-123"

    monkeypatch.setattr(local, "_api_post",
                        lambda *a, **k: (200, {"mfa_required": True}))
    with pytest.raises(local.LocalError, match="two-factor"):
        local.login_session("a@b.c", "pw")

    monkeypatch.setattr(local, "_api_post",
                        lambda *a, **k: (401, {"detail": "Invalid email or password."}))
    with pytest.raises(local.LocalError, match="Sign-in failed"):
        local.login_session("a@b.c", "pw")


def test_reset_and_activate_are_wired():
    """The generated .env names `artzain local reset`; the trial-expired
    status hint names `activate` — both must exist as commands."""
    import artzain.cli as cli

    assert callable(cli.cmd_local_reset)
    assert callable(cli.cmd_local_activate)
    assert "reset" in local._ENV_HEADER


# ---------------------------------------------------------------------------
# Optional: the rendered compose parses (docker CLI only, no daemon)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("docker") is None,
                    reason="docker CLI not installed")
def test_rendered_compose_is_valid_compose(_workspace):
    local.ensure_workspace(_manifest())
    proc = subprocess.run(
        ["docker", "compose", "-f", str(local.workspace_dir() / "compose.yaml"),
         "--env-file", str(local.workspace_dir() / ".env"), "config", "--quiet"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
