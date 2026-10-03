"""What the SDK writes to disk is its user's alone from the moment it exists
(survey 25 Sep 2026, rows 37 and 38).

Row 37: ``artzain local`` wrote the stack's ``.env`` (database password and
other secrets) and ``artzain policy keygen`` the Ed25519 signing key with the
process umask, then chmod'ed them, so on a multi-user POSIX host another user
could read them in between; the pre-upgrade database dumps were never
chmod'ed at all, in a workspace folder anyone could list.

Row 38: with no events directory configured, the prompt-defence events
(previews of screened prompts) and their tamper-evident chain went to a shared
``/tmp`` (``C:\\tmp`` on Windows, where any signed-in user may change them).

Files are now created 0600 and folders 0700, whatever the umask, and the
events default to a folder of the user's own.
"""

from __future__ import annotations

import gzip
import io
import os
import stat
import sys
from pathlib import Path

import pytest

import artzain.events as events
import artzain.local as local

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def loose_umask():
    """The common default umask, under which a plain write is world-readable."""
    if sys.platform == "win32":
        yield
        return
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


# ── The helpers ───────────────────────────────────────────────────────────────

@posix_only
def test_a_private_folder_is_created_and_tightened(tmp_path, loose_umask):
    from artzain import _private_files as pf

    made = pf.private_dir(tmp_path / "new" / "leaf")
    assert _mode(made) == 0o700
    existing = tmp_path / "existing"
    existing.mkdir(mode=0o755)
    os.chmod(existing, 0o755)
    pf.private_dir(existing)
    assert _mode(existing) == 0o700


@posix_only
def test_a_private_file_is_private_before_it_holds_anything(tmp_path, loose_umask):
    from artzain import _private_files as pf

    fresh = tmp_path / "fresh"
    pf.write_private(fresh, b"secret")
    assert (_mode(fresh), fresh.read_bytes()) == (0o600, b"secret")
    fd = pf.open_private(tmp_path / "opened")
    try:
        info = os.fstat(fd)
        assert (stat.S_IMODE(info.st_mode), info.st_size) == (0o600, 0)
    finally:
        os.close(fd)


@posix_only
def test_a_file_left_readable_is_replaced_not_written_into(tmp_path, loose_umask):
    from artzain import _private_files as pf

    # Whoever opened the old file while it was readable keeps reading it
    # through that descriptor, whatever its mode becomes: the secret goes
    # into a new file.
    stale = tmp_path / "stale"
    stale.write_bytes(b"old")
    os.chmod(stale, 0o644)
    held = os.open(stale, os.O_RDONLY)
    try:
        pf.write_private(stale, b"new secret")
        assert os.read(held, 100) == b"old"
    finally:
        os.close(held)
    assert (_mode(stale), stale.read_bytes()) == (0o600, b"new secret")
    # A link at the name is replaced, not written through.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(b"theirs")
    link = tmp_path / "link"
    link.symlink_to(elsewhere)
    pf.write_private(link, b"secret")
    assert elsewhere.read_bytes() == b"theirs"
    assert not link.is_symlink() and link.read_bytes() == b"secret"


@posix_only
def test_a_folder_that_is_another_users_is_refused(tmp_path, monkeypatch):
    from artzain import _private_files as pf

    theirs = tmp_path / "theirs"
    theirs.mkdir()
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(PermissionError):
        pf.private_dir(theirs)


def test_a_file_the_write_could_not_finish_is_removed(tmp_path, monkeypatch):
    from artzain import _private_files as pf

    real_fdopen = os.fdopen

    class _DiskFull:
        def __init__(self, fd):
            self.fh = real_fdopen(fd, "wb")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()
            return False

        def write(self, data):
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fdopen", lambda fd, *a, **kw: _DiskFull(fd))
    target = tmp_path / "key"
    with pytest.raises(OSError):
        pf.write_private(target, b"secret", exclusive=True)
    # A half-written key would refuse the next keygen as "existing".
    assert not target.exists()


def test_an_exclusive_private_file_refuses_an_existing_one(tmp_path):
    from artzain import _private_files as pf

    target = tmp_path / "key"
    pf.write_private(target, b"first", exclusive=True)
    with pytest.raises(FileExistsError):
        pf.write_private(target, b"second", exclusive=True)
    assert target.read_bytes() == b"first"


# A new file goes over the old one by a rename. Windows refuses the rename
# while another program has the old one open, a virus scanner reading a file
# just written, say, and lets it through once that program closes it.

def _old_and_new(folder: Path) -> tuple:
    target, new = folder / "state.json", folder / "state.json.new"
    target.write_bytes(b"old")
    new.write_bytes(b"new")
    return target, new


def test_a_replace_another_program_holds_up_waits_for_it(tmp_path, artzain_held_replace):
    from artzain import _private_files as pf

    target, new = _old_and_new(tmp_path)
    refused = artzain_held_replace(3)
    pf.replace_file(new, target)
    assert target.read_bytes() == b"new" and len(refused) == 3
    assert os.listdir(tmp_path) == ["state.json"]


def test_only_windows_waits_for_a_file_to_be_let_go():
    """Elsewhere a rename is never held up by a reader, so a refusal is real."""
    from artzain import _private_files as pf

    assert (pf._REPLACE_RETRY_SECONDS > 0) == (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="Windows waits for the file")
def test_off_windows_a_refused_replace_is_not_tried_again(tmp_path, monkeypatch):
    from artzain import _private_files as pf

    target, new = _old_and_new(tmp_path)
    attempts = []

    def refused(source, destination):
        attempts.append(destination)
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "replace", refused)
    with pytest.raises(PermissionError):
        pf.replace_file(new, target)
    assert len(attempts) == 1 and target.read_bytes() == b"old"
    assert os.listdir(tmp_path) == ["state.json"]


@pytest.mark.parametrize("seconds", [0.0, 0.05])  # off Windows; a program that never lets go
def test_a_replace_that_never_goes_through_leaves_the_file_as_it_was(
        tmp_path, monkeypatch, artzain_held_replace, seconds):
    from artzain import _private_files as pf

    target, new = _old_and_new(tmp_path)
    refused = artzain_held_replace(10 ** 6)
    monkeypatch.setattr(pf, "_REPLACE_RETRY_SECONDS", seconds)
    with pytest.raises(PermissionError):
        pf.replace_file(new, target)
    assert target.read_bytes() == b"old"
    assert os.listdir(tmp_path) == ["state.json"]
    assert (len(refused) == 1) == (seconds == 0.0)


def test_only_a_refused_replace_is_tried_again(tmp_path, monkeypatch):
    """Waiting mends a file another program holds, not a failing disk."""
    from artzain import _private_files as pf

    target, new = _old_and_new(tmp_path)
    monkeypatch.setattr(pf, "_REPLACE_RETRY_SECONDS", 5.0)
    attempts = []

    def failing(source, destination):
        attempts.append(destination)
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "replace", failing)
    with pytest.raises(OSError):
        pf.replace_file(new, target)
    assert len(attempts) == 1 and target.read_bytes() == b"old"
    assert os.listdir(tmp_path) == ["state.json"]


# ── artzain local ─────────────────────────────────────────────────────────────

def _manifest() -> dict:
    return {
        "channel": "stable", "version": "2026.08.25-e7faeee",
        "registry": "public.ecr.aws/cognexuslabs", "source_commit": "e" * 40,
        "images": {
            "cognexus-core": {"tag": "2026.08.25-e7faeee", "digest": "sha256:" + "d" * 64},
            "cognexus-frontend": {"tag": "2026.08.25-e7faeee", "digest": "sha256:" + "e" * 64},
        },
    }


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNEXUS_LOCAL_HOME", str(tmp_path / "ws"))
    monkeypatch.delenv("COGNEXUS_CHANNEL_MANIFEST", raising=False)
    return tmp_path / "ws"


@posix_only
def test_the_local_workspace_and_its_secrets_are_private(workspace, loose_umask):
    workspace.mkdir()
    os.chmod(workspace, 0o755)
    # A temporary file an interrupted run left world-readable.
    stale_tmp = workspace / ".env.tmp"
    stale_tmp.write_text("OLD=1\n", encoding="utf-8")
    os.chmod(stale_tmp, 0o644)
    local.ensure_workspace(_manifest())
    env = workspace / ".env"
    assert "POSTGRES_PASSWORD=" in env.read_text(encoding="utf-8")
    assert _mode(env) == 0o600
    assert _mode(workspace) == 0o700
    assert _mode(local.backups_dir()) == 0o700


@posix_only
def test_the_env_file_is_private_without_a_chmod_after_it(workspace, monkeypatch, loose_umask):
    # Written with the umask's mode and fixed up by a chmod afterwards, the
    # secrets were readable in between; with no chmod, that stays visible.
    monkeypatch.setattr(os, "chmod", lambda *a, **kw: None)
    monkeypatch.setattr(Path, "chmod", lambda *a, **kw: None)
    local.ensure_workspace(_manifest())
    assert _mode(workspace / ".env") == 0o600


@posix_only
def test_a_stale_env_tmp_someone_opened_does_not_receive_the_secrets(workspace, loose_umask):
    workspace.mkdir()
    os.chmod(workspace, 0o755)
    stale_tmp = workspace / ".env.tmp"
    stale_tmp.write_text("OLD=1\n", encoding="utf-8")
    os.chmod(stale_tmp, 0o644)
    held = os.open(stale_tmp, os.O_RDONLY)  # opened while the folder was open to all
    try:
        local.ensure_workspace(_manifest())
        assert b"POSTGRES_PASSWORD" not in os.read(held, 1 << 16)
    finally:
        os.close(held)
    assert "POSTGRES_PASSWORD=" in (workspace / ".env").read_text(encoding="utf-8")


@posix_only
def test_a_workspace_folder_that_is_another_users_is_refused(workspace, monkeypatch):
    workspace.mkdir()
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(PermissionError):
        local.ensure_workspace(_manifest())
    assert not (workspace / ".env").exists()


class _FakeDumpProc:
    def __init__(self, payload: bytes):
        self.stdout = io.BytesIO(payload)
        self.stderr = io.BytesIO(b"")

    def wait(self, timeout=None):
        return 0


@posix_only
def test_a_database_dump_is_private(workspace, monkeypatch, loose_umask):
    payload = b"-- PostgreSQL database dump\n" * (local._MIN_DUMP_BYTES // 28 + 64)
    monkeypatch.setattr(local.subprocess, "Popen", lambda cmd, stdout=None, stderr=None: _FakeDumpProc(payload))
    monkeypatch.setattr(local, "_compose_cmd", lambda args: ["docker", "compose", *args])
    target = local._predump(out=io.StringIO())
    assert _mode(target) == 0o600
    assert _mode(local.backups_dir()) == 0o700
    with gzip.open(target, "rb") as fh:
        assert fh.read() == payload


def test_a_stack_file_another_program_holds_up_is_still_written(workspace, artzain_held_replace):
    """A program reading ``.env`` on Windows, a virus scanner say, made the
    rename fail, and the command with it."""
    workspace.mkdir()
    env = workspace / ".env"
    env.write_text("OLD=1\n", encoding="utf-8")
    refused = artzain_held_replace(3)
    local._write_atomic(env, "NEW=1\n", private=True)
    assert env.read_text(encoding="utf-8") == "NEW=1\n" and len(refused) == 3
    assert os.listdir(workspace) == [".env"]


# ── artzain policy keygen ─────────────────────────────────────────────────────

@posix_only
def test_a_signing_key_is_private_from_the_start(tmp_path, loose_umask, monkeypatch):
    pytest.importorskip("cryptography")
    import artzain.policy_sign as ps

    # With no chmod after the write, a key written world-readable and fixed
    # up afterwards stays readable; one created private does not need it.
    monkeypatch.setattr(os, "chmod", lambda *a, **kw: None)
    monkeypatch.setattr(Path, "chmod", lambda *a, **kw: None)
    ps.generate_keypair(tmp_path / "keys")
    priv = tmp_path / "keys" / ps._PRIV_NAME
    assert _mode(priv) == 0o600
    assert _mode(tmp_path / "keys") == 0o700
    with pytest.raises(ps.PolicySigningError):
        ps.generate_keypair(tmp_path / "keys")


# ── Prompt-defence events ─────────────────────────────────────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", "REPORTS_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    return tmp_path


def test_events_default_to_a_folder_of_the_users_own(home, loose_umask):
    path = events._events_path()
    expected = (home / "localappdata" / "artzain" / "events" if sys.platform == "win32"
                else home / "home" / ".artzain" / "events")
    assert path == expected / "prompt_defense_events.jsonl"
    assert path.parent.is_dir()
    if sys.platform != "win32":
        assert _mode(path.parent) == 0o700


@posix_only
def test_with_no_writable_home_events_go_to_a_temp_folder_of_the_users_own(
        home, monkeypatch, loose_umask):
    # A function sandbox or a container user: the home cannot be written, and
    # the shared temp folder is the only writable place.
    import tempfile

    blocked = home / "home"
    blocked.write_text("not a folder", encoding="utf-8")
    shared_tmp = home / "sys-tmp"
    shared_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared_tmp))
    path = events._events_path()
    folder = shared_tmp / f"artzain-events-{os.geteuid()}"
    assert path == folder / "prompt_defense_events.jsonl"
    assert _mode(folder) == 0o700
    # A folder of the user's own left loose is tightened.
    os.chmod(folder, 0o755)
    events._events_path()
    assert _mode(folder) == 0o700


@posix_only
@pytest.mark.parametrize("squatter", ["link", "file", "theirs", "unsticky"])
def test_a_temp_folder_name_taken_by_something_else_is_refused(
        home, monkeypatch, squatter):
    import tempfile

    from artzain.audit_chain import AuditLogWriteError

    (home / "home").write_text("not a folder", encoding="utf-8")
    shared_tmp = home / "sys-tmp"
    shared_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared_tmp))
    if squatter == "theirs":
        # A real folder, made first by another user.
        monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    taken = shared_tmp / f"artzain-events-{os.geteuid()}"
    elsewhere = home / "elsewhere"
    elsewhere.mkdir()
    if squatter == "link":
        # Another user's folder, reached through a link planted under the name.
        taken.symlink_to(elsewhere, target_is_directory=True)
    elif squatter == "file":
        taken.write_text("", encoding="utf-8")
    elif squatter == "theirs":
        taken.mkdir()
    else:
        # Anyone may write the temp folder, and nothing stops them moving
        # another user's folder out of it.
        os.chmod(shared_tmp, 0o777)
    with pytest.raises(AuditLogWriteError, match="COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR"):
        events._events_path()
    assert list(elsewhere.iterdir()) == []
    if squatter in ("theirs", "unsticky"):
        assert not (shared_tmp / f"artzain-events-{os.getuid()}" / "prompt_defense_events.jsonl").exists()


@posix_only
def test_an_events_folder_that_is_another_users_is_not_written_to(home, monkeypatch):
    from artzain.audit_chain import AuditLogWriteError

    theirs = home / "home" / ".artzain" / "events"
    theirs.mkdir(parents=True)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(AuditLogWriteError):
        events._events_path()
    assert list(theirs.iterdir()) == []
    # Nothing to read there either, rather than an error.
    assert events.read_recent_events() == []


@posix_only
def test_under_sudo_a_new_sdk_folder_is_given_to_the_invoking_user(home, monkeypatch):
    # root, run by sudo with HOME kept: ~/.artzain left root's refused the
    # user their credentials profile later.
    (home / "home").mkdir()
    uid, gid = os.getuid(), os.getgid()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setenv("SUDO_GID", str(gid))
    given: list = []
    monkeypatch.setattr(os, "chown", lambda path, u, g: given.append((Path(path), u, g)))
    events._events_path()
    assert given == [(home / "home" / ".artzain", uid, gid)]
    # One that was there already is left as it is.
    given.clear()
    events._events_path()
    assert given == []


def test_a_configured_events_folder_is_used_as_given(home, monkeypatch):
    chosen = home / "chosen"
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(chosen))
    assert events._events_path() == chosen / "prompt_defense_events.jsonl"
    monkeypatch.delenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR")
    monkeypatch.setenv("REPORTS_DIR", str(home / "reports"))
    assert events._events_path() == home / "reports" / "prompt_defense_events.jsonl"


def test_a_recorded_event_and_its_chain_land_in_the_users_folder(home):
    from artzain.prompt_injection import DetectionResult, ThreatLevel

    result = DetectionResult(is_injection=False, threat_level=ThreatLevel.NONE, injection_type=None,
                             confidence=0.0, explanation="No injection patterns detected")
    events.record_prompt_defense_event(kind="prompt_injection", surface="test", source="user",
                                       result=result, enforcement_action="allowed", text="hello there")
    folder = (home / "localappdata" / "artzain" / "events" if sys.platform == "win32"
              else home / "home" / ".artzain" / "events")
    log = folder / "prompt_defense_events.jsonl"
    assert log.is_file() and "prompt_injection" in log.read_text(encoding="utf-8")
    assert log.with_suffix(".chain_state").is_file()
