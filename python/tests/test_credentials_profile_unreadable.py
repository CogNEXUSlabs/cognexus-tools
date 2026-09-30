"""A credentials profile that cannot be read is not a profile without a key.

``read_profile()`` answered ``{}`` for a profile file that is not there and
for one that is there but cannot be read (another process holds a lock on it,
its permissions shut this user out, it is not UTF-8 text), and every caller
took that for no API key: the policy-rules loader put the built-in conduct
rules alone in place of the tenant's, events were skipped without a word, an
offline decision stood in for the platform's. ``write_profile()`` truncated the
file and wrote it again, so a process reading while ``artzain login`` ran could
find it empty.

What happens now:

* no profile file is still no profile, and ``read_profile()`` keeps answering
  ``{}`` for one that cannot be read;
* ``resolve_credentials()`` refuses instead (a ``CredentialConflictError``,
  naming no value), unless a project ``.env`` supplies both the key and its
  host; it reads the profile once, and so do ``decide()`` and each CLI command;
* the rules loader counts it as a failed fetch, so its backoff and its last
  good copy apply;
* ``write_profile()`` writes a new file beside the profile, private from the
  start, and moves it over the profile.

A profile that cannot be read is made for real: a byte-range lock held on it
on Windows, no permissions elsewhere, or bytes that are not UTF-8.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import errno
import importlib
import json
import logging
import os
import socket
import stat
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Optional

import pytest

from artzain import _helpers, cloud, credentials
from artzain._helpers import load_client_policy_rules
from artzain.policy_enforcement import ClientPolicyRule, builtin_conduct_rules

KEY = "cnx_profile_read_test_0123456789"
HOST = "https://profile.example.test"
#: Another login's key, and the other host it was issued with.
OTHER_KEY = "cnx_profile_read_other_98765432"
OTHER_HOST = "https://other.example.test"
URL = HOST + "/api/policy-enforcement/rules"
GRACE_ENV = "COGNEXUS_BUNDLE_LAST_GOOD_GRACE_SECONDS"

#: Each way a profile that is there can fail to be read.
HOW = pytest.mark.parametrize("how", ["held", "undecodable"])


@contextlib.contextmanager
def _cannot_read(path: Path, how: str) -> Iterator[None]:
    """*path* is there but cannot be read while the block runs.

    ``held``: another process holds it, as each platform shows that: a
    byte-range lock over the file on Windows, no read permission elsewhere.
    ``undecodable``: it holds a byte that is not UTF-8, beside an intact key
    and host.
    """
    if how == "undecodable":
        saved = path.read_bytes()
        path.write_bytes(saved + b"# \xff\n")
        try:
            yield
        finally:
            path.write_bytes(saved)
        return
    if sys.platform == "win32":
        import msvcrt

        with open(path, "rb+") as held:
            span = path.stat().st_size + 1
            msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, span)
            try:
                yield
            finally:
                held.seek(0)
                msvcrt.locking(held.fileno(), msvcrt.LK_UNLCK, span)
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("this user reads a file whatever its permissions say")
        yield
    finally:
        path.chmod(mode)


@pytest.fixture
def profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where the profile goes. No key or host from the machine running the tests."""
    for name in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL", GRACE_ENV):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "home" / ".artzain" / "credentials.toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(path))
    # conftest.py restores the overrides afterwards.
    cloud.configure(api_key=None, base_url=None)
    return path


def _login(key: str = KEY, host: str = HOST) -> None:
    credentials.write_profile(api_key=key, base_url=host)


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def _no_value_in(text: str, profile: Path) -> None:
    for value in (KEY, HOST, OTHER_KEY, OTHER_HOST, str(profile)):
        assert value not in text


def _chained(exc: BaseException) -> list[BaseException]:
    """*exc* and every exception chained to it, as cause or as context."""
    found: list[BaseException] = []
    todo: list[Optional[BaseException]] = [exc]
    while todo:
        each = todo.pop()
        if each is None or any(each is seen for seen in found):
            continue
        found.append(each)
        todo += [each.__cause__, each.__context__]
    return found


def _refuse_reads(monkeypatch: pytest.MonkeyPatch, profile: Path, error: OSError, times: int) -> list[int]:
    """Reads of *profile* raise *error*, the first *times* of them (every one
    for a negative *times*); returns the list the reads are counted in."""
    real_read_bytes = Path.read_bytes
    reads: list[int] = []

    def _read_bytes(self: Path) -> bytes:
        if self == profile:
            reads.append(1)
            if times < 0 or len(reads) <= times:
                raise error
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    return reads


@contextlib.contextmanager
def _no_new_file_beside(profile: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """The profile's directory takes no new file, as an ACL can have it: an
    exclusive create there is refused. Yields the names tried; past fifty the
    retrying is taken to be endless."""
    real_open = os.open
    tried: list[str] = []

    def _open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        name = os.fspath(path)
        if flags & os.O_EXCL and os.path.samefile(os.path.dirname(name), profile.parent):
            tried.append(name)
            if len(tried) > 50:
                raise RuntimeError("an exclusive create was retried without end")
            raise PermissionError(errno.EACCES, "Access is denied")
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", _open)
        yield tried


# ---------------------------------------------------------------------------
# Reading the profile
# ---------------------------------------------------------------------------


def test_no_profile_file_is_a_profile_without_a_key(profile: Path) -> None:
    creds = credentials.resolve_credentials()

    assert (creds.api_key, creds.base_url) == (None, credentials.DEFAULT_BASE_URL)
    assert credentials.read_profile() == {}


def test_a_directory_where_the_profile_goes_is_no_profile(profile: Path) -> None:
    profile.mkdir(parents=True)

    assert credentials.resolve_credentials().api_key is None
    assert credentials.read_profile() == {}


def test_a_profile_path_through_a_file_is_no_profile(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    not_a_directory = tmp_path / "not-a-directory"
    not_a_directory.write_text("", encoding="utf-8")
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(not_a_directory / "credentials.toml"))

    assert credentials.resolve_credentials().api_key is None


@HOW
def test_a_profile_that_cannot_be_read_is_not_one_without_a_key(profile: Path, how: str) -> None:
    _login()

    with _cannot_read(profile, how):
        with pytest.raises(credentials.CredentialConflictError) as caught:
            credentials.resolve_credentials()

    message = str(caught.value)
    assert "credentials profile" in message and "could not be read" in message
    _no_value_in(message, profile)


@HOW
def test_read_profile_still_answers_an_empty_profile_for_one_it_cannot_read(
    profile: Path, how: str
) -> None:
    """``read_profile()`` and its two helpers are public, and their callers
    read ``{}`` and ``None`` as no profile."""
    _login()

    with _cannot_read(profile, how):
        assert credentials.read_profile() == {}
        assert credentials.profile_api_key() is None
        assert credentials.profile_base_url() is None

    assert credentials.profile_api_key() == KEY


@pytest.mark.parametrize("source", ["COGNEXUS_API_KEY", "MYAPP_API_KEY", "configure"])
@HOW
def test_a_key_set_elsewhere_is_not_sent_while_the_profile_cannot_be_read(
    profile: Path, monkeypatch: pytest.MonkeyPatch, source: str, how: str
) -> None:
    """The profile records which host issued its key, and that key goes to no
    other however it is supplied: while the profile cannot be read, no key is
    sent."""
    _login()
    kwargs: dict[str, Any] = {}
    if source == "configure":
        kwargs["api_key"] = KEY
    else:
        monkeypatch.setenv(source, KEY)
    assert credentials.resolve_credentials(**kwargs).base_url == HOST

    with _cannot_read(profile, how):
        with pytest.raises(credentials.CredentialConflictError) as caught:
            credentials.resolve_credentials(**kwargs)

    _no_value_in(str(caught.value), profile)


@HOW
def test_a_dotenv_key_with_its_own_host_needs_no_profile(profile: Path, how: str) -> None:
    """A project ``.env`` that sets both says where its key goes; one that sets
    only the key may hold the profile's."""
    _login()

    with _cannot_read(profile, how):
        creds = credentials.resolve_credentials(dotenv=(OTHER_KEY, OTHER_HOST, "project .env"))
        assert (creds.api_key, creds.base_url) == (OTHER_KEY, OTHER_HOST)
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials(dotenv=(OTHER_KEY, None, "project .env"))


def test_a_resolution_reads_the_profile_once(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile is rewritten between two reads: the key and the host still
    come from one version of it."""
    first, second = tmp_path / "first.toml", tmp_path / "second.toml"
    for path, key, host in ((first, KEY, HOST), (second, OTHER_KEY, OTHER_HOST)):
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(path))
        _login(key, host)
    reads: list[Path] = []

    def _each_read_a_newer_version() -> Path:
        reads.append(first if not reads else second)
        return reads[-1]

    monkeypatch.setattr(credentials, "credentials_path", _each_read_a_newer_version)

    creds = credentials.resolve_credentials()

    assert (creds.api_key, creds.base_url) == (KEY, HOST)
    assert reads == [first]


def test_a_profile_being_rewritten_never_reads_as_one_without_a_key(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``artzain login`` in one process while another reads the profile: the
    reader finds one whole version or the other, never an empty or half written
    file. On Windows a read that meets the rename itself can still fail after
    its retries; that refuses to send, which is no pairing and no missing key.

    The reader and the writer meet at the move, not by racing on the wall
    clock: the new file is filled, the move waits, the reader runs, then the
    move goes through and the reader runs again. A free-running rewrite loop
    depended on thread scheduling and, on Windows, on the replace retry
    budget while readers kept the profile open.
    """
    versions = {(KEY, HOST), (OTHER_KEY, OTHER_HOST)}
    _login()
    ready_to_replace = threading.Event()
    allow_replace = threading.Event()
    replaced = threading.Event()
    real_replace = os.replace
    errors: list[BaseException] = []
    seen: collections.Counter[tuple[Optional[str], str]] = collections.Counter()
    refused = 0

    def _gated_replace(src: Any, dst: Any) -> None:
        ready_to_replace.set()
        if not allow_replace.wait(10):
            raise TimeoutError("the reader did not release the move")
        real_replace(src, dst)
        replaced.set()

    def _rewrite(key: str, host: str) -> None:
        try:
            _login(key, host)
        except BaseException as exc:
            errors.append(exc)

    def _observe() -> Optional[tuple[Optional[str], str]]:
        nonlocal refused
        try:
            creds = credentials.resolve_credentials()
        except credentials.CredentialConflictError:
            refused += 1
            return None
        pair = (creds.api_key, creds.base_url)
        seen[pair] += 1
        return pair

    monkeypatch.setattr(os, "replace", _gated_replace)

    previous = (KEY, HOST)
    for i in range(20):
        nxt = (OTHER_KEY, OTHER_HOST) if i % 2 == 0 else (KEY, HOST)
        ready_to_replace.clear()
        allow_replace.clear()
        replaced.clear()
        writer = threading.Thread(target=_rewrite, args=nxt)
        writer.start()
        assert ready_to_replace.wait(10), "the writer never reached the move"
        # New file filled; the profile path still names the previous whole version.
        pair = _observe()
        if pair is None:
            assert sys.platform == "win32"
        else:
            assert pair == previous
        allow_replace.set()
        assert replaced.wait(10), "the move never finished"
        writer.join(10)
        assert not writer.is_alive()
        assert errors == []
        pair = _observe()
        if pair is None:
            assert sys.platform == "win32"
        else:
            assert pair == nxt
        previous = nxt

    assert errors == []
    assert set(seen) <= versions, (
        f"a read found {sorted(map(repr, set(seen) - versions))[:3]}: no key, or one "
        "version's key with the other's host"
    )
    assert set(seen) == versions
    if sys.platform != "win32":
        assert refused == 0


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_a_profile_this_user_cannot_reach_is_no_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another user's home directory, which this user may not search, as in a
    container run as a user whose HOME is root's: whatever it holds is not this
    user's profile, and a key set in the environment still goes out."""
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", OTHER_KEY)
    home = profile.parent
    mode = stat.S_IMODE(home.stat().st_mode)
    home.chmod(0)
    try:
        if os.access(profile, os.F_OK):
            pytest.skip("this user reaches a path whatever its directory's permissions say")
        # The directory is another user's.
        monkeypatch.setattr(os, "geteuid", lambda: home.stat().st_uid + 1)
        creds = credentials.resolve_credentials()
    finally:
        home.chmod(mode)

    assert (creds.api_key, creds.base_url) == (OTHER_KEY, credentials.DEFAULT_BASE_URL)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_a_profile_in_a_directory_of_this_users_own_it_may_not_search_is_not_skipped(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This user's own directory, its search permission taken away by mistake:
    the profile in it is theirs, and cannot be read."""
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    home = profile.parent
    mode = stat.S_IMODE(home.stat().st_mode)
    home.chmod(0o600)
    try:
        if os.access(profile, os.F_OK):
            pytest.skip("this user reaches a path whatever its directory's permissions say")
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials()
    finally:
        home.chmod(mode)


@pytest.mark.parametrize("err", [errno.EIO, errno.ESTALE, getattr(errno, "EHOSTDOWN", errno.EIO)])
def test_a_profile_the_system_fails_to_look_at_is_not_skipped(
    profile: Path, monkeypatch: pytest.MonkeyPatch, err: int
) -> None:
    """An I/O or network error when looking at the path says nothing about
    whether a profile is there."""
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    real_stat, real_lstat = os.stat, os.lstat

    def _failing(real: Any) -> Any:
        def _look(path: Any, *args: Any, **kwargs: Any) -> Any:
            if os.fspath(path) == str(profile):
                raise OSError(err, os.strerror(err))
            return real(path, *args, **kwargs)

        return _look

    monkeypatch.setattr(os, "stat", _failing(real_stat))
    monkeypatch.setattr(os, "lstat", _failing(real_lstat))

    with pytest.raises(credentials.CredentialConflictError):
        credentials.resolve_credentials()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows error codes")
@pytest.mark.parametrize(
    ("winerror", "no_file"),
    [(123, True), (1921, True), (161, True), (53, False), (67, False), (64, False), (21, False)],
    ids=["invalid-name", "symlink-loop", "bad-path", "network-path-gone", "share-gone",
         "network-name-deleted", "device-not-ready"],
)
def test_what_windows_says_of_the_path_decides_whether_there_is_no_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch, winerror: int, no_file: bool
) -> None:
    """A name no file can have, and a symlink loop, are no profile, as before.
    A network path or share that cannot be reached, which Python reports as a
    file not found, or a device that is not ready, may hold one."""
    _login()
    real_stat = os.stat

    def _stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == str(profile):
            raise OSError(errno.EINVAL, "error", os.fspath(path), winerror)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", _stat)

    if no_file:
        assert credentials.resolve_credentials().api_key is None
    else:
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials()


@pytest.mark.parametrize("kind", ["pipe", "socket", "device"])
def test_what_is_not_a_file_where_the_profile_goes_is_no_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Not opened either: a read of a pipe waits for a writer, and a device
    may never end."""
    server: Optional[socket.socket] = None
    if kind == "device":
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", os.devnull)
    elif sys.platform == "win32":
        pytest.skip("POSIX pipes and sockets")
    else:
        profile.parent.mkdir(parents=True)
        if kind == "pipe":
            os.mkfifo(profile)
        else:
            # Bound by a short relative name: a socket path has a length limit.
            monkeypatch.chdir(profile.parent)
            server = socket.socket(socket.AF_UNIX)
            server.bind(profile.name)
    outcome: dict[str, Any] = {}

    def _resolve() -> None:
        try:
            outcome["creds"] = credentials.resolve_credentials()
        except BaseException as exc:
            outcome["error"] = exc

    try:
        resolving = threading.Thread(target=_resolve, daemon=True)
        resolving.start()
        resolving.join(10)
        if resolving.is_alive():
            # Stuck opening the pipe: let it go before failing.
            os.close(os.open(profile, os.O_WRONLY | os.O_NONBLOCK))
            resolving.join(10)
            pytest.fail("the resolution waited on what is at the profile path")
    finally:
        if server is not None:
            server.close()

    assert "error" not in outcome, outcome.get("error")
    assert outcome["creds"].api_key is None
    assert credentials.read_profile() == {}


def test_a_path_no_file_can_have_is_no_profile(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = "credentials<>.toml" if sys.platform == "win32" else "x" * 300 + ".toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / name))

    assert credentials.resolve_credentials().api_key is None
    assert credentials.read_profile() == {}


def test_an_error_reading_a_profile_that_is_there_is_not_no_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows reports many failures to read a file that is there with the
    errno it also gives for a name no file can have."""
    _login()
    _refuse_reads(monkeypatch, profile, OSError(errno.EINVAL, "Invalid argument"), times=-1)

    with pytest.raises(credentials.CredentialConflictError):
        credentials.resolve_credentials()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege on Windows")
def test_a_symlink_loop_where_the_profile_goes_is_no_profile(profile: Path) -> None:
    profile.parent.mkdir(parents=True)
    profile.symlink_to(profile)

    assert credentials.resolve_credentials().api_key is None


def test_a_read_refused_for_a_moment_is_tried_again(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows a read that meets the profile being replaced is refused for a
    moment."""
    _login()
    monkeypatch.setattr(credentials, "_READ_RETRY_DELAYS", (0.0, 0.0, 0.0))
    reads = _refuse_reads(monkeypatch, profile, PermissionError(errno.EACCES, "Permission denied"), times=2)

    assert credentials.resolve_credentials().api_key == KEY
    assert len(reads) == 3


def test_a_profile_that_keeps_refusing_is_not_waited_for_on_every_call(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lock another process keeps would add the waits to every call that
    resolves the credentials. They come back once the file changes."""
    _login()
    monkeypatch.setattr(credentials, "_READ_RETRY_DELAYS", (0.0, 0.0))
    with monkeypatch.context() as patch:
        reads = _refuse_reads(patch, profile, PermissionError(errno.EACCES, "Permission denied"), times=-1)
        for _ in range(3):
            with pytest.raises(credentials.CredentialConflictError):
                credentials.resolve_credentials()
        assert len(reads) == 3 + 1 + 1

        _login(OTHER_KEY, OTHER_HOST)
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials()
        assert len(reads) == 3 + 1 + 1 + 3

    assert credentials.resolve_credentials().api_key == OTHER_KEY


@HOW
def test_the_refusal_carries_nothing_read_from_the_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """Not chained to the error that names the path, nor to the decoding error
    that holds the file's bytes, key and all."""
    decide_mod = importlib.import_module("artzain.decide")
    _login()
    monkeypatch.setattr(cloud, "_urlopen", lambda req, timeout=None: pytest.fail("sent"))

    with _cannot_read(profile, how):
        with pytest.raises(credentials.CredentialConflictError) as caught:
            credentials.resolve_credentials()
        with pytest.raises(decide_mod.DecisionError) as refused:
            decide_mod.decide(action="send_email", target="crm:contact:1", payload="hi", kind="user_input")

    assert (caught.value.__cause__, caught.value.__context__) == (None, None)
    for exc in _chained(refused.value):
        _no_value_in(f"{exc!s} {exc!r} {exc.args!r} {getattr(exc, 'filename', '')}", profile)


def test_the_refusal_leaves_no_copy_of_the_file_where_it_was_raised(profile: Path) -> None:
    """A tool that records the variables of each frame in a traceback does not
    find the file's bytes, key and all, in the reader's."""
    _login()

    with _cannot_read(profile, "undecodable"):
        with pytest.raises(credentials.CredentialConflictError) as caught:
            credentials.resolve_credentials()

    frames = []
    tb = caught.value.__traceback__
    while tb is not None:
        frames.append(tb.tb_frame)
        tb = tb.tb_next
    assert any(f.f_code.co_name == "_load_profile" for f in frames)
    for frame in frames:
        if frame.f_code.co_filename == credentials.__file__:
            for name, value in frame.f_locals.items():
                assert KEY not in repr(value), f"{frame.f_code.co_name}.{name} holds the key"


def test_the_environment_keys_are_read_in_order(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYAPP_API_KEY", OTHER_KEY)
    assert credentials.resolve_credentials().key_source == "MYAPP_API_KEY"
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    creds = credentials.resolve_credentials()
    assert (creds.api_key, creds.key_source) == (KEY, "COGNEXUS_API_KEY")
    assert credentials.resolve_credentials(api_key=OTHER_KEY).key_source == "configure(api_key=...)"


# ---------------------------------------------------------------------------
# Writing the profile
# ---------------------------------------------------------------------------


def test_write_profile_moves_a_new_file_over_the_profile(profile: Path) -> None:
    """Written beside the profile and moved over it, never truncated and
    written again, and nothing left beside it."""
    _login()
    before = profile.stat().st_ino

    _login(OTHER_KEY, OTHER_HOST)

    assert profile.stat().st_ino != before
    assert credentials.read_profile() == {"api_key": OTHER_KEY, "base_url": OTHER_HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_profile_is_private_from_its_creation(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not created readable by others and narrowed afterwards: a process that
    dies in between leaves no key for others to read."""
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: None)
    umask = os.umask(0o022)
    try:
        _login()
    finally:
        os.umask(umask)

    assert stat.S_IMODE(profile.stat().st_mode) == 0o600


def test_a_failed_move_leaves_the_profile_as_it_was(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login()

    def _fails(src: Any, dst: Any) -> None:
        raise OSError(errno.EIO, "Input/output error")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", _fails)
        with pytest.raises(OSError):
            _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


def test_a_move_another_process_blocks_is_tried_again(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows refuses to move a file over one another process has open, which
    a reader does for a moment."""
    _login()
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_SECONDS", 5.0, raising=False)
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_INTERVAL", 0.0, raising=False)
    real_replace = os.replace
    moves: list[Any] = []

    def _blocked_twice(src: Any, dst: Any) -> None:
        moves.append(dst)
        if len(moves) <= 2:
            raise PermissionError(errno.EACCES, "The process cannot access the file")
        real_replace(src, dst)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", _blocked_twice)
        _login(OTHER_KEY, OTHER_HOST)

    assert len(moves) == 3
    assert credentials.read_profile() == {"api_key": OTHER_KEY, "base_url": OTHER_HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


def test_a_profile_that_stays_blocked_is_left_as_it_was(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not rewritten in place instead: Windows truncates a file another process
    has locked and then refuses the write, which would leave it empty."""
    _login()
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_SECONDS", 0.05, raising=False)
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_INTERVAL", 0.001, raising=False)

    def _blocked(src: Any, dst: Any) -> None:
        raise PermissionError(errno.EACCES, "The process cannot access the file")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", _blocked)
        with pytest.raises(PermissionError):
            _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows byte-range locks")
def test_a_locked_profile_is_not_emptied(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _login()
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_SECONDS", 0.05, raising=False)
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_INTERVAL", 0.001, raising=False)

    with _cannot_read(profile, "held"):
        with pytest.raises(OSError):
            _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


def test_a_directory_that_takes_no_new_file_has_the_profile_written_in_place(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Still written, as before, and at once rather than after trying name
    after name (which is what tempfile does on Windows for as long as the
    directory is not read-only). A profile others could read before is its
    owner's alone after, and holds the new profile and nothing of the old."""
    elsewhere = tmp_path / "elsewhere" / "credentials.toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(elsewhere))
    _login(OTHER_KEY, OTHER_HOST)
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(profile))
    _login()
    if sys.platform != "win32":
        profile.chmod(0o644)

    with _no_new_file_beside(profile, monkeypatch) as tried:
        _login(OTHER_KEY, OTHER_HOST)

    assert profile.read_bytes() == elsewhere.read_bytes()
    assert 1 <= len(tried) <= 3
    if sys.platform != "win32":
        assert stat.S_IMODE(profile.stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="Windows byte-range locks")
def test_a_locked_profile_rewritten_in_place_is_not_emptied(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rewritten in place because its directory takes no new file, while
    another program holds a lock on it: Windows would truncate it and then
    refuse the write, so it is refused before anything in it changes."""
    _login()

    with _cannot_read(profile, "held"), _no_new_file_beside(profile, monkeypatch):
        with pytest.raises(OSError):
            _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}


def test_only_what_an_interrupted_write_leaves_is_removed(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a name the writes do not make, nor a link, and a file's age is told
    by the file system's clock rather than this machine's, which may run ahead
    of it (a network file system, a clock just set)."""
    _login()
    old = time.time() - 86400
    not_hex = profile.with_name(f".{profile.name}.{'z' * 12}.tmp")
    not_hex.write_text("", encoding="utf-8")
    os.utime(not_hex, (old, old))
    recent = profile.with_name(f".{profile.name}.{'3' * 12}.tmp")
    recent.write_text("", encoding="utf-8")
    kept = [not_hex.name, recent.name]
    if sys.platform != "win32":
        link = profile.with_name(f".{profile.name}.{'4' * 12}.tmp")
        link.symlink_to(not_hex)
        os.utime(link, (old, old), follow_symlinks=False)
        kept.append(link.name)
    ahead = time.time() + 2 * 3600
    monkeypatch.setattr(credentials.time, "time", lambda: ahead)

    _login(OTHER_KEY, OTHER_HOST)

    assert _listing(profile.parent) == sorted(["credentials.toml", *kept])


def test_a_new_profile_left_by_an_interrupted_write_is_removed(profile: Path) -> None:
    """A write stopped between making the new file and moving it leaves that
    file, key and all, beside the profile. The next write removes it, once it
    is old enough not to be another write's, however slow that one is (a
    stalled disk, a suspended process)."""
    _login()
    stale = profile.with_name(f".{profile.name}.{'0' * 12}.tmp")
    minutes_old = profile.with_name(f".{profile.name}.{'1' * 12}.tmp")
    recent = profile.with_name(f".{profile.name}.{'2' * 12}.tmp")
    unrelated = profile.with_name(f".{profile.name}.bak")
    for path in (stale, minutes_old, recent, unrelated):
        path.write_text('api_key = "cnx_left_behind_0123456789"\n', encoding="utf-8")
    now = time.time()
    os.utime(stale, (now - 86400, now - 86400))
    os.utime(minutes_old, (now - 300, now - 300))

    _login(OTHER_KEY, OTHER_HOST)

    assert _listing(profile.parent) == sorted(
        ["credentials.toml", minutes_old.name, recent.name, unrelated.name]
    )


def test_a_write_interrupted_before_the_move_leaves_no_new_file(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login()

    def _interrupted(src: Any, dst: Any) -> None:
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", _interrupted)
        with pytest.raises(KeyboardInterrupt):
            _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_profile_is_its_owners_to_read_and_write_whatever_the_umask(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile.parent.mkdir(parents=True)
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: None)
    umask = os.umask(0o277)
    try:
        _login()
    finally:
        os.umask(umask)

    assert stat.S_IMODE(profile.stat().st_mode) == 0o600


def test_login_says_so_when_it_cannot_save_the_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Approved in the browser, then the profile stays held: a message that
    says what to do, rather than a traceback."""
    import webbrowser

    from artzain import cli

    answers = iter(
        [
            (200, {"device_code": "d", "user_code": "ABCD", "interval": 1, "expires_in": 60}),
            (200, {"ok": True, "sandbox": {"api_key": {"key": KEY}}}),
        ]
    )
    monkeypatch.setattr(cli, "_http_json", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    monkeypatch.setattr(webbrowser, "open", lambda *args, **kwargs: True)

    def _held(**kwargs: Any) -> Path:
        raise PermissionError(errno.EACCES, "The process cannot access the file")

    monkeypatch.setattr(credentials, "write_profile", _held)

    with pytest.raises(SystemExit) as caught:
        cli.cmd_login(argparse.Namespace())

    message = str(caught.value)
    assert "credentials profile" in message and "artzain login" in message
    _no_value_in(message, profile)
    assert os.environ.get("COGNEXUS_API_KEY") != KEY
    # Nothing chained: the error names the paths, and its frames hold the key.
    assert (caught.value.__cause__, caught.value.__context__) == (None, None)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege on Windows")
def test_a_profile_that_is_a_symlink_stays_one(profile: Path, tmp_path: Path) -> None:
    """Written through the link, as before, rather than replacing it."""
    target = tmp_path / "dotfiles" / "credentials.toml"
    target.parent.mkdir()
    target.write_text("", encoding="utf-8")
    profile.parent.mkdir(parents=True)
    profile.symlink_to(target)

    _login()

    assert profile.is_symlink()
    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(target.parent) == ["credentials.toml"]


@pytest.mark.parametrize("how", ["path", "symlink"])
def test_a_profile_kept_on_the_null_device_stays_there(
    profile: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """The null device, to keep no key: written to as before, never replaced by
    a file or its mode or its directory's changed."""
    if how == "path":
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", os.devnull)
    elif sys.platform == "win32":
        pytest.skip("symlinks need a privilege on Windows")
    else:
        profile.parent.mkdir(parents=True)
        profile.symlink_to(os.devnull)
    before = os.stat(os.devnull)

    _login()

    after = os.stat(os.devnull)
    assert not stat.S_ISREG(after.st_mode)
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert credentials.resolve_credentials().api_key is None


def test_a_move_blocked_again_and_again_is_tried_until_it_goes_through(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Readers that keep the profile open in turn block the move time after
    time: it is tried often for a few seconds, not a dozen times."""
    _login()
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_SECONDS", 5.0, raising=False)
    monkeypatch.setattr(credentials, "_REPLACE_RETRY_INTERVAL", 0.0, raising=False)
    real_replace = os.replace
    moves: list[Any] = []

    def _blocked_a_hundred_times(src: Any, dst: Any) -> None:
        moves.append(dst)
        if len(moves) <= 100:
            raise PermissionError(errno.EACCES, "The process cannot access the file")
        real_replace(src, dst)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", _blocked_a_hundred_times)
        _login(OTHER_KEY, OTHER_HOST)

    assert len(moves) == 101
    assert credentials.read_profile() == {"api_key": OTHER_KEY, "base_url": OTHER_HOST}


def _pretend_to_run_as_root(monkeypatch: pytest.MonkeyPatch, sudo_for: Optional[int]) -> list[tuple[int, int]]:
    """This process runs as root, under ``sudo`` for the user *sudo_for* (no
    ``sudo`` for ``None``). Returns the list of owners new files are given; the
    change itself is made to this process's own ids, which it may."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    for name in ("SUDO_UID", "SUDO_GID"):
        monkeypatch.delenv(name, raising=False)
    if sudo_for is not None:
        monkeypatch.setenv("SUDO_UID", str(sudo_for))
        monkeypatch.setenv("SUDO_GID", str(os.getgid()))
    real_fchown = os.fchown
    given: list[tuple[int, int]] = []

    def _fchown(fd: int, uid: int, gid: int) -> None:
        given.append((uid, gid))
        real_fchown(fd, os.getuid(), os.getgid())

    monkeypatch.setattr(os, "fchown", _fchown)
    return given


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX file owners, pretended as a user who is not root",
)
@pytest.mark.parametrize("before", ["a-profile", "no-profile-yet"])
def test_sudo_gives_the_new_profile_to_the_user_it_runs_for(
    profile: Path, monkeypatch: pytest.MonkeyPatch, before: str
) -> None:
    """``sudo artzain login`` with HOME kept: the profile it replaces, or the
    directory a new one goes in, is the invoking user's, and so is the new
    profile, which they could not read as root's."""
    if before == "a-profile":
        _login()
    else:
        profile.parent.mkdir(parents=True)
    given = _pretend_to_run_as_root(monkeypatch, sudo_for=os.getuid())

    _login(OTHER_KEY, OTHER_HOST)

    assert given == [(os.getuid(), os.getgid())]
    assert credentials.read_profile() == {"api_key": OTHER_KEY, "base_url": OTHER_HOST}


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX file owners, pretended as a user who is not root",
)
@pytest.mark.parametrize("sudo_for", [None, 4242], ids=["root-itself", "sudo-for-another-user"])
def test_a_new_key_is_not_handed_to_whoever_owns_the_file_it_replaces(
    profile: Path, monkeypatch: pytest.MonkeyPatch, sudo_for: Optional[int]
) -> None:
    """Root is asked to rewrite a profile that is another user's and not the
    invoking user's (``su -p``, a service): refused, the profile left as it
    was, rather than handing that user the new key or taking the profile from
    them."""
    _login()
    given = _pretend_to_run_as_root(monkeypatch, sudo_for=sudo_for)

    with pytest.raises(PermissionError):
        _login(OTHER_KEY, OTHER_HOST)

    assert given == []
    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file owners")
def test_a_profile_of_another_users_is_not_taken_over(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory shared with a group, where another member's profile sits:
    the write is refused, as writing it in place was when it could not open
    that member's file, rather than replacing it with the writer's, which
    would leave that member without it."""
    _login()
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)

    with pytest.raises(PermissionError):
        _login(OTHER_KEY, OTHER_HOST)

    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}
    assert _listing(profile.parent) == ["credentials.toml"]


def _own_passwd_entry() -> Any:
    import pwd

    try:
        return pwd.getpwuid(os.getuid())
    except KeyError:
        pytest.skip("this user has no passwd entry")


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX file owners, pretended as a user who is not root",
)
def test_doas_gives_the_new_profile_to_the_user_it_runs_for(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``doas`` with the environment kept names the invoking user in DOAS_USER."""
    entry = _own_passwd_entry()
    _login()
    given = _pretend_to_run_as_root(monkeypatch, sudo_for=None)
    monkeypatch.setenv("DOAS_USER", entry.pw_name)

    _login(OTHER_KEY, OTHER_HOST)

    assert given == [(entry.pw_uid, entry.pw_gid)]
    assert credentials.read_profile() == {"api_key": OTHER_KEY, "base_url": OTHER_HOST}


def _root_only() -> Any:
    return pytest.mark.skipif(
        sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() != 0,
        reason="root rewriting another user's profile",
    )


@_root_only()
def test_root_under_sudo_leaves_a_users_profile_theirs(profile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _login()
    os.chown(profile.parent, 1000, 1000)
    os.chown(profile, 1000, 1000)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    _login(OTHER_KEY, OTHER_HOST)

    info = profile.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (1000, 1000, 0o600)


@_root_only()
def test_root_does_not_give_a_key_to_the_owner_of_a_file_it_replaces(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login()
    os.chown(profile, 1001, 1001)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    with pytest.raises(PermissionError):
        _login(OTHER_KEY, OTHER_HOST)

    info = profile.stat()
    assert info.st_uid == 1001
    assert credentials.read_profile() == {"api_key": KEY, "base_url": HOST}


@_root_only()
def test_root_does_not_follow_a_link_another_user_made(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kernel refuses to follow such a link in a shared directory; the key
    is not written where another user points it either."""
    elsewhere = tmp_path / "elsewhere.toml"
    elsewhere.write_text("kept\n", encoding="utf-8")
    profile.parent.mkdir(parents=True)
    profile.symlink_to(elsewhere)
    os.lchown(profile, 1001, 1001)
    monkeypatch.setenv("SUDO_UID", "1000")

    with pytest.raises(PermissionError):
        _login()

    assert elsewhere.read_text(encoding="utf-8") == "kept\n"
    assert profile.is_symlink()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pipes")
def test_a_pipe_nothing_reads_where_the_profile_goes_is_refused_not_waited_on(profile: Path) -> None:
    profile.parent.mkdir(parents=True)
    os.mkfifo(profile)
    outcome: dict[str, BaseException] = {}

    def _write() -> None:
        try:
            _login()
        except BaseException as exc:
            outcome["error"] = exc

    writing = threading.Thread(target=_write, daemon=True)
    writing.start()
    writing.join(10)
    if writing.is_alive():
        # Waiting for a reader: be one, so that it ends, before failing.
        reader = os.open(profile, os.O_RDONLY | os.O_NONBLOCK)
        writing.join(10)
        os.close(reader)
        pytest.fail("the write waited for something to read the pipe")

    assert isinstance(outcome.get("error"), OSError)


@pytest.mark.skipif(sys.platform == "win32" or not os.path.isdir("/dev/fd"), reason="POSIX /dev/fd")
def test_a_profile_path_that_names_a_pipe_by_its_descriptor_is_written_to_it(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/dev/stdout`` of a command whose output goes to a pipe, say."""
    read_end, write_end = os.pipe()
    try:
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", f"/dev/fd/{write_end}")
        _login()
    finally:
        os.close(write_end)
    with os.fdopen(read_end, "rb") as written:
        data = written.read()

    assert f'api_key = "{KEY}"'.encode() in data


def _stat_of(monkeypatch: pytest.MonkeyPatch, directory: Path, **changes: int) -> None:
    """``os.stat`` of *directory* answers with *changes* made to what it says."""
    real_stat = os.stat
    fields = ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size")

    def _stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        info = real_stat(path, *args, **kwargs)
        if os.fspath(path) != str(directory):
            return info
        values = [changes.get(name, getattr(info, name)) for name in fields]
        return os.stat_result([*values, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)])

    monkeypatch.setattr(os, "stat", _stat)


@contextlib.contextmanager
def _closed(directory: Path, mode_while_closed: int = 0) -> Iterator[None]:
    """*directory* may not be searched while the block runs."""
    mode = stat.S_IMODE(directory.stat().st_mode)
    directory.chmod(mode_while_closed)
    try:
        if os.access(directory / "x", os.F_OK) or os.access(directory, os.X_OK):
            pytest.skip("this user searches a directory whatever its permissions say")
        yield
    finally:
        directory.chmod(mode)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
@pytest.mark.parametrize("why", ["mounted-over", "unmapped-owner"])
def test_a_home_hidden_from_this_process_is_not_its_profile(
    profile: Path, monkeypatch: pytest.MonkeyPatch, why: str
) -> None:
    """A service whose home is hidden by the sandbox it runs in (systemd's
    ProtectHome mounts an inaccessible directory over it, which even root may
    not search without its capabilities), or a user namespace that shows every
    user it does not map, this process included, as the overflow uid."""
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", OTHER_KEY)
    home = profile.parent
    with _closed(home):
        if why == "mounted-over":
            # A root service: the inaccessible directory is root's too.
            monkeypatch.setattr(os, "geteuid", lambda: 0)
            _stat_of(monkeypatch, home, st_dev=home.parent.stat().st_dev + 1, st_uid=0)
        else:
            monkeypatch.setattr(credentials, "_overflow_uid", lambda: 65534, raising=False)
            monkeypatch.setattr(os, "geteuid", lambda: 65534)
            _stat_of(monkeypatch, home, st_uid=65534)
        creds = credentials.resolve_credentials()

    assert (creds.api_key, creds.base_url) == (OTHER_KEY, credentials.DEFAULT_BASE_URL)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
@pytest.mark.parametrize("mode", [0o600, 0o000], ids=["no-search", "nothing"])
def test_a_home_of_this_users_own_on_a_mount_of_its_own_closed_by_mistake_is_not_skipped(
    profile: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    """A home on its own mount (an NFS automount, a ZFS dataset, systemd-homed,
    a bind mount) is not a sandbox's: closed by its own user, the profile in it
    is theirs. A sandbox mounts a directory of root's that nobody may read,
    write or search."""
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    home = profile.parent
    with _closed(home, mode_while_closed=mode):
        _stat_of(monkeypatch, home, st_dev=home.parent.stat().st_dev + 1)
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_a_directory_on_the_way_that_cannot_be_looked_at_is_not_skipped(
    profile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login()
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    home = profile.parent
    with _closed(home):
        real_stat = os.stat

        def _stat(path: Any, *args: Any, **kwargs: Any) -> Any:
            if os.fspath(path) == str(home):
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(os, "stat", _stat)
        with pytest.raises(credentials.CredentialConflictError):
            credentials.resolve_credentials()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
def test_a_directory_chosen_for_the_profile_keeps_its_mode(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``COGNEXUS_CREDENTIALS_PATH`` in a directory that is there already, and
    may be shared: the profile is its owner's alone, the directory is left as
    it is. Only the SDK's own directory, or one the write makes, is closed to
    others."""
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o755)
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(shared / "credentials.toml"))

    _login()

    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert stat.S_IMODE((shared / "credentials.toml").stat().st_mode) == 0o600
    made = tmp_path / "made" / "credentials.toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(made))
    _login()
    assert stat.S_IMODE(made.parent.stat().st_mode) == 0o700


# ---------------------------------------------------------------------------
# What the callers do with it
# ---------------------------------------------------------------------------


@HOW
def test_events_are_held_back_with_a_warning(
    profile: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, how: str
) -> None:
    _login()
    queued: list[Any] = []
    monkeypatch.setattr(cloud, "_enqueue_post", lambda item: queued.append(item) or True)
    monkeypatch.setattr(cloud, "_session_logged", True)

    with _cannot_read(profile, how), caplog.at_level(logging.WARNING, logger="artzain"):
        cloud.post_sdk_event("guard.block", title="t", payload={})

    assert queued == []
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("credentials profile" in m and "could not be read" in m for m in warnings)
    _no_value_in(" ".join(warnings), profile)

    cloud.post_sdk_event("guard.block", title="t", payload={})
    assert [item.url for item in queued] == [HOST + "/api/events"]


@HOW
def test_decide_does_not_go_offline_while_the_profile_cannot_be_read(
    profile: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    """A profile is there, so the platform decides: an offline decision would
    screen without the team's rules and leave no audit record."""
    decide_mod = importlib.import_module("artzain.decide")
    _login()
    sent: list[Any] = []
    monkeypatch.setattr(cloud, "_urlopen", lambda req, timeout=None: sent.append(req))

    with _cannot_read(profile, how):
        with pytest.raises(decide_mod.DecisionError) as caught:
            decide_mod.decide(action="send_email", target="crm:contact:1", payload="hi", kind="user_input")

    assert sent == []
    assert "credentials profile" in str(caught.value)
    _no_value_in(str(caught.value), profile)


@HOW
def test_a_cli_command_stops_and_says_why(profile: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    from artzain import cli

    monkeypatch.setattr(cli, "_iter_dotenv_paths", lambda start=None: iter(()))
    _login()

    with _cannot_read(profile, how):
        with pytest.raises(SystemExit) as caught:
            cli._cli_credentials()

    assert "credentials profile" in str(caught.value)
    _no_value_in(str(caught.value), profile)


def _two_logins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Two profiles: one with KEY for HOST, one with OTHER_KEY for OTHER_HOST."""
    first, second = tmp_path / "first.toml", tmp_path / "second.toml"
    for path, key, host in ((first, KEY, HOST), (second, OTHER_KEY, OTHER_HOST)):
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(path))
        _login(key, host)
    return first, second


def test_decide_reads_the_credentials_once(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile cannot be read by the time it would be read a second time:
    the decision that had a key is not made offline."""
    decide_mod = importlib.import_module("artzain.decide")
    first, _ = _two_logins(tmp_path, monkeypatch)
    unreadable = tmp_path / "unreadable.toml"
    unreadable.write_bytes(first.read_bytes() + b"# \xff\n")
    reads: list[Path] = []

    def _then_unreadable() -> Path:
        reads.append(first if not reads else unreadable)
        return reads[-1]

    monkeypatch.setattr(credentials, "credentials_path", _then_unreadable)
    sent: list[tuple[str, Optional[str]]] = []

    def _urlopen(req: Any, timeout: Optional[float] = None) -> _Answer:
        sent.append((req.full_url, req.get_header("X-api-key")))
        decision = {"outcome": "allow", "decision_id": "d", "audit_block_id": "b",
                    "contributing_agents": [], "reasons": []}
        return _Answer(json.dumps(decision).encode("utf-8"))

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)

    result = decide_mod.decide(action="send_email", target="crm:contact:1", payload="hi", kind="user_input")

    assert result.get("offline") is not True
    assert sent == [(HOST + "/api/v1/decisions", KEY)]
    assert reads == [first]


COMMANDS = [
    pytest.param("cmd_registry_list", {"limit": 10, "q": None, "source": None, "lifecycle": None,
                                       "json": True}, id="registry-list"),
    pytest.param("cmd_registry_findings", {"status": "open", "kind": None, "json": True},
                 id="registry-findings"),
    pytest.param("cmd_policy_diff", {"a": "1", "b": "2"}, id="policy-diff"),
]


@pytest.mark.parametrize(("command", "fields"), COMMANDS)
def test_a_cli_command_sends_the_key_to_the_host_read_with_it(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, fields: dict[str, Any]
) -> None:
    """The profile is rewritten while the command runs: its request carries a
    key and goes to that key's host, from one reading."""
    from artzain import cli

    monkeypatch.setattr(cli, "_iter_dotenv_paths", lambda start=None: iter(()))
    first, second = _two_logins(tmp_path, monkeypatch)
    reads: list[Path] = []

    def _alternating() -> Path:
        reads.append(second if len(reads) % 2 else first)
        return reads[-1]

    monkeypatch.setattr(credentials, "credentials_path", _alternating)
    requests: list[tuple[str, Optional[str]]] = []

    def _http_json(method: str, url: str, *, headers: Any = None, body: Any = None,
                   timeout_sec: float = 30.0) -> tuple[int, dict[str, Any]]:
        requests.append((url, dict(headers or {}).get("X-Api-Key")))
        return 200, {"entries": [], "total": 0, "findings": []}

    monkeypatch.setattr(cli, "_http_json", _http_json)

    getattr(cli, command)(argparse.Namespace(**fields))

    [(url, key)] = requests
    assert (url.startswith(HOST + "/") and key == KEY) or (
        url.startswith(OTHER_HOST + "/") and key == OTHER_KEY
    ), "the key from one reading went to the host from another"
    assert reads == [first]


@pytest.mark.parametrize("command", ["audit-export", "quickstart", "gui"])
def test_the_other_cli_commands_that_send_the_key_read_it_once(
    profile: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    from artzain import cli, gui

    monkeypatch.setattr(cli, "_iter_dotenv_paths", lambda start=None: iter(()))
    first, second = _two_logins(tmp_path, monkeypatch)
    reads: list[Path] = []

    def _alternating() -> Path:
        reads.append(second if len(reads) % 2 else first)
        return reads[-1]

    monkeypatch.setattr(credentials, "credentials_path", _alternating)
    used: list[tuple[str, Optional[str]]] = []
    if command == "audit-export":

        def _urlopen(req: Any, timeout: Optional[float] = None) -> _Answer:
            used.append((req.full_url, req.get_header("X-api-key")))
            return _Answer(b"PK")

        monkeypatch.setattr(cloud, "_urlopen", _urlopen)
        cli.cmd_audit_export(argparse.Namespace(profile=None, from_=None, to=None,
                                                out=str(tmp_path / "bundle.zip")))
    elif command == "quickstart":
        monkeypatch.setattr(cli, "run_quickstart_demo",
                            lambda api_key, *, base_url: used.append((base_url, api_key)))
        cli.cmd_quickstart(argparse.Namespace())
    else:
        monkeypatch.setattr(gui, "launch_gui",
                            lambda base_url, *, api_key, port, no_browser: used.append((base_url, api_key)))
        cli.cmd_gui(argparse.Namespace(port=None, no_browser=True))

    [(url, key)] = used
    assert (url.startswith(HOST) and key == KEY) or (url.startswith(OTHER_HOST) and key == OTHER_KEY)
    assert reads == [first]


# ---------------------------------------------------------------------------
# The policy-rules loader
# ---------------------------------------------------------------------------

#: The tenant's own rule, as the platform lists it.
TENANT = ClientPolicyRule(
    rule_id="ACME-discounts",
    title="No discount promises",
    summary="Account managers must not promise discounts to customers.",
    category="communications_legal",
    agent="compliance_monitor",
    violation_patterns=(r"\bguaranteed discount\b",),
    severity="high",
)
CONDUCT_IDS = [r.rule_id for r in builtin_conduct_rules()]
TENANT_IDS = [TENANT.rule_id, *CONDUCT_IDS]
#: Longer than the longest wait between two attempts at a failing fetch.
PAST_ANY_BACKOFF = 61.0


class _Answer:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _Platform:
    """``GET /api/policy-enforcement/rules``: the tenant's rules, and a record
    of where each request went with which key."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, Optional[str]]] = []

    def urlopen(self, req: Any, timeout: Optional[float] = None) -> _Answer:
        self.sent.append((req.full_url, req.get_header("X-api-key")))
        return _Answer(json.dumps({"rules": [TENANT.to_dict()]}).encode("utf-8"))


class _Clock:
    """Stands in for ``_helpers.time``: ``monotonic`` reads a time the test
    moves, and everything else is the real module."""

    def __init__(self) -> None:
        self.now = 50_000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


@pytest.fixture
def platform(monkeypatch: pytest.MonkeyPatch, profile: Path) -> _Platform:
    stub = _Platform()
    monkeypatch.setattr(cloud, "_urlopen", stub.urlopen)
    # The User-Agent's version lookup reads package metadata on every request.
    monkeypatch.setattr(cloud, "_package_version", lambda: "test")
    return stub


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(_helpers, "time", fake)
    return fake


def _ids(rules: list[ClientPolicyRule]) -> list[str]:
    return [r.rule_id for r in rules]


def _loader_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "artzain.security" and r.levelno >= logging.WARNING
    ]


@HOW
def test_a_refresh_while_the_profile_cannot_be_read_keeps_the_tenants_rules(
    profile: Path, platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture, how: str
) -> None:
    _login()
    assert _ids(load_client_policy_rules()) == TENANT_IDS

    with _cannot_read(profile, how), caplog.at_level(logging.INFO):
        assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS, (
            "a profile that could not be read was taken for one without a key"
        )
        clock.advance(PAST_ANY_BACKOFF)
        assert _ids(load_client_policy_rules()) == TENANT_IDS

    assert platform.sent == [(URL, KEY)]
    warnings = _loader_warnings(caplog)
    assert warnings and "credentials profile could not be read" in warnings[0]
    _no_value_in(" ".join(r.getMessage() for r in caplog.records), profile)


@HOW
def test_the_tenants_rules_are_fetched_again_once_the_profile_can_be_read(
    profile: Path, platform: _Platform, clock: _Clock, how: str
) -> None:
    """A failed fetch like any other: the next is made once its backoff has
    passed, not at once."""
    _login()
    load_client_policy_rules()
    with _cannot_read(profile, how):
        load_client_policy_rules(force_refresh=True)

    clock.advance(0.5)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert len(platform.sent) == 1

    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert platform.sent == [(URL, KEY), (URL, KEY)]


@HOW
def test_past_the_window_the_conduct_rules_apply_alone(
    profile: Path, platform: _Platform, clock: _Clock, how: str
) -> None:
    _login()
    load_client_policy_rules()

    with _cannot_read(profile, how):
        assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS
        clock.advance(301)
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    assert len(platform.sent) == 1


@HOW
def test_a_first_load_while_the_profile_cannot_be_read_is_a_failed_fetch(
    profile: Path, platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture, how: str
) -> None:
    _login()

    with _cannot_read(profile, how), caplog.at_level(logging.INFO):
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    assert platform.sent == []
    assert any("credentials profile could not be read" in w for w in _loader_warnings(caplog))
    clock.advance(0.5)
    load_client_policy_rules()
    assert platform.sent == []
    clock.advance(PAST_ANY_BACKOFF)
    assert _ids(load_client_policy_rules()) == TENANT_IDS


@HOW
def test_a_key_configured_since_gets_no_rules_fetched_before_it(
    profile: Path, platform: _Platform, clock: _Clock, how: str
) -> None:
    """``configure()`` switched keys, and the profile that says which host may
    have the new one cannot be read: the rules fetched with the old key are not
    served for it, and the new key is not sent."""
    _login()
    load_client_policy_rules()
    cloud.configure(api_key=OTHER_KEY, base_url=OTHER_HOST)

    with _cannot_read(profile, how):
        assert _ids(load_client_policy_rules()) == CONDUCT_IDS

    assert platform.sent == [(URL, KEY)]


@pytest.mark.parametrize("switch", ["key", "host"])
@HOW
def test_a_switch_made_in_the_environment_is_seen_while_the_profile_cannot_be_read(
    profile: Path,
    platform: _Platform,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    switch: str,
    how: str,
) -> None:
    """The key and host the environment sets can still be read, and they are
    not those the rules were fetched with: those rules are not served, as when
    a fetch for another key fails."""
    _login(OTHER_KEY, OTHER_HOST)
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", HOST)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    if switch == "key":
        monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_profile_read_third_55555555")
    else:
        monkeypatch.setenv("COGNEXUS_API_BASE_URL", "https://third.example.test")

    with _cannot_read(profile, how):
        assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS

    assert platform.sent == [(URL, KEY)]


@HOW
def test_configure_with_the_key_the_rules_were_fetched_with_keeps_them(
    profile: Path, platform: _Platform, clock: _Clock, caplog: pytest.LogCaptureFixture, how: str
) -> None:
    """``configure()`` set again the key in use, and the profile cannot be read:
    the key set now is the one those rules were fetched with."""
    _login()
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    cloud.configure(api_key=KEY)

    with _cannot_read(profile, how), caplog.at_level(logging.WARNING):
        assert _ids(load_client_policy_rules()) == TENANT_IDS

    assert platform.sent == [(URL, KEY)]
    assert not any("another API key or host" in w for w in _loader_warnings(caplog))


@pytest.mark.parametrize("unset", ["environment-key", "environment-host", "configure-host"])
@HOW
def test_a_key_or_host_unset_since_the_fetch_is_not_taken_for_the_same(
    profile: Path,
    platform: _Platform,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    unset: str,
    how: str,
) -> None:
    """The rules were fetched with a key and host set in the environment or
    with ``configure()``; one of them is unset since, so the one in use now
    comes from the profile, which cannot be read: it cannot be told whether
    they are still the same."""
    _login(OTHER_KEY, OTHER_HOST)
    if unset == "configure-host":
        cloud.configure(api_key=KEY, base_url=HOST)
    else:
        monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
        monkeypatch.setenv("COGNEXUS_API_BASE_URL", HOST)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    if unset == "environment-key":
        monkeypatch.delenv("COGNEXUS_API_KEY")
    elif unset == "environment-host":
        monkeypatch.delenv("COGNEXUS_API_BASE_URL")
    else:
        cloud.configure(base_url=None)

    with _cannot_read(profile, how), caplog.at_level(logging.WARNING):
        assert _ids(load_client_policy_rules(force_refresh=True)) == CONDUCT_IDS

    assert platform.sent == [(URL, KEY)]
    assert any("cannot be told" in w for w in _loader_warnings(caplog))


@HOW
def test_the_same_host_written_otherwise_is_the_same_host(
    profile: Path, platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    _login(OTHER_KEY, OTHER_HOST)
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", HOST)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", HOST.upper() + "/")

    with _cannot_read(profile, how):
        assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS

    assert platform.sent == [(URL, KEY)]


@HOW
def test_rules_kept_across_a_configure_that_changed_nothing_know_where_their_key_is_from(
    profile: Path, platform: _Platform, clock: _Clock, how: str
) -> None:
    """``configure()`` set the profile's own key, then cleared it: the same key
    and host throughout, now from the profile, so the rules fetched with them
    are still served while it cannot be read."""
    _login()
    cloud.configure(api_key=KEY)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    cloud.configure(api_key=None)
    assert _ids(load_client_policy_rules()) == TENANT_IDS

    with _cannot_read(profile, how):
        assert _ids(load_client_policy_rules(force_refresh=True)) == TENANT_IDS

    assert platform.sent == [(URL, KEY)]


class _WatchedLock:
    """``_helpers._policy_rules_lock``, saying when a caller starts to wait for it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.waiting = threading.Event()

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if blocking and self._lock.locked():
            self.waiting.set()
        return self._lock.acquire(blocking, timeout)

    def release(self) -> None:
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()


def test_a_refresh_that_waited_for_another_keeps_to_its_backoff(
    profile: Path, platform: _Platform, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two refreshes at once while the profile cannot be read: the one that
    waited for the other's attempt serves what that attempt left rather than
    counting a failure of its own, so the next fetch is not put off further."""
    _login()
    load_client_policy_rules()
    lock = _WatchedLock()
    monkeypatch.setattr(_helpers, "_policy_rules_lock", lock)
    unreadable = profile.with_name("unreadable.toml")
    unreadable.write_bytes(profile.read_bytes() + b"# \xff\n")
    reading, release = threading.Event(), threading.Event()

    def _first_read_held() -> Path:
        if not reading.is_set():
            reading.set()
            release.wait(10)
        return unreadable

    monkeypatch.setattr(credentials, "credentials_path", _first_read_held)
    served: dict[str, list[str]] = {}

    def _refresh(name: str) -> None:
        served[name] = _ids(load_client_policy_rules(force_refresh=True))

    first = threading.Thread(target=_refresh, args=("first",))
    first.start()
    assert reading.wait(10)
    second = threading.Thread(target=_refresh, args=("second",))
    second.start()
    assert lock.waiting.wait(10)
    release.set()
    first.join(10)
    second.join(10)

    assert served == {"first": TENANT_IDS, "second": TENANT_IDS}
    monkeypatch.setattr(credentials, "credentials_path", lambda: profile)
    # Past the backoff of one failure, not of two.
    clock.advance(1.5)
    assert _ids(load_client_policy_rules()) == TENANT_IDS
    assert len(platform.sent) == 2
