"""Credential profile at ``~/.artzain/credentials.toml`` (Wave 1 · R1).

Resolution order for the API key (highest wins):
  1. ``artzain.configure(api_key=…)``
  2. ``COGNEXUS_API_KEY`` / ``MYAPP_API_KEY`` env
  3. a project ``.env`` (CLI only)
  4. profile file

The host a key is sent to is decided with the key, by
:func:`resolve_credentials`: it pairs a key only with the host it was issued
with, and only with a plain ``http://`` or ``https://`` URL of that host.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import sys
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "DEFAULT_BASE_URL",
    "CredentialConflictError",
    "ResolvedCredentials",
    "credentials_path",
    "read_profile",
    "write_profile",
    "profile_api_key",
    "profile_base_url",
    "resolve_credentials",
]

DEFAULT_BASE_URL = "https://app.cognexuslabs.ai"

#: Source label for the profile. Messages name sources, never values: the
#: profile holds the API key, so nothing read from it goes into a message.
PROFILE_SOURCE = "credentials profile"
#: Source label for a host that nothing set: :data:`DEFAULT_BASE_URL`.
_DEFAULT_BASE_SOURCE = "default"

#: Waits before each new attempt at reading a profile that Windows reports as
#: in use. A read that meets :func:`write_profile` moving a new profile into
#: place fails for a moment; a lock another process keeps on the file is still
#: there after these, and the profile then counts as unreadable. Elsewhere a
#: refused read is refused for good.
_READ_RETRY_DELAYS: tuple[float, ...] = (
    (0.001, 0.002, 0.005, 0.01) if sys.platform == "win32" else ()
)

#: The profile file (path, device, inode, mtime, size) whose last read failed.
#: While it is unchanged, a read is tried once, without the waits above: a lock
#: another process keeps would otherwise add them to every call.
_failed_read: Optional[tuple[str, int, int, int, int]] = None

#: How long, and how often, a move of a new profile over the old one is tried
#: again. Windows refuses the move while another process has the old one open,
#: as every process reading it does for a moment: tried often, so that the
#: moment between two readers is not missed.
_REPLACE_RETRY_SECONDS = 5.0 if sys.platform == "win32" else 0.0
_REPLACE_RETRY_INTERVAL = 0.002

#: What Windows says of a path where no file can be: a name no file can have
#: (ERROR_INVALID_NAME), a symlink loop (ERROR_CANT_RESOLVE_FILENAME).
_NO_FILE_WINERRORS = frozenset({123, 1921})
#: What Windows says of a network path or share it cannot reach
#: (ERROR_BAD_NETPATH, ERROR_BAD_NET_NAME), which Python reports as a file not
#: found although a file may be there.
_UNREACHABLE_WINERRORS = frozenset({53, 67})
#: A byte range covering any profile, locked while one is rewritten in place.
_LOCK_SPAN = 1 << 20

#: A new profile is written to ``.<name>.<12 hex digits>.tmp`` beside it. One
#: that an interrupted write left there is removed by a later write, once it
#: is far older than a write still under way could have made it, however slow.
_NEW_FILE_SUFFIX = ".tmp"
_LEFT_BEHIND_SECONDS = 3600.0

#: Why a profile that is there cannot be read. Fixed phrases: nothing from the
#: file or from the error, which names the path, goes into a message.
_REFUSED = "permission denied, or another program holds a lock on it"
_READ_FAILED = "the system could not read it"
_NOT_UTF8 = "it is not UTF-8 text"


class CredentialConflictError(RuntimeError):
    """The host that is set is not the host the API key was issued with.

    Nothing was sent. The message names the settings involved, never their
    values. Also raised when the credentials profile is there but cannot be
    read: it records the host its key was issued with, so no key can be paired
    with a host while it is unread (see :func:`resolve_credentials`); and when
    the base URL the key would go to is not a plain ``http://`` or
    ``https://`` URL of a host.
    """


class _ProfileUnreadable(CredentialConflictError):
    """The credentials profile is there but cannot be read.

    Not a profile without a key: it holds the key ``artzain login`` saved and
    the host that key was issued with. :func:`read_profile` still answers
    ``{}`` for it; :func:`resolve_credentials` raises this instead. A
    :class:`CredentialConflictError`, so a caller that sends nothing on a
    conflict sends nothing here either. Raised with nothing chained to it.
    """


class _BaseUrlUnusable(CredentialConflictError):
    """The base URL an API key would go to is not a plain ``http://`` or
    ``https://`` URL of a host (see :func:`_usable_base`).

    A :class:`CredentialConflictError`, so a caller that sends nothing on a
    conflict sends nothing here either. Its message names the setting that
    holds the URL, never the URL.
    """


def _base_url_unusable(source: str) -> _BaseUrlUnusable:
    return _BaseUrlUnusable(
        f"Not sent: the base URL from {source} is not an http:// or https:// URL "
        "that names a host, with no space, control character, user or password "
        "in it, so the API key is not sent to it. Correct the URL there, for "
        f"example {DEFAULT_BASE_URL}."
    )


def _unreadable(why: str) -> _ProfileUnreadable:
    return _ProfileUnreadable(
        f"Not sent: the {PROFILE_SOURCE} could not be read ({why}). It holds the "
        "API key `artzain login` saved and the host that key was issued with, so "
        "no key is sent until it can be read. If another program has it open, "
        "try again; otherwise fix its permissions, remove it, or set "
        "COGNEXUS_CREDENTIALS_PATH to another file."
    )


def credentials_path() -> Path:
    override = (os.environ.get("COGNEXUS_CREDENTIALS_PATH") or "").strip()
    if override:
        return Path(override)
    return Path.home() / ".artzain" / "credentials.toml"


def _no_file_at(path: Path, exc: OSError) -> bool:
    """Whether *exc*, raised looking at *path*, means this user has no profile
    file there.

    Nothing at the path, a path through a file, a symlink loop or a name no
    file can have, as before; and a directory on the way that this user may
    not search and that is another user's (:func:`_behind_another_users`).
    Anything else, an I/O or a network error say, tells nothing about what is
    there, and the profile counts as unreadable.
    """
    winerror = getattr(exc, "winerror", None)
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return winerror not in _UNREACHABLE_WINERRORS
    if exc.errno in (getattr(errno, "ELOOP", None), errno.ENAMETOOLONG):
        return True
    if winerror in _NO_FILE_WINERRORS:
        return True
    if isinstance(exc, PermissionError) and sys.platform != "win32":
        return _behind_another_users(path)
    return False


def _behind_another_users(path: Path) -> bool:
    """Whether the first directory on the way to *path* that this user may not
    search is not this user's: what is past it is not this user's profile.

    Another user's (a container whose HOME is root's), one a user namespace
    shows as the overflow uid because it does not map its owner, or a
    directory of root's that nobody may read, write or search mounted over
    its place (a sandbox hiding home directories, as systemd's ProtectHome
    does) is not.
    One of this user's own, closed by mistake, may hold theirs, a home on a
    mount of its own included.
    """
    directory = Path(os.path.abspath(path)).parent
    above: Optional[Path] = None
    for step in (*reversed(directory.parents), directory):
        if not _searchable(step):
            try:
                info = os.stat(step)
                mounted = above is not None and info.st_dev != os.stat(above).st_dev
            except OSError:
                return False
            hidden = mounted and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0
            return hidden or info.st_uid != os.geteuid() or info.st_uid == _overflow_uid()
        above = step
    return False


def _overflow_uid() -> Optional[int]:
    """The uid Linux shows for the users a user namespace does not map, when
    this process is in one that maps no user (its uid_map is empty), where its
    own uid shows as that one too. ``None`` otherwise: a user whose uid it
    really is (nobody) owns what shows it."""
    try:
        with open("/proc/self/uid_map", encoding="ascii") as mapping:
            if mapping.read().strip():
                return None
        with open("/proc/sys/kernel/overflowuid", encoding="ascii") as shown:
            return int(shown.read().strip())
    except (OSError, ValueError):
        return None


def _searchable(directory: Path) -> bool:
    if os.access in os.supports_effective_ids:
        return os.access(directory, os.X_OK, effective_ids=True)
    return os.access(directory, os.X_OK)


def _read_file(path: Path, delays: tuple[float, ...]) -> tuple[Optional[bytes], str]:
    """The bytes of the regular file at *path*: ``(data, "")``, ``(None, "")``
    when it is gone by now, ``(None, why)`` when it cannot be read."""
    retries = iter(delays)
    while True:
        try:
            return path.read_bytes(), ""
        except (FileNotFoundError, IsADirectoryError):
            return None, ""
        except PermissionError:
            delay = next(retries, None)
            if delay is None:
                return None, _REFUSED
            time.sleep(delay)
        except OSError:
            return None, _READ_FAILED


def _load_profile() -> dict[str, str]:
    """The profile's ``[default]`` table, from one read of the file.

    ``{}`` when this user has no profile file (see :func:`_no_file_at`), and
    when what is at the path is not a file: a directory, a device, a pipe, a
    socket, none of which is opened (a read of a pipe waits for a writer).
    Raises :class:`_ProfileUnreadable` when a file is there but cannot be read,
    or is not UTF-8 text; the error that says why is not chained to it, since
    it names the path or holds the file's bytes.
    """
    global _failed_read
    path = credentials_path()
    try:
        info = os.stat(path)
    except OSError as exc:
        if _no_file_at(path, exc):
            return {}
        raw, why = None, _REFUSED if isinstance(exc, PermissionError) else _READ_FAILED
    else:
        if not stat.S_ISREG(info.st_mode):
            return {}
        this_file = (os.fspath(path), info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
        raw, why = _read_file(path, () if this_file == _failed_read else _READ_RETRY_DELAYS)
        if raw is None and not why:
            return {}
        _failed_read = this_file if raw is None else None
    if raw is None:
        raise _unreadable(why)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        del raw
        raise _unreadable(_NOT_UTF8)
    return _parse_profile(text)


def _parse_profile(text: str) -> dict[str, str]:
    # Minimal TOML subset (no dependency): key = "value" under [default]
    section = "default"
    data: dict[str, dict[str, str]] = {"default": {}}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip() or "default"
            data.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        data.setdefault(section, {})[key] = val
    return data.get("default") or {}


def read_profile() -> dict[str, Any]:
    """The profile's ``[default]`` table.

    ``{}`` when there is no profile, and also, as before, when there is one
    that cannot be read: callers of this function read ``{}`` as no profile.
    :func:`resolve_credentials` tells the two apart.
    """
    try:
        return _load_profile()
    except _ProfileUnreadable:
        return {}


def write_profile(*, api_key: str, base_url: str = "", email: str = "") -> Path:
    """Save the profile ``artzain login`` writes, and return its path.

    The profile is replaced whole: a new file, which on POSIX only its owner
    can read from its creation, is written beside it and moved over it, so a
    process reading the profile meanwhile finds the old one or the new one,
    never an empty or half written file. The new file is the writer's. A
    profile that is another user's is not replaced: the write is refused, but
    for root under ``sudo`` or ``doas`` writing for that user (HOME kept), who
    is given the new one, as they are a new one in a directory of theirs:
    they could not read root's. No one else is handed a new key. A symlink at
    the path is written through, unless another user than the writer, the
    invoking user or root made it; a device there (the null device, to keep
    no key) is written to, as before, and a pipe nothing reads is refused
    rather than waited on.

    Windows refuses the move while another process has the profile open; it is
    tried again for a few seconds, and if it still fails the error is raised
    with the profile left as it was, rather than rewritten in place, which
    Windows truncates and then refuses to write while another process holds a
    lock on it. A directory that takes no new file has the profile rewritten in
    place, as before. A new file an interrupted write left beside the profile,
    with its key, is removed once it is old. The SDK's own directory, or one
    this write makes, is closed to other users; one that is there already is
    left as it is.
    """
    path = credentials_path()
    invoker = _invoking_user()
    made_directory = not os.path.lexists(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    if made_directory and invoker is not None:
        # sudo made ~/.artzain in the invoking user's home: it is theirs.
        with contextlib.suppress(OSError):
            if os.stat(path.parent.parent).st_uid == invoker[0]:
                os.chown(path.parent, *invoker)
    lines = ["# CogNEXUS CLI credentials — do not commit", "[default]"]
    lines.append(f'api_key = "{api_key}"')
    if base_url:
        lines.append(f'base_url = "{base_url.rstrip("/")}"')
    if email:
        lines.append(f'email = "{email}"')
    # The line ends text mode wrote before.
    data = ("\n".join(lines) + "\n").replace("\n", os.linesep).encode("utf-8")
    _refuse_a_link_of_another_users(path, invoker)
    try:
        existing: Optional[os.stat_result] = os.stat(path)
    except OSError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        # Opened by its own name, which a pipe named by a descriptor needs.
        _write_through(path, data)
    else:
        _refuse_another_users_profile(existing, invoker)
        # Through a symlink to what it names, rather than over the link.
        target = Path(os.path.realpath(path))
        _write_file(target, data, _owner_to_give(target, existing, invoker))
        _remove_left_behind(target)
    if sys.platform != "win32" and (made_directory or _is_sdk_directory(path.parent)):
        with contextlib.suppress(OSError):
            os.chmod(path.parent, stat.S_IRWXU)  # 0o700
    return path


def _is_sdk_directory(directory: Path) -> bool:
    """*directory* is ``~/.artzain``, the SDK's own."""
    try:
        return directory == Path.home() / ".artzain"
    except RuntimeError:
        # No home directory to tell by.
        return False


def _invoking_user() -> Optional[tuple[int, int]]:
    """The user and group ``sudo`` or ``doas`` runs this process for, when it
    is root: ``SUDO_UID`` and ``SUDO_GID``, or the user ``DOAS_USER`` names.
    ``None`` otherwise, ``su`` among them, which says nothing of who ran it."""
    if sys.platform == "win32" or os.geteuid() != 0:
        return None
    if os.environ.get("SUDO_UID"):
        try:
            return int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID") or -1)
        except ValueError:
            return None
    if os.environ.get("DOAS_USER"):
        import pwd

        try:
            entry = pwd.getpwnam(os.environ["DOAS_USER"])
        except KeyError:
            return None
        return entry.pw_uid, entry.pw_gid
    return None


def _owner_to_give(
    target: Path, existing: Optional[os.stat_result], invoker: Optional[tuple[int, int]]
) -> Optional[tuple[int, int]]:
    """Whom to give the new profile at *target*: the invoking user under
    ``sudo`` (*invoker*), when the profile it replaces (*existing*), or with
    none yet the directory it goes in, is theirs. ``None``: the writer keeps
    it, whoever owned what it replaces, who is not handed the new key."""
    if invoker is None or invoker == (os.geteuid(), os.getegid()):
        return None
    try:
        owner = existing.st_uid if existing is not None else os.stat(target.parent).st_uid
    except OSError:
        return None
    return invoker if owner == invoker[0] else None


def _refuse_another_users_profile(
    existing: Optional[os.stat_result], invoker: Optional[tuple[int, int]]
) -> None:
    """Refuse to replace a profile that is another user's: it is not taken
    over, and its owner is not left without it. Root under ``sudo`` or
    ``doas`` writing for its owner (*invoker*) replaces it and gives it back
    (:func:`_owner_to_give`). Writing it in place, as before, was refused too
    when the file could not be opened."""
    if sys.platform == "win32" or existing is None or existing.st_uid == os.geteuid():
        return
    if invoker is not None and existing.st_uid == invoker[0]:
        return
    raise PermissionError(errno.EACCES, "the credentials profile is another user's")


def _refuse_a_link_of_another_users(path: Path, invoker: Optional[tuple[int, int]]) -> None:
    """Refuse a symlink at *path* that neither this process's user, the user
    ``sudo`` or ``doas`` runs it for, nor root made: writing through it would put the key
    where another user chose. The kernel refuses to follow such a link in a
    shared directory; resolving it here must not do what it would not."""
    if sys.platform == "win32":
        return
    try:
        info = os.lstat(path)
    except OSError:
        return
    trusted = {0, os.geteuid()} | ({invoker[0]} if invoker is not None else set())
    if stat.S_ISLNK(info.st_mode) and info.st_uid not in trusted:
        raise PermissionError(errno.EACCES, "the credentials profile's path is a link another user made")


def _write_file(target: Path, data: bytes, owner: Optional[tuple[int, int]]) -> None:
    """Write the profile file at *target*, the new file given to *owner* (see
    :func:`_owner_to_give`) before any of *data* is in it."""
    try:
        fd, new = _create_beside(target)
    except PermissionError:
        # The directory takes no new file: rewrite the profile in place.
        _write_in_place(target, data)
        return
    if owner is not None:
        with contextlib.suppress(OSError):
            os.fchown(fd, *owner)
    _move_into_place(fd, new, target, data)


def _create_beside(target: Path) -> tuple[int, str]:
    """A new file beside *target*, open for writing, and its name.

    Created exclusively, so nothing already at the name is opened, and on POSIX
    readable by its owner alone from the start. A PermissionError means the
    directory takes no new file: it is not tried again under another name, as
    tempfile does on Windows for as long as the directory is not read-only.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(8):
        new = os.path.join(target.parent, f".{target.name}.{secrets.token_hex(6)}{_NEW_FILE_SUFFIX}")
        try:
            return os.open(new, flags, stat.S_IRUSR | stat.S_IWUSR), new
        except FileExistsError:
            continue
    raise FileExistsError(errno.EEXIST, "no free name beside the credentials profile")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _fill(fd: int, data: bytes) -> None:
    """Write *data* to the open file *fd* and flush it to the disk.

    On POSIX the file is its owner's alone before any of *data* is in it. A
    file of another user's, rewritten in place, may refuse the change, as it
    refused the chmod before.
    """
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600, whatever the umask
    _write_all(fd, data)
    os.fsync(fd)


def _move_into_place(fd: int, new: str, target: Path, data: bytes) -> None:
    """Fill the new file *new* (open as *fd*) and move it over *target*.

    Whatever fails, *new* is removed and *target* is as it was.
    """
    try:
        try:
            _fill(fd, data)
        finally:
            os.close(fd)
        deadline = time.monotonic() + _REPLACE_RETRY_SECONDS
        while True:
            try:
                os.replace(new, target)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
            time.sleep(_REPLACE_RETRY_INTERVAL)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(new)
        raise


def _write_in_place(target: Path, data: bytes) -> None:
    """Rewrite the profile file *target* itself.

    On Windows it is locked first, so one another program holds a lock on is
    refused before anything in it changes: Windows lets a truncation through
    such a lock and refuses the write after it, which would leave it empty.
    """
    if sys.platform != "win32":
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
        try:
            _fill(fd, data)
        finally:
            os.close(fd)
        return
    import msvcrt

    fd = os.open(target, os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0), stat.S_IRUSR | stat.S_IWUSR)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, _LOCK_SPAN)
        try:
            os.ftruncate(fd, 0)
            _fill(fd, data)
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_SPAN)
    finally:
        os.close(fd)


def _write_through(path: Path, data: bytes) -> None:
    """Write *data* to what is at *path* and is not a file (a device, a pipe),
    as writing in place did before: its mode is left alone, and it is not
    flushed to a disk it may not have. Opened without waiting, so a pipe that
    nothing reads is refused at once (ENXIO) rather than waited on for good."""
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if sys.platform != "win32":
            os.set_blocking(fd, True)
        _write_all(fd, data)
    finally:
        os.close(fd)


def _remove_left_behind(target: Path) -> None:
    """Remove the new files interrupted writes left beside *target*.

    Only names :func:`_create_beside` makes, only files, not links, and only
    those older than any write still under way, by the file system's clock
    (the time on the profile just written): this machine's may run ahead of
    it. Never raises: the profile is written already.
    """
    prefix = f".{target.name}."
    with contextlib.suppress(OSError), os.scandir(target.parent) as entries:
        cutoff = os.stat(target).st_mtime - _LEFT_BEHIND_SECONDS
        for entry in entries:
            name = entry.name
            if not (name.startswith(prefix) and name.endswith(_NEW_FILE_SUFFIX)):
                continue
            middle = name[len(prefix):-len(_NEW_FILE_SUFFIX)]
            if len(middle) != 12 or any(c not in "0123456789abcdef" for c in middle):
                continue
            with contextlib.suppress(OSError):
                if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    os.unlink(entry.path)


def profile_api_key() -> Optional[str]:
    val = (read_profile().get("api_key") or "").strip()
    return val or None


def profile_base_url() -> Optional[str]:
    val = (read_profile().get("base_url") or "").strip().rstrip("/")
    return val or None


@dataclass(frozen=True)
class ResolvedCredentials:
    """An API key and the host it goes to, decided together.

    ``key_source`` and ``base_source`` are labels such as
    ``"COGNEXUS_API_KEY"`` or ``"credentials profile"``, safe to log.
    """

    api_key: Optional[str]
    base_url: str
    key_source: str
    base_source: str


def _clean_base(value: Optional[str]) -> Optional[str]:
    val = (value or "").strip().rstrip("/")
    return val or None


def _same_host(a: str, b: str) -> bool:
    return a.rstrip("/").lower() == b.rstrip("/").lower()


#: The schemes a base URL may have: HTTPS, and HTTP, which a deployment on
#: this machine uses (``artzain local`` serves one at ``http://localhost``).
#: HTTP is taken for any host, and carries the key unencrypted.
_BASE_URL_SCHEMES = ("https", "http")


def _space_or_control(text: str) -> bool:
    """Whether *text* holds white space or a control character (C0, DEL or
    C1)."""
    return any(c.isspace() or unicodedata.category(c) == "Cc" for c in text)


def _usable_base(url: str) -> bool:
    """Whether *url* is a plain ``http://`` or ``https://`` URL of a host: it
    names one, its port is a number if it has one, it carries no user or
    password, and it holds no white space or control character, in its host
    percent-encoded or not.

    No other can carry a key to the host it names: the event and
    policy-decision posts used plain HTTP for any scheme but ``https``, a
    mistyped one included, and dialled an empty host, this machine, for a URL
    with no scheme; and urllib refuses the rest with an error that quotes the
    URL, its host percent-decoded.
    """
    if _space_or_control(url):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port  # raises ValueError for a port that is not a number
    except ValueError:
        return False
    del port
    if parts.username is not None or parts.password is not None:
        return False
    if _space_or_control(urllib.parse.unquote(parts.netloc)):
        return False
    return parts.scheme in _BASE_URL_SCHEMES and bool(parts.hostname)


def _named_host(base_url: Optional[str] = None) -> tuple[Optional[str], str]:
    """The host set above the profile, and its label: *base_url* (a
    ``configure()`` value), then ``COGNEXUS_API_BASE_URL``."""
    if _clean_base(base_url):
        return _clean_base(base_url), "configure(base_url=...)"
    env = _clean_base(os.environ.get("COGNEXUS_API_BASE_URL"))
    if env:
        return env, "COGNEXUS_API_BASE_URL"
    return None, ""


def _key_set_above_profile(api_key: Optional[str] = None) -> tuple[Optional[str], str]:
    """The API key set above the profile (the library reads no ``.env``), and
    its label: *api_key* (a ``configure()`` value), then ``COGNEXUS_API_KEY``,
    then ``MYAPP_API_KEY``."""
    explicit = (api_key or "").strip() or None
    if explicit:
        return explicit, "configure(api_key=...)"
    for name in ("COGNEXUS_API_KEY", "MYAPP_API_KEY"):
        value = (os.environ.get(name) or "").strip() or None
        if value:
            return value, name
    return None, "none"


def resolve_credentials(
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    dotenv: Optional[tuple[str, Optional[str], str]] = None,
) -> ResolvedCredentials:
    """Pick the API key, then the host it may be sent to.

    *api_key* and *base_url* are ``configure()`` values. *dotenv* is
    ``(key, base_url_or_None, label)`` from a project ``.env`` (the CLI's
    layer; the library passes none).

    A key read from the profile goes to the profile's ``base_url``, and so
    does a runtime key equal to it. A ``.env`` key goes to the same file's
    ``COGNEXUS_API_BASE_URL`` when the file sets one. The profile's host is
    never used with any other key. Any other key goes to *base_url*, then
    ``COGNEXUS_API_BASE_URL``, then :data:`DEFAULT_BASE_URL`. With no key at
    all, nothing is sent and the profile's host may name the default.

    Raises :class:`CredentialConflictError` when *base_url* or
    ``COGNEXUS_API_BASE_URL`` names a host other than the one the key was
    issued with. A profile without ``base_url`` records no host, so its key
    goes to the named host or the default as before. It raises it too when
    the base URL a key would go to, or the one that is set, is not a plain
    ``http://`` or ``https://`` URL of a host (:func:`_usable_base`); the
    message names the setting that holds it. With no key, any base URL is
    returned as it is: no key goes with it.

    The profile is read once, so its key and its host come from one version
    of it. A profile that is there but cannot be read is not one without a
    key: this raises :class:`CredentialConflictError` for it, since the key
    may be in it, and a key set elsewhere may be the one it records with the
    host that issued it. Only a ``.env`` key whose file names its host needs
    no profile.
    """
    named, named_source = _named_host(base_url)
    key, key_source = _key_set_above_profile(api_key)
    paired: Optional[str] = None
    paired_source = ""
    if key is None and dotenv and (dotenv[0] or "").strip():
        key, key_source = dotenv[0].strip(), dotenv[2]
        if _clean_base(dotenv[1]):
            paired, paired_source = _clean_base(dotenv[1]), dotenv[2]

    # Read once, and only when it decides something: it holds the key when
    # none is set elsewhere, and the host its key was issued with, which a key
    # set elsewhere may be.
    profile = _load_profile() if paired is None else {}
    profile_key = (profile.get("api_key") or "").strip() or None
    profile_base = _clean_base(profile.get("base_url"))
    if key is None and profile_key:
        key, key_source = profile_key, PROFILE_SOURCE

    if key is None:
        # No key is sent, so the profile's host can stand in for display.
        if named:
            return ResolvedCredentials(None, named, key_source, named_source)
        if profile_base:
            return ResolvedCredentials(None, profile_base, key_source, PROFILE_SOURCE)
        return ResolvedCredentials(None, DEFAULT_BASE_URL, key_source, _DEFAULT_BASE_SOURCE)

    # A set host that no key can be sent to is named for what it is, before it
    # is compared with the host the key was issued with.
    if named and not _usable_base(named):
        raise _base_url_unusable(named_source)

    # The profile records which host issued its key; that key goes nowhere
    # else, however it was supplied.
    if paired is None and profile_key and profile_base and key == profile_key:
        paired, paired_source = profile_base, PROFILE_SOURCE

    if paired is not None:
        if named and not _same_host(named, paired):
            raise CredentialConflictError(
                f"Not sent: {named_source} names a different host from the one "
                f"the API key from {key_source} was issued with (recorded in "
                f"{paired_source}). Set COGNEXUS_API_KEY to a key for that host, "
                f"run `artzain login` against it, or unset {named_source}."
            )
        base, base_source = paired, paired_source
    elif named:
        base, base_source = named, named_source
    else:
        base, base_source = DEFAULT_BASE_URL, _DEFAULT_BASE_SOURCE
    if not _usable_base(base):
        raise _base_url_unusable(base_source)
    return ResolvedCredentials(key, base, key_source, base_source)
