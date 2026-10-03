"""Files and folders that only their owner can read, from the moment they exist.

A file is created new with mode ``0600`` and a folder with ``0700``, whatever
the process umask, and a folder is used only if it is this user's. Writing
first and changing the mode after left a window in which another local user
could read a secret; a file created with the umask's mode (commonly ``0644``)
and never changed stayed readable. An existing file is never reopened for a
secret: whoever opened it while it was readable could read the secret
through that descriptor, whatever its mode became.

On Windows the modes do not apply: a file there takes its access list from
its folder, and the SDK's default folders sit under the user's own profile.

A file rewritten whole is written beside itself and moved over the old one
(:func:`replace_file`), so a reader never sees half of it.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR          # 0o600
_DIR_MODE = stat.S_IRWXU                          # 0o700

#: How long, and how often, a move of a new file over an old one is tried
#: again. Windows refuses the move while another program has the old one
#: open, as a virus scanner reading a file just written does, and as every
#: reader does for a moment: tried often, so that the moment between two
#: readers is not missed. Elsewhere a rename is never held up by a reader,
#: and a refusal is not tried again.
_REPLACE_RETRY_SECONDS = 5.0 if sys.platform == "win32" else 0.0
_REPLACE_RETRY_INTERVAL = 0.002


def _refuse_another_users(path: Path, info: os.stat_result) -> None:
    """A folder another user owns is theirs to read and change: refused,
    except to root."""
    euid = os.geteuid()  # type: ignore[attr-defined]  # POSIX only
    if info.st_uid != euid and euid != 0:
        raise PermissionError(errno.EACCES, f"{path} is another user's folder")


def private_dir(path: Path) -> Path:
    """Create *path* (and any missing parents) and make it ``0700``.

    On POSIX a folder that is there already and is another user's (made
    first where both can write) is refused with ``PermissionError``.
    """
    path.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    if sys.platform != "win32":
        _refuse_another_users(path, os.stat(path))
        with contextlib.suppress(OSError):
            os.chmod(path, _DIR_MODE)
    return path


def private_temp_dir(name: str) -> Path:
    """A ``0700`` folder of this user's own in the system temp folder, for a
    host with no writable home (POSIX only).

    The folder is ``<tmp>/<name>-<uid>``. The temp folder is shared, so the
    name may already be taken by another user, or be a link to a folder of
    theirs: anything but a real folder owned by this user is refused
    (``PermissionError``), as is a temp folder anyone may write without the
    sticky bit, where another user could move the folder away.
    """
    uid = os.geteuid()  # type: ignore[attr-defined]  # POSIX only
    base = Path(tempfile.gettempdir())
    shared = os.stat(base)
    if shared.st_mode & stat.S_IWOTH and not shared.st_mode & stat.S_ISVTX:
        raise PermissionError(errno.EACCES, f"{base} lets any user move what is in it")
    path = base / f"{name}-{uid}"
    with contextlib.suppress(FileExistsError):
        os.mkdir(path, _DIR_MODE)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
        raise PermissionError(errno.EACCES, f"{path} is not a folder of this user's own")
    if stat.S_IMODE(info.st_mode) != _DIR_MODE:
        os.chmod(path, _DIR_MODE)
    return path


def open_private(path: Path, *, exclusive: bool = False) -> int:
    """Create *path* as a new ``0600`` file, open for writing, and return the
    descriptor.

    Whatever is at the name is removed first, a link included (not what it
    names); with *exclusive* it is refused instead (``FileExistsError``) and
    left as it is.
    """
    if not exclusive:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags, _FILE_MODE)
    if sys.platform != "win32":
        try:
            os.fchmod(fd, _FILE_MODE)  # a umask cannot add bits; this undoes one that took some
        except OSError:
            os.close(fd)
            raise
    return fd


def write_private(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """Write *data* to *path* as a new ``0600`` file (see :func:`open_private`).

    A file the write could not finish is removed, not left half written.
    """
    fd = open_private(path, exclusive=exclusive)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def replace_file(new: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
    """Move the file *new* over *target*, by a rename.

    A move Windows refuses (``PermissionError``) is tried again every
    :data:`_REPLACE_RETRY_INTERVAL` until :data:`_REPLACE_RETRY_SECONDS` have
    gone. Whatever fails, *new* is removed and *target* is as it was.
    """
    try:
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
