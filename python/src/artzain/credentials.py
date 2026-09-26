"""Credential profile at ``~/.artzain/credentials.toml`` (Wave 1 · R1).

Resolution order for the API key (highest wins):
  1. ``artzain.configure(api_key=…)``
  2. ``COGNEXUS_API_KEY`` / ``MYAPP_API_KEY`` env
  3. a project ``.env`` (CLI only)
  4. profile file

The host a key is sent to is decided with the key, by
:func:`resolve_credentials`: a key goes only to the host it was issued with.
"""

from __future__ import annotations

import os
import stat
import sys
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


def credentials_path() -> Path:
    override = (os.environ.get("COGNEXUS_CREDENTIALS_PATH") or "").strip()
    if override:
        return Path(override)
    return Path.home() / ".artzain" / "credentials.toml"


def read_profile() -> dict[str, Any]:
    path = credentials_path()
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
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


def write_profile(*, api_key: str, base_url: str = "", email: str = "") -> Path:
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# CogNEXUS CLI credentials — do not commit", "[default]"]
    lines.append(f'api_key = "{api_key}"')
    if base_url:
        lines.append(f'base_url = "{base_url.rstrip("/")}"')
    if email:
        lines.append(f'email = "{email}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        if sys.platform != "win32":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            os.chmod(path.parent, stat.S_IRWXU)  # 0o700
    except OSError:
        pass
    return path


def profile_api_key() -> Optional[str]:
    val = (read_profile().get("api_key") or "").strip()
    return val or None


def profile_base_url() -> Optional[str]:
    val = (read_profile().get("base_url") or "").strip().rstrip("/")
    return val or None


class CredentialConflictError(RuntimeError):
    """The host that is set is not the host the API key was issued with.

    Nothing was sent. The message names the settings involved, never their
    values.
    """


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
    goes to the named host or the default as before.
    """
    named: Optional[str] = None
    named_source = ""
    if _clean_base(base_url):
        named, named_source = _clean_base(base_url), "configure(base_url=...)"
    elif _clean_base(os.environ.get("COGNEXUS_API_BASE_URL")):
        named = _clean_base(os.environ.get("COGNEXUS_API_BASE_URL"))
        named_source = "COGNEXUS_API_BASE_URL"

    profile_key = profile_api_key()
    profile_base = profile_base_url()

    key: Optional[str] = None
    key_source = "none"
    paired: Optional[str] = None
    paired_source = ""
    explicit = (api_key or "").strip() or None
    env_cnx = (os.environ.get("COGNEXUS_API_KEY") or "").strip() or None
    env_myapp = (os.environ.get("MYAPP_API_KEY") or "").strip() or None
    if explicit:
        key, key_source = explicit, "configure(api_key=...)"
    elif env_cnx:
        key, key_source = env_cnx, "COGNEXUS_API_KEY"
    elif env_myapp:
        key, key_source = env_myapp, "MYAPP_API_KEY"
    elif dotenv and (dotenv[0] or "").strip():
        key, key_source = dotenv[0].strip(), dotenv[2]
        if _clean_base(dotenv[1]):
            paired, paired_source = _clean_base(dotenv[1]), dotenv[2]
    elif profile_key:
        key, key_source = profile_key, PROFILE_SOURCE

    if key is None:
        # No key is sent, so the profile's host can stand in for display.
        if named:
            return ResolvedCredentials(None, named, key_source, named_source)
        if profile_base:
            return ResolvedCredentials(None, profile_base, key_source, PROFILE_SOURCE)
        return ResolvedCredentials(None, DEFAULT_BASE_URL, key_source, "default")

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
        return ResolvedCredentials(key, paired, key_source, paired_source)
    if named:
        return ResolvedCredentials(key, named, key_source, named_source)
    return ResolvedCredentials(key, DEFAULT_BASE_URL, key_source, "default")
