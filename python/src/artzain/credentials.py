"""Credential profile at ``~/.artzain/credentials.toml`` (Wave 1 · R1).

Resolution order for the API key (highest wins):
  1. ``artzain.configure(api_key=…)``
  2. ``COGNEXUS_API_KEY`` / ``MYAPP_API_KEY`` env
  3. profile file
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "credentials_path",
    "read_profile",
    "write_profile",
    "profile_api_key",
    "profile_base_url",
]


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
