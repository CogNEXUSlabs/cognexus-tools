"""Unit tests for CLI quickstart helpers (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from artzain import __version__
from artzain.cli import (
    _quickstart_demo_file_contents,
    _request_headers_for_url,
    extract_artzain_api_key_from_text,
    find_artzain_api_key_in_env_files,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("COGNEXUS_API_KEY=abc123\n", "abc123"),
        ('COGNEXUS_API_KEY="quoted"', "quoted"),
        ("export COGNEXUS_API_KEY=ex\n", "ex"),
        ("# comment\nFOO=1\nCOGNEXUS_API_KEY=k\n", "k"),
        ("MYAPP_API_KEY=fall\n", "fall"),
        ("MYAPP_API_KEY=a\nCOGNEXUS_API_KEY=b\n", "b"),
        ("COGNEXUS_API_KEY=b\nMYAPP_API_KEY=a\n", "b"),
        ("COGNEXUS_API_KEY=first\nCOGNEXUS_API_KEY=second\n", "first"),
        ("NOT_IT=x\n", None),
    ],
)
def test_extract_artzain_api_key_from_text(text: str, expected: str | None) -> None:
    assert extract_artzain_api_key_from_text(text) == expected


def test_find_artzain_api_key_in_env_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("COGNEXUS_API_KEY=file-key\n", encoding="utf-8")
    key, path = find_artzain_api_key_in_env_files()
    assert key == "file-key"
    assert path == (tmp_path / ".env").resolve()


def test_request_headers_match_dashboard_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COGNEXUS_CLI_USER_AGENT", raising=False)
    url = "https://app.cognexuslabs.ai/api/auth/signup"
    h = _request_headers_for_url(url)
    assert h["Origin"] == "https://app.cognexuslabs.ai"
    assert h["Referer"] == "https://app.cognexuslabs.ai/"
    assert h["Sec-Fetch-Site"] == "same-origin"
    assert "Mozilla" in h["User-Agent"]
    assert "Chrome" in h["User-Agent"]
    assert "Python-urllib" not in h["User-Agent"]
    assert h["X-Cognexus-Client"] == f"artzain-cli/{__version__}"


def test_quickstart_demo_template_substitutes_metadata() -> None:
    body = _quickstart_demo_file_contents("https://example.test")
    assert "https://example.test" in body
    assert __version__ in body
    assert "google/gemma-4-E4B-it" in body
    assert "run_guard_tests" in body
