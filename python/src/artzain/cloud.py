"""Optional HTTPS ingest of SDK telemetry into the CogNEXUS dashboard.

Requires an API key created under **Account → API Keys** in the dashboard.
If no key or base URL is configured, :func:`post_sdk_event` returns immediately
without raising — user application code keeps running.

Environment variables
---------------------
``COGNEXUS_API_KEY``
    Primary secret sent as ``X-Api-Key``.
``MYAPP_API_KEY``
    Fallback secret name (same semantics as ``COGNEXUS_API_KEY``).
``COGNEXUS_API_BASE_URL``
    API origin, e.g. ``https://app.cognexuslabs.ai`` — **no trailing slash required**.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import platform
import sys
import threading
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

_log = logging.getLogger("artzain.cloud")

_override_key: Optional[str] = None
_override_base: Optional[str] = None
_session_lock = threading.Lock()
_session_logged = False
_session_user_prompt: Optional[str] = None
_pending_cloud_threads: list[threading.Thread] = []
_pending_cloud_lock = threading.Lock()
_atexit_registered = False

_MISSING = object()


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("artzain")
    except Exception:
        return "unknown"


def has_api_key() -> bool:
    """True when cloud ingest is configured (override or env)."""
    return _effective_key() is not None


def note_session_user_prompt(text: str) -> None:
    """Remember the latest end-user prompt for subsequent cloud event rows."""
    global _session_user_prompt
    cleaned = " ".join((text or "").split())
    if cleaned:
        with _session_lock:
            _session_user_prompt = cleaned


def session_user_prompt() -> Optional[str]:
    """Return the latest end-user prompt noted this process, if any."""
    with _session_lock:
        return _session_user_prompt


def _redact_prompt_preview(text: str, max_len: int = 96) -> str:
    one_line = " ".join((text or "").split())[:max_len]
    return one_line + ("\u2026" if len((text or "")) > max_len else "")


def _key_hint(key: str, keep: int = 14) -> str:
    """Display form of an API key: a truncated prefix, or ``"redacted"``.

    A value too short to spare a prefix is masked entirely, so a mistyped or
    malformed key is never echoed in full to a terminal or CI log.
    """
    key = (key or "").strip()
    if len(key) <= keep:
        return "redacted"
    return key[:keep] + "\u2026"


def configure(*, api_key: Any = _MISSING, base_url: Any = _MISSING) -> None:
    """Set package-wide defaults (overrides env until cleared).

    Pass ``api_key=None`` or ``base_url=None`` to clear an override and fall
    back to environment variables / built-in default base URL.
    """
    global _override_key, _override_base
    if api_key is not _MISSING:
        if api_key is None:
            _override_key = None
        else:
            _override_key = str(api_key).strip() or None
    if base_url is not _MISSING:
        if base_url is None:
            _override_base = None
        else:
            _override_base = str(base_url).strip().rstrip("/") or None


def _effective_key() -> Optional[str]:
    if _override_key:
        return _override_key
    env = (
        (os.environ.get("COGNEXUS_API_KEY") or "").strip()
        or (os.environ.get("MYAPP_API_KEY") or "").strip()
        or None
    )
    if env:
        return env
    try:
        from artzain.credentials import profile_api_key
        return profile_api_key()
    except Exception:
        return None


def _effective_base() -> str:
    if _override_base:
        return _override_base.rstrip("/")
    raw = (os.environ.get("COGNEXUS_API_BASE_URL") or "").strip().rstrip("/")
    if raw:
        return raw
    try:
        from artzain.credentials import profile_base_url
        prof = profile_base_url()
        if prof:
            return prof
    except Exception:
        pass
    return "https://app.cognexuslabs.ai"


def _sdk_user_agent() -> str:
    """Identifiable client for CDN/WAF allowlists (Cloudflare blocks bare urllib)."""
    return f"artzain-python-sdk/{_package_version()}"


def _api_request_headers(api_key: Optional[str] = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": _sdk_user_agent(),
    }
    if api_key:
        headers["X-Api-Key"] = api_key
    return headers


def _probe_api_key_via_events(*, timeout_sec: float = 8.0) -> dict[str, Any]:
    """Validate the configured key with ``POST /api/events`` (older dashboard builds).

    Used when ``GET /api/api-keys/me`` is not deployed yet (HTTP 405/404).
    """
    base = _effective_base()
    key = _effective_key()
    if not key:
        return {"valid": False, "error": "no_api_key", "base_url": base}

    body_obj = {
        "event_type": "sdk_key_probe",
        "source": "pypi_sdk",
        "level": "info",
        "title": "SDK · key probe",
        "payload": {"probe": True},
    }
    url = base + "/api/events"
    data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
    headers = _api_request_headers(key)
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status >= 400:
                return {
                    "valid": False,
                    "error": f"http_{resp.status}",
                    "base_url": base,
                    "http_status": resp.status,
                }
        return {
            "valid": True,
            "key_prefix": key[:14],
            "key_label": "",
            "email": "",
            "display_name": "",
            "base_url": base,
            "verified_via": "events",
        }
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw.strip() else {}
            if isinstance(parsed, dict) and parsed.get("detail"):
                detail = str(parsed["detail"])
        except Exception:
            pass
        if exc.code == 401:
            err = detail or "invalid_or_revoked"
        elif exc.code == 403:
            err = detail or "blocked_by_cdn"
        else:
            err = detail or f"http_{exc.code}"
        return {"valid": False, "error": err, "base_url": base, "http_status": exc.code}
    except Exception as exc:
        return {"valid": False, "error": str(exc), "base_url": base}


def fetch_api_key_identity(*, timeout_sec: float = 8.0) -> dict[str, Any]:
    """Check whether the configured API key is valid and return account metadata.

    Returns a dict with ``valid`` (bool). When valid, includes ``email``,
    ``display_name``, ``key_prefix``, ``key_label``, and ``base_url``.

    Tries ``GET /api/api-keys/me`` first. On older dashboards that do not expose
    that route (HTTP 404/405), falls back to a lightweight ``POST /api/events``
    probe so quickstart still reports whether ingest will work.
    """
    base = _effective_base()
    key = _effective_key()
    if not key:
        return {"valid": False, "error": "no_api_key", "base_url": base}

    url = base + "/api/api-keys/me"
    req = urllib.request.Request(url, method="GET", headers=_api_request_headers(key))
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body) if body.strip() else {}
        if not isinstance(data, dict) or not data.get("ok"):
            return {
                "valid": False,
                "error": "unexpected_response",
                "base_url": base,
            }
        return {
            "valid": True,
            "email": str(data.get("email") or "").strip(),
            "display_name": str(data.get("display_name") or "").strip(),
            "key_prefix": str(data.get("key_prefix") or key[:14]).strip(),
            "key_label": str(data.get("key_label") or "").strip(),
            "base_url": base,
            "verified_via": "api_keys_me",
        }
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            return _probe_api_key_via_events(timeout_sec=timeout_sec)
        detail = ""
        try:
            raw = exc.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw.strip() else {}
            if isinstance(parsed, dict) and parsed.get("detail"):
                detail = str(parsed["detail"])
        except Exception:
            pass
        if exc.code == 401:
            err = detail or "invalid_or_revoked"
        elif exc.code == 403:
            err = detail or "blocked_by_cdn"
        else:
            err = detail or f"http_{exc.code}"
        return {"valid": False, "error": err, "base_url": base, "http_status": exc.code}
    except Exception as exc:
        return {"valid": False, "error": str(exc), "base_url": base}


def announce_cloud_ingest(*, file: Any = None) -> bool:
    """Print whether Event Logs ingest is configured and which account owns the key.

    Intended for ``artzain quickstart`` and generated demo scripts so users can
    confirm events will land on the expected dashboard profile.

    Returns ``True`` when the API key was validated against the dashboard API.
    """
    out = file if file is not None else sys.stdout
    base = _effective_base()
    key = _effective_key()

    print(file=out)
    print("Cloud ingest (Event Logs)", file=out)
    print(f"  Dashboard API:  {base}", file=out)

    if not key:
        print("  API key:        not set", file=out)
        print(
            "  Event Logs:     disabled — create a key under Account → API Keys,\n"
            "                  set COGNEXUS_API_KEY, then re-run.",
            file=out,
        )
        print(file=out)
        return False

    info = fetch_api_key_identity()
    if info.get("valid"):
        server_prefix = str(info.get("key_prefix") or "").strip()
        hint = f"{server_prefix}…" if server_prefix else _key_hint(key)
        label = str(info.get("key_label") or "").strip()
        email = str(info.get("email") or "").strip()
        name = str(info.get("display_name") or "").strip()
        verified_via = str(info.get("verified_via") or "").strip()
        print(f"  API key:        valid ({hint})", file=out)
        if label:
            print(f"  Key label:      {label}", file=out)
        if email:
            account = email
            if name and name.lower() != email.lower():
                account = f"{email} ({name})"
            print(f"  Account:        {account}", file=out)
        elif verified_via == "events":
            print(
                "  Account:        email lookup unavailable on this dashboard build\n"
                "                  (deploy latest API for /api/api-keys/me)",
                file=out,
            )
        print(
            f"  Event Logs:     enabled — view under Account → Event Logs on {base}",
            file=out,
        )
        print(file=out)
        return True

    err = str(info.get("error") or "unknown")
    print(f"  API key:        invalid or unreachable ({_key_hint(key)})", file=out)
    if err == "invalid_or_revoked":
        print(
            "  Event Logs:     disabled — key is invalid or revoked. Create a new key\n"
            "                  under Account → API Keys and update COGNEXUS_API_KEY.",
            file=out,
        )
    elif err == "blocked_by_cdn":
        print(
            "  Event Logs:     may be blocked — the dashboard CDN rejected this client.\n"
            "                  Upgrade the artzain package or allow the SDK User-Agent.",
            file=out,
        )
    elif err == "no_api_key":
        print("  Event Logs:     disabled — no API key configured.", file=out)
    else:
        print(
            f"  Event Logs:     could not verify key ({err}). Events may not be recorded.",
            file=out,
        )
    print(file=out)
    return False


def _register_cloud_atexit() -> None:
    global _atexit_registered
    if _atexit_registered:
        return
    _atexit_registered = True
    atexit.register(flush_cloud_events)


def _start_cloud_thread(fn: Callable[[], None]) -> None:
    """Run *fn* on a background thread and track it for :func:`flush_cloud_events`."""
    thread_box: list[threading.Thread | None] = [None]

    def _run() -> None:
        try:
            fn()
        finally:
            t = thread_box[0]
            if t is not None:
                with _pending_cloud_lock:
                    try:
                        _pending_cloud_threads.remove(t)
                    except ValueError:
                        pass

    t = threading.Thread(target=_run, daemon=True)
    thread_box[0] = t
    with _pending_cloud_lock:
        _pending_cloud_threads.append(t)
    _register_cloud_atexit()
    t.start()


def flush_cloud_events(timeout_sec: float = 10.0) -> None:
    """Wait for in-flight cloud POST threads (CLI demos, quickstart scripts).

    ``post_sdk_event`` is fire-and-forget on a daemon thread so application
    servers are not blocked.  Short-lived processes must flush (or rely on the
    registered ``atexit`` hook) or events may never reach the dashboard.
    """
    with _pending_cloud_lock:
        threads = list(_pending_cloud_threads)
    if not threads:
        return
    per_thread = max(0.1, float(timeout_sec) / len(threads))
    for t in threads:
        t.join(timeout=per_thread)


def _log_http_error(op: str, event_type: str, exc: urllib.error.HTTPError) -> None:
    body = ""
    try:
        body = exc.read().decode("utf-8", errors="replace")[:240]
    except Exception:
        pass
    if exc.code == 403 and ("1010" in body or "cloudflare" in body.lower()):
        _log.warning(
            "cloud: %s %s failed HTTP 403 (CDN/WAF — use a current artzain package "
            "or allow User-Agent %r on /api/events)",
            op,
            event_type,
            _sdk_user_agent(),
        )
        return
    if exc.code == 401:
        _log.warning(
            "cloud: %s %s failed HTTP 401 — invalid or revoked API key for %s",
            op,
            event_type,
            _effective_base(),
        )
        return
    _log.warning("cloud: %s %s failed HTTP %s %s", op, event_type, exc.code, body)


def ensure_sdk_session_logged() -> None:
    """Post one ``sdk_session`` row per process when an API key is configured."""
    global _session_logged
    if not has_api_key():
        return
    with _session_lock:
        if _session_logged:
            return
        _session_logged = True
    post_sdk_event(
        "sdk_session",
        source="pypi_sdk",
        level="info",
        title="Python SDK · session started",
        payload={
            "package": "artzain",
            "version": _package_version(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        _skip_session_hook=True,
    )


def post_generation_outcome(
    *,
    outcome: str,
    reason: str,
    model_id: Optional[str] = None,
    request_id: Optional[str] = None,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
    prompt: Optional[str] = None,
    latency_ms: Optional[float] = None,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    """Log an LLM generation pass or failure to the dashboard (optional helper).

    Call after ``model.generate()`` (or your provider's equivalent) when you want
    generation outcomes visible in **Event Logs**, and token spend reflected on
    the **Leaderboard** / **Token-to-Outcome** analytics, alongside prompt-defense
    rows.

    Args:
        outcome: ``"passed"`` or ``"failed"`` (other values are stored as-is).
        reason: Human-readable explanation (e.g. blocked by guard, success, timeout).
        model_id: Optional model / deployment label.
        request_id: Correlation id (new UUID hex when omitted).
        tokens_in: Optional prompt / input token count. Drives the Leaderboard's
            "Total Tokens In" and the Token-to-Outcome (T2O) averages.
        tokens_out: Optional completion / output token count.
        prompt: Optional end-user prompt for this generation. Only a redacted
            preview is sent; it lets the prompt defender classify the
            department / outcome for Token-to-Outcome even when
            :func:`screen_user_input` was not called for this turn.
        latency_ms: Optional wall time in milliseconds.
        extra: Additional JSON-serialisable fields merged into the payload.
    """
    oc = (outcome or "").strip().lower()
    if oc == "passed":
        level = "success"
        title = "Generation · PASSED"
    elif oc == "failed":
        level = "error"
        title = "Generation · FAILED"
    else:
        level = "info"
        title = f"Generation · {outcome or 'event'}"

    import uuid

    rid = (request_id or uuid.uuid4().hex).lower()
    payload: dict[str, Any] = {
        "outcome": oc or outcome,
        "reason": (reason or "").strip()[:2000],
        "request_id": rid,
        "model_id": model_id,
    }
    if prompt:
        payload["user_prompt"] = _redact_prompt_preview(prompt)
    if latency_ms is not None:
        payload["latency_ms"] = max(0.0, float(latency_ms))
    if extra:
        payload.update(extra)

    post_sdk_event(
        "generation",
        source="pypi_sdk",
        level=level,
        title=title,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        payload=payload,
    )


def post_sdk_event(
    event_type: str,
    *,
    source: str = "pypi_sdk",
    payload: Optional[dict[str, Any]] = None,
    level: str = "info",
    title: Optional[str] = None,
    tokens_in: Optional[int] = None,
    tokens_out: Optional[int] = None,
    timeout_sec: float = 5.0,
    _skip_session_hook: bool = False,
) -> None:
    """POST one row to ``/api/events`` (fire-and-forget thread).

    Never raises to callers. Logs at DEBUG when skipped (no key); WARNING when
    the HTTP round-trip fails after a key was present.

    ``tokens_in`` / ``tokens_out`` attribute LLM token spend to this decision so
    it appears on the dashboard Leaderboard and Token-to-Outcome analytics. They
    are merged into the payload (explicit args win over any payload values).

    The first successful post in a process also emits ``sdk_session`` (package
    version and runtime) so the dashboard shows when the SDK was invoked.
    """
    key = _effective_key()
    if not key:
        _log.debug("cloud: skip event %r — no COGNEXUS_API_KEY / MYAPP_API_KEY", event_type)
        return

    if not _skip_session_hook:
        ensure_sdk_session_logged()

    pl = dict(payload or {})
    if not pl.get("user_prompt"):
        sp = session_user_prompt()
        if sp:
            pl["user_prompt"] = _redact_prompt_preview(sp)
    if tokens_in is not None:
        try:
            pl["tokens_in"] = max(0, int(tokens_in))
        except (TypeError, ValueError):
            pass
    if tokens_out is not None:
        try:
            pl["tokens_out"] = max(0, int(tokens_out))
        except (TypeError, ValueError):
            pass

    body_obj = {
        "event_type": event_type,
        "source": source,
        "payload": pl,
        "level": level,
        "title": title,
    }

    def _run() -> None:
        url = _effective_base() + "/api/events"
        data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
        headers = _api_request_headers(key)
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status >= 400:
                    _log.warning(
                        "cloud: event POST %s returned HTTP %s", event_type, resp.status
                    )
        except urllib.error.HTTPError as exc:
            _log_http_error("event POST", event_type, exc)
        except Exception as exc:
            _log.warning("cloud: event POST %s failed: %s", event_type, exc)

    _start_cloud_thread(_run)


def post_policy_human_decision(
    verdict: str,
    *,
    request_id: str = "",
    surface: str = "pypi_sdk_review",
    notes: str = "",
    timeout_sec: float = 5.0,
) -> None:
    """POST a human **approved** / **denied** follow-up to ``/api/policy-decisions``.

    Uses the same API key and base URL as :func:`post_sdk_event`. Fire-and-forget;
    never raises.
    """
    key = _effective_key()
    if not key:
        _log.debug("cloud: skip policy decision %r — no COGNEXUS_API_KEY / MYAPP_API_KEY", verdict)
        return
    v = (verdict or "").strip().lower()
    if v not in ("approved", "denied"):
        _log.warning("cloud: policy decision verdict must be approved|denied, got %r", verdict)
        return

    body_obj = {
        "verdict": v,
        "request_id": (request_id or "").strip()[:64],
        "surface": (surface or "pypi_sdk_review").strip()[:200] or "pypi_sdk_review",
        "notes": (notes or "").strip()[:2000],
    }

    def _run() -> None:
        url = _effective_base() + "/api/policy-decisions"
        data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
        headers = _api_request_headers(key)
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status >= 400:
                    _log.warning(
                        "cloud: policy decision POST returned HTTP %s", resp.status
                    )
        except urllib.error.HTTPError as exc:
            _log_http_error("policy decision POST", verdict, exc)
        except Exception as exc:
            _log.warning("cloud: policy decision POST failed: %s", exc)

    _start_cloud_thread(_run)


def fetch_client_policy_rules(
    *,
    timeout_sec: float = 12.0,
) -> list[dict[str, Any]]:
    """Download tenant policy rules from ``GET /api/policy-enforcement/rules``.

    Requires ``COGNEXUS_API_KEY`` (or :func:`configure`). Returns an empty list
    when no key is configured or the request fails.
    """
    key = _effective_key()
    if not key:
        _log.debug("cloud: skip policy rules fetch — no API key")
        return []
    url = _effective_base() + "/api/policy-enforcement/rules"
    req = urllib.request.Request(
        url,
        method="GET",
        headers=_api_request_headers(key),
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body)
        rules = data.get("rules") if isinstance(data, dict) else None
        return list(rules) if isinstance(rules, list) else []
    except urllib.error.HTTPError as exc:
        _log_http_error("policy rules GET", "policy-enforcement", exc)
        return []
    except Exception as exc:
        _log.warning("cloud: policy rules fetch failed: %s", exc)
        return []


__all__ = [
    "announce_cloud_ingest",
    "configure",
    "ensure_sdk_session_logged",
    "fetch_api_key_identity",
    "fetch_client_policy_rules",
    "flush_cloud_events",
    "has_api_key",
    "note_session_user_prompt",
    "session_user_prompt",
    "post_generation_outcome",
    "post_sdk_event",
    "post_policy_human_decision",
]
