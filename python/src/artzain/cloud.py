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
``COGNEXUS_SDK_BROWSER_HEADERS``
    ``"1"`` (default for now) makes the CLI and GUI send browser-like headers
    so the CDN/WAF lets them through; ``"0"`` sends the honest
    ``artzain-python-sdk/<ver>`` identity. See :func:`_sdk_headers`.
"""

from __future__ import annotations

import atexit
import base64
import http.client
import json
import logging
import os
import platform
import queue
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NamedTuple, Optional

_log = logging.getLogger("artzain.cloud")

_override_key: Optional[str] = None
_override_base: Optional[str] = None
_session_lock = threading.Lock()
_session_logged = False
_session_user_prompt: Optional[str] = None
_atexit_registered = False

#: Upper bound on telemetry rows waiting for the background sender. When the
#: queue is full new rows are dropped (and counted) so callers never block.
_QUEUE_MAXSIZE = 1000

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
        _log.debug("credentials profile unavailable; using the default base URL", exc_info=True)
    return "https://app.cognexuslabs.ai"


def _safe_base_for_log(base: str) -> str:
    """Return a log-safe base URL with any embedded credentials removed."""
    value = (base or "").strip()
    if not value:
        return value
    try:
        parts = urllib.parse.urlsplit(value)
        hostname = parts.hostname or ""
        if not hostname:
            return value
        netloc = hostname
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return "redacted"


def _sdk_user_agent() -> str:
    """Identifiable client for CDN/WAF allowlists (Cloudflare blocks bare urllib)."""
    return f"artzain-python-sdk/{_package_version()}"


#: Policy switch for :func:`_sdk_headers`. ``"0"`` (the default since 0.6.11,
#: after the CDN allowlisted the ``artzain-python-sdk/`` User-Agent on
#: ``/api/*``; docs/runbooks/supply-chain.md, "CDN / WAF allowlist") sends the
#: honest SDK identity. ``"1"`` keeps the browser-like header set for an edge
#: that still challenges non-browser clients; that branch and this switch are
#: scheduled for removal in a later release.
_BROWSER_HEADERS_ENV = "COGNEXUS_SDK_BROWSER_HEADERS"
_BROWSER_HEADERS_DEFAULT = "0"

# Cloudflare (and similar) may block ``Python-urllib/…`` or a non-browser TLS
# fingerprint *before* requests reach FastAPI. This mimics a desktop Chrome
# fetch; override with COGNEXUS_CLI_USER_AGENT if your edge still challenges
# the client.
_BROWSER_LIKE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _browser_headers_enabled() -> bool:
    """True when ``COGNEXUS_SDK_BROWSER_HEADERS`` (default ``"0"``) is on."""
    raw = (os.environ.get(_BROWSER_HEADERS_ENV) or _BROWSER_HEADERS_DEFAULT).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _sdk_headers(
    *,
    url: str = "",
    browser_like: Optional[bool] = None,
    browser_user_agent: Optional[str] = None,
) -> dict[str, str]:
    """Base headers for an outbound request to the dashboard API.

    The single place that knows both header sets:

    * honest (``browser_like=False``): ``Accept`` plus the identifiable
      ``artzain-python-sdk/<ver>`` User-Agent that CDN/WAF allowlists match on;
    * browser-like (``browser_like=True``): a desktop-Chrome User-Agent,
      ``Accept-Language`` and, when *url* is given, ``Origin``/``Referer`` and
      the ``Sec-Fetch-*`` metadata of a same-origin browser ``fetch``. This is
      what the edge currently requires for ``/api/auth/*`` and the GUI proxy.

    ``browser_like=None`` (the default) follows :func:`_browser_headers_enabled`,
    i.e. env ``COGNEXUS_SDK_BROWSER_HEADERS``, whose default is ``"0"`` since
    0.6.11: the CDN allowlists the SDK User-Agent on ``/api/*``, so the CLI and
    GUI identify honestly. Set the variable to ``"1"`` only for an edge that
    still challenges non-browser clients.

    *browser_user_agent* (the GUI proxy's real browser UA) replaces the
    synthetic one in browser-like mode and is ignored in honest mode.
    ``COGNEXUS_CLI_USER_AGENT`` overrides the User-Agent in either mode.
    """
    if browser_like is None:
        browser_like = _browser_headers_enabled()
    override = (os.environ.get("COGNEXUS_CLI_USER_AGENT") or "").strip()
    if not browser_like:
        return {
            "Accept": "application/json",
            "User-Agent": override or _sdk_user_agent(),
        }
    h: dict[str, str] = {
        "User-Agent": override or browser_user_agent or _BROWSER_LIKE_UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    parts = urllib.parse.urlsplit(url) if url else None
    if parts and parts.scheme and parts.netloc:
        origin = f"{parts.scheme}://{parts.netloc}"
        h["Origin"] = origin
        h["Referer"] = origin + "/"
        h["Sec-Fetch-Dest"] = "empty"
        h["Sec-Fetch-Mode"] = "cors"
        h["Sec-Fetch-Site"] = "same-origin"
    return h


def _api_request_headers(api_key: Optional[str] = None) -> dict[str, str]:
    headers = _sdk_headers(browser_like=False)
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
            _log.debug("HTTP %s error body is not JSON", exc.code, exc_info=True)
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
            _log.debug("HTTP %s error body is not JSON", exc.code, exc_info=True)
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


class _QueuedPost(NamedTuple):
    """One telemetry POST waiting for the background sender."""

    op: str
    label: str
    url: str
    body: bytes
    headers: dict[str, str]
    timeout_sec: float


class _CloudTransport:
    """One keep-alive ``http.client`` connection reused across telemetry POSTs.

    The connection is opened lazily, kept for the next request, and closed on
    any socket / protocol error so the following request reconnects. A request
    that fails on a *reused* connection (a keep-alive the server has since
    dropped) is retried once on a fresh one.
    """

    def __init__(self) -> None:
        self._conn: Any = None
        self._conn_key: Optional[tuple[str, str, Optional[int], float]] = None

    def close(self) -> None:
        conn, self._conn, self._conn_key = self._conn, None, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                _log.debug("closing the pooled connection failed", exc_info=True)

    @staticmethod
    def _open(scheme: str, host: str, port: Optional[int], timeout_sec: float) -> Any:
        if scheme == "https":
            proxy = urllib.request.getproxies().get("https")
            if proxy and not urllib.request.proxy_bypass(host):
                pp = urllib.parse.urlsplit(proxy)
                conn = http.client.HTTPSConnection(
                    pp.hostname or proxy, pp.port, timeout=timeout_sec
                )
                tunnel_headers: dict[str, str] = {}
                if pp.username is not None:
                    cred = urllib.parse.unquote(pp.username)
                    if pp.password is not None:
                        cred += ":" + urllib.parse.unquote(pp.password)
                    token = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                    tunnel_headers["Proxy-Authorization"] = "Basic " + token
                conn.set_tunnel(host, port, headers=tunnel_headers)
                return conn
            return http.client.HTTPSConnection(host, port, timeout=timeout_sec)
        return http.client.HTTPConnection(host, port, timeout=timeout_sec)

    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout_sec: float
    ) -> tuple[int, bytes]:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        key = (parts.scheme, host, parts.port, float(timeout_sec))
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        for attempt in (1, 2):
            reused = self._conn is not None and self._conn_key == key
            if not reused:
                self.close()
                self._conn = self._open(parts.scheme, host, parts.port, timeout_sec)
                self._conn_key = key
            try:
                self._conn.request("POST", path, body=body, headers=headers)
                resp = self._conn.getresponse()
                data = resp.read()
                return int(resp.status), data
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt == 2 or not reused:
                    raise
        raise RuntimeError("unreachable")  # pragma: no cover


class _CloudWorker:
    """Single daemon thread draining a bounded queue of telemetry POSTs.

    ``enqueue`` never blocks: a full queue drops the row and bumps ``dropped``.
    The thread is started lazily on first use and sends every row over one
    :class:`_CloudTransport`, so a burst of events costs one thread and one
    TLS connection rather than one of each per event.
    """

    def __init__(self, maxsize: int = _QUEUE_MAXSIZE) -> None:
        self._queue: queue.Queue[Optional[_QueuedPost]] = queue.Queue(maxsize=maxsize)
        self._transport = _CloudTransport()
        self._idle = threading.Condition()
        self._pending = 0
        self._thread: Optional[threading.Thread] = None
        self.dropped = 0

    def enqueue(self, item: _QueuedPost) -> bool:
        with self._idle:
            self._pending += 1
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._idle:
                self._pending -= 1
                self.dropped += 1
                n = self.dropped
                if self._pending == 0:
                    self._idle.notify_all()
            if n == 1 or n % max(1, self._queue.maxsize) == 0:
                _log.warning(
                    "cloud: telemetry queue full (%d) — dropped %s %s (%d dropped so far)",
                    self._queue.maxsize,
                    item.op,
                    item.label,
                    n,
                )
            return False
        self._ensure_thread()
        return True

    def _ensure_thread(self) -> None:
        _register_cloud_atexit()
        with self._idle:
            t = self._thread
            if t is not None and t.is_alive():
                return
            t = threading.Thread(target=self._run, name="artzain-cloud", daemon=True)
            self._thread = t
            t.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._transport.close()
                return
            try:
                _deliver_post(self._transport, item)
            except Exception as exc:  # pragma: no cover - _deliver_post logs its own
                _log.warning("cloud: %s %s failed: %s", item.op, item.label, exc)
            finally:
                with self._idle:
                    self._pending -= 1
                    if self._pending == 0:
                        self._idle.notify_all()

    def flush(self, timeout_sec: float = 10.0) -> bool:
        """Wait until every queued row has been sent (or *timeout_sec* passes)."""
        deadline = time.monotonic() + max(0.0, float(timeout_sec))
        with self._idle:
            while self._pending > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._idle.wait(remaining)
        return True

    def close(self, timeout_sec: float = 10.0) -> None:
        """Drain, then stop the worker thread (tests / interpreter shutdown)."""
        self.flush(timeout_sec)
        with self._idle:
            t = self._thread
            self._thread = None
        if t is not None and t.is_alive():
            self._queue.put(None)
            t.join(timeout=max(0.1, float(timeout_sec)))


_worker = _CloudWorker()


def _enqueue_post(item: _QueuedPost) -> bool:
    """Hand one POST to the background worker (patched by tests to run inline)."""
    return _worker.enqueue(item)


def _deliver_post(transport: _CloudTransport, item: _QueuedPost) -> None:
    """Send one queued POST; log failures, never raise."""
    try:
        status, body = transport.post(item.url, item.body, item.headers, item.timeout_sec)
    except Exception as exc:
        _log.warning("cloud: %s %s failed: %s", item.op, item.label, exc)
        return
    if status >= 400:
        _log_http_status(item.op, item.label, status, body)


def dropped_cloud_events() -> int:
    """Number of telemetry rows dropped because the send queue was full."""
    return _worker.dropped


def flush_cloud_events(timeout_sec: float = 10.0) -> None:
    """Wait for queued cloud POSTs to be sent (CLI demos, quickstart scripts).

    ``post_sdk_event`` is fire-and-forget: rows are queued for a single
    background daemon thread so application servers are not blocked.
    Short-lived processes must flush (or rely on the registered ``atexit``
    hook) or events may never reach the dashboard.
    """
    _worker.flush(timeout_sec)


def _log_http_error(op: str, event_type: str, exc: urllib.error.HTTPError) -> None:
    body = b""
    try:
        body = exc.read()
    except Exception:
        _log.debug("cloud: %s %s HTTP %s body unreadable", op, event_type, exc.code, exc_info=True)
    _log_http_status(op, event_type, exc.code, body)


def _log_http_status(op: str, event_type: str, code: int, raw: bytes) -> None:
    body = ""
    try:
        body = raw.decode("utf-8", errors="replace")[:240]
    except Exception:
        _log.debug("cloud: %s %s HTTP %s body undecodable", op, event_type, code, exc_info=True)
    if code == 403 and ("1010" in body or "cloudflare" in body.lower()):
        _log.warning(
            "cloud: %s %s failed HTTP 403 (CDN/WAF — use a current artzain package "
            "or allow User-Agent %r on /api/events)",
            op,
            event_type,
            _sdk_user_agent(),
        )
        return
    if code == 401:
        _log.warning(
            "cloud: %s %s failed HTTP 401 — invalid or revoked API key for %s",
            op,
            event_type,
            _safe_base_for_log(_effective_base()),
        )
        return
    _log.warning("cloud: %s %s failed HTTP %s %s", op, event_type, code, body)


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
    """POST one row to ``/api/events`` (fire-and-forget via the background worker).

    Never raises to callers. Logs at DEBUG when skipped (no key); WARNING when
    the HTTP round-trip fails after a key was present, or when the bounded send
    queue is full and the row is dropped (see :func:`dropped_cloud_events`).

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
    headers = _api_request_headers(key)
    headers["Content-Type"] = "application/json"
    try:
        _enqueue_post(
            _QueuedPost(
                op="event POST",
                label=event_type,
                url=_effective_base() + "/api/events",
                body=json.dumps(body_obj, ensure_ascii=False).encode("utf-8"),
                headers=headers,
                timeout_sec=float(timeout_sec),
            )
        )
    except Exception as exc:
        _log.warning("cloud: event POST %s failed: %s", event_type, exc)


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
    headers = _api_request_headers(key)
    headers["Content-Type"] = "application/json"
    try:
        _enqueue_post(
            _QueuedPost(
                op="policy decision POST",
                label=v,
                url=_effective_base() + "/api/policy-decisions",
                body=json.dumps(body_obj, ensure_ascii=False).encode("utf-8"),
                headers=headers,
                timeout_sec=float(timeout_sec),
            )
        )
    except Exception as exc:
        _log.warning("cloud: policy decision POST failed: %s", exc)


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
    "dropped_cloud_events",
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
