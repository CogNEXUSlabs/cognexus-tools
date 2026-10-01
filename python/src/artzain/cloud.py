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
    An ``http://`` or ``https://`` URL; with any other, no key is sent.
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
import select
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NamedTuple, Optional

from artzain._surrogates import replace_unpaired_surrogates, without_unpaired_surrogates
from artzain.credentials import (
    DEFAULT_BASE_URL,
    CredentialConflictError,
    ResolvedCredentials,
    resolve_credentials,
)

_log = logging.getLogger("artzain.cloud")

#: What :func:`configure` set: the API key and the base URL, ``None`` for one
#: not set. One value that configure() replaces whole, so a call that reads it
#: without the lock gets the pair as one configure() call left it, never a mix
#: of two.
_overrides: tuple[Optional[str], Optional[str]] = (None, None)
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
    """Remember the latest end-user prompt for subsequent cloud event rows.

    A row posted without a ``user_prompt`` of its own carries it as
    ``user_prompt``, redacted the way the audit trail's preview is. The
    prompt-defense and policy rows :mod:`artzain.events` posts do not: their
    ``preview`` is the screened text itself.
    """
    global _session_user_prompt
    # A lone surrogate cannot be encoded into the event body, and the prompt
    # rides on every later event, so one would drop them all.
    cleaned = replace_unpaired_surrogates(" ".join((text or "").split()))
    if cleaned:
        with _session_lock:
            _session_user_prompt = cleaned


def session_user_prompt() -> Optional[str]:
    """Return the latest end-user prompt noted this process, if any."""
    with _session_lock:
        return _session_user_prompt


def _redact_prompt_preview(text: str, max_len: int = 96) -> str:
    """The audit trail's preview of a prompt, for the events posted here.

    One implementation, in :mod:`artzain.events`: a prompt travels to the
    dashboard under ``user_prompt``, so it is masked the way the JSONL row
    is. Imported on call: ``events`` brings in the detectors, which this
    module does not need.
    """
    from artzain.events import _redact_preview

    return _redact_preview(text, max_len)


def _key_hint(key: str, keep: int = 14) -> str:
    """Display form of an API key: a truncated prefix, or ``"redacted"``.

    A value too short to spare a prefix is masked entirely, so a mistyped or
    malformed key is never echoed in full to a terminal or CI log.
    """
    key = (key or "").strip()
    if len(key) <= keep:
        return "redacted"
    return key[:keep] + "\u2026"


#: Bumped each time :func:`configure` changes the key or the base URL, after
#: the change, so a cache of what the previous ones fetched can tell it is stale
#: (``artzain._helpers.load_client_policy_rules``).
_credentials_generation = 0
#: Makes a configure() call one step, so two at once cannot drop each other's
#: change to the pair or cancel the bump. Readers of the pair do not take it.
_configure_lock = threading.Lock()


def configure(*, api_key: Any = _MISSING, base_url: Any = _MISSING) -> None:
    """Set package-wide defaults (overrides env until cleared).

    Pass ``api_key=None`` or ``base_url=None`` to clear an override and fall
    back to environment variables / built-in default base URL.

    A call made meanwhile, on another thread or from a signal handler, uses
    the key and base URL as they were before this call or as it leaves them,
    never one of each.
    """
    global _overrides, _credentials_generation
    with _configure_lock:
        key, base = _overrides
        if api_key is not _MISSING:
            if api_key is None:
                key = None
            else:
                key = str(api_key).strip() or None
        if base_url is not _MISSING:
            if base_url is None:
                base = None
            else:
                base = str(base_url).strip().rstrip("/") or None
        if (key, base) != _overrides:
            # One assignment, after both values are known: a call that reads
            # the settings meanwhile gets the previous pair or this one, and a
            # value that raises above changes neither.
            _overrides = (key, base)
            _credentials_generation += 1


def _resolve() -> ResolvedCredentials:
    """The API key and the host it goes to, decided together.

    Raises :class:`~artzain.credentials.CredentialConflictError` when a set
    host is not the one the key was issued with, or when the credentials
    profile is there but cannot be read.
    """
    # One read, so a configure() on another thread cannot land between the
    # key and the base URL.
    api_key, base_url = _overrides
    return resolve_credentials(api_key=api_key, base_url=base_url)


#: Conflict messages already logged, so fire-and-forget callers warn once.
_conflicts_warned: set[str] = set()


def _warn_conflict(exc: CredentialConflictError) -> None:
    """Log *exc* at WARNING the first time its message comes up in the process.

    Its message names the settings involved, never their values.
    """
    message = str(exc)
    if message not in _conflicts_warned:
        _conflicts_warned.add(message)
        _log.warning("cloud: %s", message)


def _resolve_or_warn() -> Optional[ResolvedCredentials]:
    """:func:`_resolve` for calls that must never raise: ``None`` on a conflict,
    or when the credentials profile cannot be read (see :func:`_warn_conflict`).
    """
    try:
        return _resolve()
    except CredentialConflictError as exc:
        _warn_conflict(exc)
        return None


def _effective_key() -> Optional[str]:
    creds = _resolve_or_warn()
    return creds.api_key if creds else None


def _effective_base() -> str:
    creds = _resolve_or_warn()
    if creds:
        return creds.base_url
    return DEFAULT_BASE_URL


def _base_url_source() -> str:
    """Which setting decides the base URL now — a label, never the value.

    It is the ``base_source`` of the credentials resolved now. A failed call's
    log line gives the ``base_source`` of the credentials that call was made
    with (:func:`_log_failure`) instead of the URL: the profile that can carry
    ``base_url`` is the same file that carries the API key, and a log entry
    must not be built from anything read out of it.
    """
    creds = _resolve_or_warn()
    return creds.base_source if creds else "conflicting settings"


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


#: The last opener :func:`_api_opener` built, with the settings it was built
#: for.
_api_opener_built: Optional[tuple[Any, urllib.request.OpenerDirector]] = None


def _api_opener() -> urllib.request.OpenerDirector:
    """The handlers ``urlopen`` uses, for ``http`` and ``https`` only, and
    without its redirect handler.

    That handler copies a request's headers, the API key or a session token
    among them, onto the request it sends wherever ``Location`` points,
    another host included. None of the routes the SDK calls answers with a
    redirect, so here a 3xx is raised as the ``HTTPError`` it is, like any
    other status the call did not expect, and nothing is sent anywhere else.

    The proxies are the ones ``urlopen`` would use (the environment's, or the
    system's on Windows and macOS), read for each request, but only those for
    ``http`` and ``https``: a proxy set for another scheme, as Windows sets
    its one system proxy for every scheme, would take a request for that
    scheme to it over plain HTTP, headers and all.

    The opener is built again only when the proxies change, or what a new
    TLS context would be made from (``ssl._create_default_https_context``,
    ``SSL_CERT_FILE``, ``SSL_CERT_DIR``): building one builds a TLS context,
    which loads the certificate store, and a context kept from a moment when
    an application had turned verification off would not verify later
    requests. An opener an application installs with
    ``urllib.request.install_opener`` is not used.
    """
    global _api_opener_built
    proxies = {
        scheme: url
        for scheme, url in urllib.request.getproxies().items()
        if scheme.lower() in ("http", "https")
    }
    setting = (
        tuple(sorted(proxies.items())),
        ssl._create_default_https_context,
        os.environ.get("SSL_CERT_FILE"),
        os.environ.get("SSL_CERT_DIR"),
    )
    built = _api_opener_built
    if built is not None and built[0] == setting:
        return built[1]
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(proxies),
        urllib.request.UnknownHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    _api_opener_built = (setting, opener)
    return opener


def _urlopen(req: urllib.request.Request, *, timeout: float) -> Any:
    """``urllib.request.urlopen(req, timeout=timeout)`` without following a
    redirect (:func:`_api_opener`). Every urllib request that carries the API
    key or a session token goes through here: ``decide()``, the key check and
    the policy-rules fetch in this module, the CLI's and ``artzain gui``'s.
    The event and policy-decision posts go through :class:`_CloudTransport`,
    which follows no redirect either."""
    return _api_opener().open(req, timeout=timeout)


def _probe_api_key_via_events(*, timeout_sec: float = 8.0) -> dict[str, Any]:
    """Validate the configured key with ``POST /api/events`` (older dashboard builds).

    Used when ``GET /api/api-keys/me`` is not deployed yet (HTTP 405/404).
    """
    creds = _resolve_or_warn()
    if creds is None:
        return {"valid": False, "error": "credential_conflict"}
    base, key = creds.base_url, creds.api_key
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
    data = json.dumps(without_unpaired_surrogates(body_obj), ensure_ascii=False).encode("utf-8")
    headers = _api_request_headers(key)
    headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        with _urlopen(req, timeout=timeout_sec) as resp:
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
        # The caller reports ``error``; the error's text is for the log only
        # (see _describe_failure).
        _log.debug("cloud: API key probe POST events failed: %s", exc)
        return {"valid": False, "error": _describe_failure(exc, creds.base_source), "base_url": base}


def fetch_api_key_identity(*, timeout_sec: float = 8.0) -> dict[str, Any]:
    """Check whether the configured API key is valid and return account metadata.

    Returns a dict with ``valid`` (bool). When valid, includes ``email``,
    ``display_name``, ``key_prefix``, ``key_label``, and ``base_url``.

    Tries ``GET /api/api-keys/me`` first. On older dashboards that do not expose
    that route (HTTP 404/405), falls back to a lightweight ``POST /api/events``
    probe so quickstart still reports whether ingest will work.
    """
    creds = _resolve_or_warn()
    if creds is None:
        return {"valid": False, "error": "credential_conflict"}
    base, key = creds.base_url, creds.api_key
    if not key:
        return {"valid": False, "error": "no_api_key", "base_url": base}

    url = base + "/api/api-keys/me"
    try:
        req = urllib.request.Request(url, method="GET", headers=_api_request_headers(key))
        with _urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            return _probe_api_key_via_events(timeout_sec=timeout_sec)
        detail = ""
        try:
            page = exc.read().decode("utf-8", errors="replace")
            parsed = json.loads(page) if page.strip() else {}
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
        # The caller reports ``error``, quickstart on the terminal; the error's
        # text is for the log only (see _describe_failure).
        _log.debug("cloud: API key check GET api-keys/me failed: %s", exc)
        return {"valid": False, "error": _describe_failure(exc, creds.base_source), "base_url": base}
    try:
        data = json.loads(raw.decode("utf-8")) if raw.strip() else {}
    except (ValueError, RecursionError):
        # Not JSON or not UTF-8, or nested deeper than the decoder follows.
        _log.debug("cloud: API key check GET api-keys/me answered with a body that is not JSON")
        data = None
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


def announce_cloud_ingest(*, file: Any = None) -> bool:
    """Print whether Event Logs ingest is configured and which account owns the key.

    Intended for ``artzain quickstart`` and generated demo scripts so users can
    confirm events will land on the expected dashboard profile.

    Returns ``True`` when the API key was validated against the dashboard API.
    """
    out = file if file is not None else sys.stdout
    print(file=out)
    print("Cloud ingest (Event Logs)", file=out)
    try:
        creds = _resolve()
    except CredentialConflictError as exc:
        print(f"  Event Logs:     disabled — {exc}", file=out)
        print(file=out)
        return False
    base, key = creds.base_url, creds.api_key
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
    #: Where the base of ``url`` came from (``ResolvedCredentials.base_source``),
    #: for the log line of a failed send.
    base_source: str


class _CloudTransport:
    """One keep-alive ``http.client`` connection reused across telemetry POSTs.

    The connection is opened lazily, kept for the next request, and closed on
    any socket / protocol error so the following request reconnects. A kept
    connection the server has closed while idle, or one idle for longer than
    a NAT on the way may keep it, is replaced before a request is sent on
    it. A request is sent again (once, on a fresh connection) only
    when sending it failed on a kept connection, never once it may have
    reached the server: the posts are not idempotent.
    """

    def __init__(self) -> None:
        self._conn: Any = None
        self._conn_key: Optional[tuple[str, str, Optional[int], float]] = None
        self._idle_since = 0.0  # when the kept connection's last answer came

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
        if scheme == "http":
            return http.client.HTTPConnection(host, port, timeout=timeout_sec)
        raise ValueError("not an http:// or https:// URL")

    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout_sec: float
    ) -> tuple[int, bytes]:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme not in ("https", "http") or not host:
            # Any other scheme went over plain HTTP, and a URL with no host
            # dialled an empty one: this machine. The credentials are refused
            # such a base URL where they are resolved; this refuses any other
            # URL that reaches the sender. The message leaves the URL out.
            raise ValueError("not an http:// or https:// URL that names a host")
        key = (parts.scheme, host, parts.port, float(timeout_sec))
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        for attempt in (1, 2):
            if (self._conn is None or self._conn_key != key
                    or time.monotonic() - self._idle_since > _CONNECTION_IDLE_LIMIT_SEC
                    or _server_closed(self._conn)):
                self.close()
                self._conn = self._open(parts.scheme, host, parts.port, timeout_sec)
                self._conn_key = key
            # A socket kept from an earlier request (``http.client`` opens a
            # new one when it holds none).
            reused = getattr(self._conn, "sock", None) is not None
            try:
                self._conn.request("POST", path, body=body, headers=headers)
            except Exception as exc:
                # A connection left mid-request (a header value refused
                # before sending, say) cannot carry the next one.
                self.close()
                # The request did not get out whole, so the server cannot
                # have acted on it: on a kept-alive connection, one more try
                # on a fresh one. A send that timed out met a slow server,
                # not a closed connection.
                if (attempt == 2 or not reused or isinstance(exc, TimeoutError)
                        or not isinstance(exc, (http.client.HTTPException, OSError))):
                    raise
                continue
            try:
                resp = self._conn.getresponse()
                data = resp.read()
            except Exception:
                # The server may have read the whole request: an answer that
                # is slow, cut short or never comes is not asked for again,
                # or the event (or a human verdict) is stored twice with
                # nothing to tell the copies apart (survey 25 Sep 2026, row 35).
                self.close()
                raise
            self._idle_since = time.monotonic()
            return int(resp.status), data
        raise RuntimeError("unreachable")  # pragma: no cover


# A kept connection idle longer than this is not used again. A NAT or
# firewall on the way may drop an idle flow after a few minutes without
# telling either end; a post sent on it is reset unread, and it is not sent
# again once it may have left, so it would be lost.
_CONNECTION_IDLE_LIMIT_SEC = 60.0


def _server_closed(conn: Any) -> bool:
    """Whether the server has closed (or written to) an idle kept-alive connection.

    Nothing is due on a connection between requests, so a readable one holds
    the server's close, or an answer to nothing: either way it cannot carry
    the next request, which would fail on it and not be sent again.
    """
    sock = getattr(conn, "sock", None)
    if sock is None:
        return False
    try:
        pending = getattr(sock, "pending", None)  # TLS bytes already decrypted
        if pending is not None and pending():
            return True
        if hasattr(select, "poll"):
            poller = select.poll()
            poller.register(sock, select.POLLIN)
            return bool(poller.poll(0))
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable)
    except (OSError, ValueError):
        return True


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
                _log_failure(f"{item.op} {item.label}", exc, item.base_source)
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
        _log_failure(f"{item.op} {item.label}", exc, item.base_source)
        return
    # A redirect is not followed, so its row did not reach the API either.
    if status >= 300:
        _log_http_status(item.op, item.label, status, body, item.base_source)


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


def _failure_kind(exc: BaseException) -> str:
    """The name of *exc*'s type; for a ``URLError`` that wraps an exception,
    that exception's type."""
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        return type(exc.reason).__name__
    return type(exc).__name__


#: Raised before anything is sent, by a base URL or an API key that no request
#: can carry, with a message that quotes the value.
_UNSENDABLE = (ValueError, http.client.InvalidURL)


def _describe_failure(exc: BaseException, source: str) -> str:
    """How a request that raised is described where its text must not go.

    The text can quote what a terminal, a log or an error message must not
    carry: a certificate issued for another name puts the host in it, and
    ``http.client`` quotes a header value it will not send, the API key among
    them. The description is the error's type (:func:`_failure_kind`) and
    *source*, where the base URL came from (``ResolvedCredentials.base_source``,
    a label); for an error the settings themselves raised (:data:`_UNSENDABLE`)
    it says that no request can be made with them. The text belongs at DEBUG.
    """
    if isinstance(exc, _UNSENDABLE):
        return f"no request can be made with the base URL (from {source}) and the API key that are set"
    return f"{_failure_kind(exc)} (base URL from {source})"


def _log_failure(what: str, exc: BaseException, source: str) -> None:
    """Log a cloud call that raised instead of answering.

    The WARNING line gives the exception's type (:func:`_failure_kind`) and
    *source*, where the base URL came from, never the exception's text (see
    :func:`_describe_failure`). The text is logged at DEBUG.

    *source* is the ``base_source`` of the credentials the call was made with,
    so logging a failure reads no settings, and cannot fail on them.
    """
    _log.warning("cloud: %s failed: %s (base URL from %s)", what, _failure_kind(exc), source)
    _log.debug("cloud: %s failed: %s", what, exc)


def _log_http_error(op: str, event_type: str, exc: urllib.error.HTTPError, source: str) -> None:
    body = b""
    try:
        body = exc.read()
    except Exception:
        _log.debug("cloud: %s %s HTTP %s body unreadable", op, event_type, exc.code, exc_info=True)
    _log_http_status(op, event_type, exc.code, body, source)


def _log_http_status(op: str, event_type: str, code: int, raw: bytes, source: str) -> None:
    """Log a cloud call the API answered with an HTTP error status.

    The WARNING line gives the status and, but for the CDN/WAF hint, *source*
    (as for :func:`_log_failure`), never the answer: a proxy's error page can
    name the host, and a page that echoes the request headers holds the API
    key. The answer is logged at DEBUG.
    """
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
    elif code == 401:
        _log.warning(
            "cloud: %s %s failed HTTP 401 — invalid or revoked API key "
            "(base URL from %s)",
            op,
            event_type,
            source,
        )
    else:
        _log.warning(
            "cloud: %s %s failed HTTP %s (base URL from %s)",
            op,
            event_type,
            code,
            source,
        )
    if body:
        _log.debug("cloud: %s %s HTTP %s response body: %r", op, event_type, code, body)


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
        prompt: Optional end-user prompt for this generation. Only its
            preview is sent, redacted as the audit trail's is (see
            :mod:`artzain.events`); it lets the prompt defender classify the
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
    _session_prompt: bool = True,
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
    creds = _resolve_or_warn()
    key = creds.api_key if creds else None
    if not creds or not key:
        _log.debug("cloud: skip event %r — no COGNEXUS_API_KEY / MYAPP_API_KEY", event_type)
        return

    if not _skip_session_hook:
        ensure_sdk_session_logged()

    pl = dict(payload or {})
    if _session_prompt and not pl.get("user_prompt"):
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
                url=creds.base_url + "/api/events",
                body=json.dumps(without_unpaired_surrogates(body_obj), ensure_ascii=False).encode("utf-8"),
                headers=headers,
                timeout_sec=float(timeout_sec),
                base_source=creds.base_source,
            )
        )
    except Exception as exc:
        _log_failure(f"event POST {event_type}", exc, creds.base_source)


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
    creds = _resolve_or_warn()
    key = creds.api_key if creds else None
    if not creds or not key:
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
                url=creds.base_url + "/api/policy-decisions",
                body=json.dumps(without_unpaired_surrogates(body_obj), ensure_ascii=False).encode("utf-8"),
                headers=headers,
                timeout_sec=float(timeout_sec),
                base_source=creds.base_source,
            )
        )
    except Exception as exc:
        _log_failure(f"policy decision POST {v}", exc, creds.base_source)


class _PolicyRulesFetchFailed(Exception):
    """``GET /api/policy-enforcement/rules`` did not end in a rule list.

    Its message says how, in a few words for a log line ("HTTP 503"). It never
    carries the URL or the key: a caller that needs to know who the fetch was
    for resolved the credentials itself.
    """


def _fetch_policy_rules(
    creds: Optional[ResolvedCredentials], *, timeout_sec: float = 12.0, quiet: bool = False
) -> list[Any]:
    """The tenant's rule rows, fetched with *creds* (``None``: the settings
    refused to send the key, which was warned of when they were resolved).

    ``[]`` is an answer: the tenant has no rules, or no key is configured, so
    there is no tenant to fetch for. Every other way the fetch can end without a
    rule list raises :class:`_PolicyRulesFetchFailed`: a key that may not go to
    the base URL that is set, a request that cannot be made or fails (an HTTP
    error, among them the 503 the platform answers while it cannot read the
    tenant's rules, or a timeout), a body that is not a rule list. Each failure
    is logged, at DEBUG rather than WARNING when *quiet*: a retry, whose run of
    failures the caller has already reported.
    """
    level = logging.DEBUG if quiet else logging.WARNING
    if creds is None:
        raise _PolicyRulesFetchFailed("the API key may not go to the base URL that is set")
    key = creds.api_key
    if not key:
        _log.debug("cloud: skip policy rules fetch — no API key")
        return []
    try:
        req = urllib.request.Request(
            creds.base_url + "/api/policy-enforcement/rules",
            method="GET",
            headers=_api_request_headers(key),
        )
        with _urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if quiet:
            _log.debug("cloud: policy rules GET policy-enforcement failed HTTP %s", exc.code)
        else:
            _log_http_error("policy rules GET", "policy-enforcement", exc, creds.base_source)
        raise _PolicyRulesFetchFailed(f"HTTP {exc.code}") from exc
    except _UNSENDABLE as exc:
        # Raised before anything is sent, by a base URL or an API key that no
        # request can carry, with a message that quotes it: the log names
        # where the base URL came from instead.
        _log.log(level, "cloud: policy rules fetch failed: %s", _describe_failure(exc, creds.base_source))
        raise _PolicyRulesFetchFailed("no request can be made with these settings") from exc
    except Exception as exc:
        if quiet:
            _log.debug("cloud: policy rules fetch failed: %s", exc)
        else:
            _log_failure("policy rules fetch", exc, creds.base_source)
        raise _PolicyRulesFetchFailed(type(exc).__name__) from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        # RecursionError: JSON nested deeper than the decoder follows.
        _log.log(level, "cloud: policy rules fetch failed: the answer is not JSON")
        raise _PolicyRulesFetchFailed("the answer is not JSON") from exc
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        _log.log(level, "cloud: policy rules fetch failed: the answer holds no rule list")
        raise _PolicyRulesFetchFailed("the answer holds no rule list")
    return list(rules)


def fetch_client_policy_rules(
    *,
    timeout_sec: float = 12.0,
) -> list[dict[str, Any]]:
    """Download tenant policy rules from ``GET /api/policy-enforcement/rules``.

    Requires ``COGNEXUS_API_KEY`` (or :func:`configure`). Returns an empty list
    when no key is configured or the request fails, so an empty list may also
    mean a failed request. :func:`~artzain.load_client_policy_rules` tells the
    two apart (it makes the same request itself rather than calling this): it
    does not cache a failed fetch, and keeps serving the rules it fetched last
    while a refresh fails.
    """
    try:
        return _fetch_policy_rules(_resolve_or_warn(), timeout_sec=timeout_sec)
    except _PolicyRulesFetchFailed:
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
