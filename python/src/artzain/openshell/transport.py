"""The sidecar's connection to the engine: one origin, kept warm.

Every call the sidecar makes goes to the engine it was configured with, and
a governed write waits on it inside the gateway's interceptor timeout. So
this client does three things the SDK's general one does not:

* **It is pinned to one origin.** The origin is ``ARTZAIN_DECISION_URL``'s. A
  request for any other scheme, host or port is refused before a socket is
  opened, and a redirect is an answer like any other status: nothing is
  followed.
* **Its proxy and its certificate authorities are settings, not ambience.**
  ``HTTPS_PROXY`` and its relatives are ignored unless
  ``OPENSHELL_SIDECAR_PROXY`` says ``env``. A proxy is an HTTP proxy asked to
  ``CONNECT`` to the engine, so the proxy carries the TLS session and does
  not see inside it. ``OPENSHELL_SIDECAR_CA_BUNDLE`` names the authorities
  to trust instead of the system's, for a network that inspects TLS or an
  engine with a private certificate. The certificate and its host name are
  always checked; there is no setting that turns that off.
* **It keeps connections.** A decision on a kept connection costs one round
  trip; on a new one it costs the TCP and TLS handshakes first. One
  connection is opened before the first request and renewed every 30 s
  (:meth:`EngineClient.warm`), so the first write after a quiet spell does
  not pay for the handshakes inside the gateway's timeout.

Settings (environment):

* ``OPENSHELL_SIDECAR_PROXY``: unset for a direct connection; ``env`` to use
  the environment's proxy for the engine's scheme (``NO_PROXY`` applies); or
  ``http://[user:password@]host[:port]``. Only an ``http`` proxy is
  supported. Credentials go to the proxy as ``Proxy-Authorization: Basic``
  and are never logged.
* ``OPENSHELL_SIDECAR_CA_BUNDLE``: a PEM file of the certificate authorities
  to trust for the engine.

A setting that cannot be honoured (:class:`SettingsError`) stops the
sidecar from starting, and denies a decision if it is met later: the
sidecar does not fall back to a direct connection or to the system's
authorities.
"""

from __future__ import annotations

import base64
import http.client
import logging
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from typing import Any, Callable, Deque, Dict, Mapping, NamedTuple, Optional, Tuple

logger = logging.getLogger("artzain.openshell.transport")

#: An engine answer is small; a larger body is refused.
MAX_ANSWER_BYTES = 256 * 1024
_READ_CHUNK = 16 * 1024
#: Connections kept for the next request.
MAX_IDLE = 4
#: A kept connection idle for longer than this is not used again: the
#: engine's load balancer closes one it has not heard from in 60 s.
IDLE_SECONDS = 50.0
#: :meth:`EngineClient.warm` renews a kept connection older than this, so
#: with a call every :data:`WARM_EVERY_SECONDS` there is always a young one.
RENEW_SECONDS = 25.0
WARM_EVERY_SECONDS = 30.0
#: How long opening the warm connection may take.
WARM_TIMEOUT_SECONDS = 5.0

_DEFAULT_PORTS = {"http": 80, "https": 443}


class SettingsError(ValueError):
    """A connection setting that cannot be honoured. The message names the
    setting and never repeats a credential."""


class Proxy(NamedTuple):
    host: str
    port: int
    #: The ``Proxy-Authorization`` value, or empty.
    authorization: str = ""

    def __repr__(self) -> str:  # the authorization stays out of logs and tracebacks
        return f"Proxy(host={self.host!r}, port={self.port!r})"


class Settings(NamedTuple):
    scheme: str
    host: str
    port: int
    proxy: Optional[Proxy] = None
    ca_bundle: str = ""

    @property
    def origin(self) -> Tuple[str, str, int]:
        return (self.scheme, self.host, self.port)


def _origin(url: str) -> Optional[Tuple[str, str, int]]:
    """``(scheme, host, port)`` of an ``http`` or ``https`` URL, or None."""
    try:
        parts = urllib.parse.urlsplit(url)  # lower-cases the scheme and the host
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    return (parts.scheme, parts.hostname, port or _DEFAULT_PORTS[parts.scheme])


def _proxy(raw: str, origin: Tuple[str, str, int]) -> Optional[Proxy]:
    """The proxy ``OPENSHELL_SIDECAR_PROXY`` asks for, or None for direct."""
    raw = raw.strip()
    if not raw:
        return None
    setting = "OPENSHELL_SIDECAR_PROXY"
    if raw.lower() == "env":
        scheme, host, _port = origin
        if urllib.request.proxy_bypass(host):
            return None
        raw = (urllib.request.getproxies().get(scheme) or "").strip()
        if not raw:
            return None
        if "://" not in raw:
            raw = "http://" + raw
        setting = f"the environment's {scheme} proxy"
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port
    except ValueError:
        raise SettingsError(f"{setting} is not a URL") from None
    if parts.scheme != "http":
        raise SettingsError(f"{setting} is not an http:// proxy; no other kind is supported")
    if not parts.hostname:
        raise SettingsError(f"{setting} names no host")
    authorization = ""
    if parts.username is not None:
        pair = "%s:%s" % (urllib.parse.unquote(parts.username),
                          urllib.parse.unquote(parts.password or ""))
        authorization = "Basic " + base64.b64encode(pair.encode("utf-8")).decode("ascii")
    return Proxy(parts.hostname, port or 80, authorization)


def settings_from_environment(environ: Optional[Mapping[str, str]] = None) -> Optional[Settings]:
    """The engine connection the environment describes.

    None when ``ARTZAIN_DECISION_URL`` is unset or is not an ``http`` or
    ``https`` URL with a host: there is no engine to call. Raises
    :class:`SettingsError` for a proxy or a certificate bundle that cannot
    be honoured.
    """
    environ = os.environ if environ is None else environ
    origin = _origin((environ.get("ARTZAIN_DECISION_URL") or "").strip())
    if origin is None:
        return None
    ca_bundle = (environ.get("OPENSHELL_SIDECAR_CA_BUNDLE") or "").strip()
    if ca_bundle and not os.path.isfile(ca_bundle):
        raise SettingsError("OPENSHELL_SIDECAR_CA_BUNDLE is not a file")
    proxy = _proxy(environ.get("OPENSHELL_SIDECAR_PROXY") or "", origin)
    return Settings(origin[0], origin[1], origin[2], proxy, ca_bundle)


def tls_context(ca_bundle: str = "") -> ssl.SSLContext:
    """A context that checks the engine's certificate and host name against
    *ca_bundle*, or against the system's authorities when it is empty."""
    try:
        if ca_bundle:
            return ssl.create_default_context(cafile=ca_bundle)
        return ssl.create_default_context()
    except (OSError, ssl.SSLError) as exc:
        raise SettingsError(
            "OPENSHELL_SIDECAR_CA_BUNDLE holds no certificate that can be read"
            if ca_bundle else "the system's certificate authorities cannot be loaded") from exc


def is_connection_reset(exc: BaseException) -> bool:
    """The other end closed the connection, with or without a reset, before
    it answered. A timeout is not one, and neither is a refused connection."""
    return isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError,
                            ssl.SSLEOFError, ssl.SSLZeroReturnError))


def _dropped(conn: http.client.HTTPConnection) -> bool:
    """Whether a kept connection can no longer be used.

    An idle connection has nothing to read. A read that would block means it
    is still open. Anything else (an end of stream, a reset, bytes nobody
    asked for) means it is not. The read is made through the TLS layer, so
    what TLS itself sends after the handshake is taken in and not mistaken
    for an answer.
    """
    sock = conn.sock
    if sock is None:
        return True
    try:
        sock.settimeout(0)
        sock.recv(1)
    except (BlockingIOError, ssl.SSLWantReadError, InterruptedError):
        return False
    except (OSError, ValueError):
        return True
    return True


class EngineClient:
    """Requests to one engine origin, over connections that are kept."""

    def __init__(self, settings: Settings, *, max_idle: int = MAX_IDLE,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.settings = settings
        self._context = tls_context(settings.ca_bundle) if settings.scheme == "https" else None
        self._max_idle = max_idle
        self._clock = clock
        self._lock = threading.Lock()
        #: ``(connection, when it was last used)``, the newest last.
        self._idle: Deque[Tuple[http.client.HTTPConnection, float]] = deque()
        self._closed = False

    # -- connections --------------------------------------------------------

    def _open(self, timeout: float) -> http.client.HTTPConnection:
        """A new connection to the engine, through the proxy when there is
        one, with the TLS handshake done."""
        scheme, host, port = self.settings.origin
        proxy = self.settings.proxy
        at_host, at_port = (proxy.host, proxy.port) if proxy else (host, port)
        conn: http.client.HTTPConnection
        if scheme == "https":
            conn = http.client.HTTPSConnection(at_host, at_port, timeout=timeout,
                                               context=self._context)
        else:
            conn = http.client.HTTPConnection(at_host, at_port, timeout=timeout)
        if proxy:
            headers = {"Proxy-Authorization": proxy.authorization} if proxy.authorization else {}
            conn.set_tunnel(host, port, headers=headers)
        try:
            conn.connect()
        except BaseException:
            conn.close()
            raise
        return conn

    def _take(self) -> Optional[http.client.HTTPConnection]:
        """The most recently used kept connection that is still usable."""
        while True:
            with self._lock:
                if not self._idle:
                    return None
                conn, since = self._idle.pop()
            if self._clock() - since <= IDLE_SECONDS and not _dropped(conn):
                return conn
            conn.close()

    def _keep(self, conn: http.client.HTTPConnection) -> None:
        """Keep *conn* for the next request, and close what no longer fits."""
        surplus = []
        with self._lock:
            if self._closed:
                surplus.append(conn)
            else:
                self._idle.append((conn, self._clock()))
                while len(self._idle) > self._max_idle:
                    surplus.append(self._idle.popleft()[0])
        for old in surplus:
            old.close()

    @property
    def idle(self) -> int:
        """How many connections are kept for the next request."""
        with self._lock:
            return len(self._idle)

    def warm(self, timeout: float = WARM_TIMEOUT_SECONDS) -> bool:
        """Make sure a young connection is waiting. True when one is.

        Kept connections older than :data:`RENEW_SECONDS` are closed, and if
        none is left a new one is opened. Never raises: an engine that
        cannot be reached now is reached, or not, by the next request.
        """
        now = self._clock()
        with self._lock:
            old = [pair for pair in self._idle if now - pair[1] > RENEW_SECONDS]
            for pair in old:
                self._idle.remove(pair)
            waiting = len(self._idle)
        for conn, _since in old:
            conn.close()
        if waiting:
            return True
        try:
            conn = self._open(timeout)
        except Exception as exc:  # noqa: BLE001 - see the docstring
            logger.info("engine connection not opened ahead of time: %s", type(exc).__name__)
            return False
        self._keep(conn)
        return True

    def close(self) -> None:
        with self._lock:
            self._closed = True
            idle, self._idle = list(self._idle), deque()
        for conn, _since in idle:
            conn.close()

    # -- requests -----------------------------------------------------------

    def path_of(self, target: str) -> str:
        """The path and query of *target*, which must be on the engine's
        origin. Raises ``ValueError`` when it is not."""
        if _origin(target) != self.settings.origin:
            raise ValueError("not the engine's origin")
        parts = urllib.parse.urlsplit(target)
        return (parts.path or "/") + ("?" + parts.query if parts.query else "")

    def request(self, method: str, target: str, *, headers: Mapping[str, str],
                body: Optional[bytes] = None, deadline: float,
                retry_on_reset: bool = False) -> Tuple[int, Any, bytes]:
        """``(status, headers, body)`` of one request, answered before
        *deadline* (a ``time.monotonic()`` value).

        * *target* must be on the engine's origin.
        * Any status is an answer; nothing is followed.
        * A body larger than :data:`MAX_ANSWER_BYTES` is refused
          (``ValueError``) when the status is 2xx. For any other status the
          body is a detail: one that is too large or too slow comes back
          empty, and the status stands.
        * With *retry_on_reset*, a connection the engine closed without
          answering is tried once more, on a new connection, in the time
          that is left. Nothing else is tried twice.
        """
        path = self.path_of(target)
        attempts = 2 if retry_on_reset else 1
        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            conn = self._take() if attempt == 0 else None
            try:
                if conn is None:
                    conn = self._open(remaining)
                conn.sock.settimeout(max(deadline - time.monotonic(), 0.001))
                conn.request(method, path, body=body, headers=dict(headers))
                answer = conn.getresponse()
                data = self._read(conn, answer, deadline)
            except BaseException as exc:
                if conn is not None:
                    conn.close()
                if attempt + 1 < attempts and is_connection_reset(exc):
                    logger.info("engine connection reset; retrying once")
                    continue
                raise
            if data is None or answer.will_close:
                conn.close()
            else:
                self._keep(conn)
            return answer.status, answer.headers, data or b""
        raise TimeoutError("sidecar engine deadline passed")

    @staticmethod
    def _read(conn: http.client.HTTPConnection, answer: http.client.HTTPResponse,
              deadline: float) -> Optional[bytes]:
        """The answer's body. None for a body that was not read to its end
        (the connection cannot be kept), which only an answer that is not
        2xx may have."""
        ok = 200 <= answer.status < 300
        chunks, size = [], 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sidecar engine deadline passed")
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                # One read of the socket at most: ``read`` would wait for the
                # whole chunk, and a body that trickles in would hold it past
                # the deadline.
                chunk = answer.read1(_READ_CHUNK)
                if not chunk:
                    # Python 3.10's ``read1`` leaves a body it has read to
                    # the end open, and the connection then refuses the next
                    # answer (``ResponseNotReady``). Closing the answer is
                    # what ``read`` does at the end of a body; the socket
                    # stays with the connection, which is still kept.
                    answer.close()
                    return b"".join(chunks)
                size += len(chunk)
                if size > MAX_ANSWER_BYTES:
                    raise ValueError("engine answer too large")
                chunks.append(chunk)
        except Exception:
            if ok:
                raise
            return None


def describe(settings: Optional[Settings]) -> Dict[str, Any]:
    """What a log line may say about the connection: no credential."""
    if settings is None:
        return {"engine": None}
    return {"engine": "%s://%s:%d" % settings.origin,
            "proxy": ("%s:%d" % (settings.proxy.host, settings.proxy.port)
                      if settings.proxy else None),
            "ca_bundle": bool(settings.ca_bundle)}


__all__ = ["EngineClient", "Proxy", "Settings", "SettingsError", "describe",
           "is_connection_reset", "settings_from_environment", "tls_context",
           "MAX_ANSWER_BYTES", "WARM_EVERY_SECONDS"]
