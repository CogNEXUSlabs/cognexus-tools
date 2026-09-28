"""A failed cloud call is reported without what came back with it.

The API's answer to a failed call can hold what a log line must not: a proxy's
error page can name the host, and a page that echoes the request headers holds
the API key. So can an exception's text: a certificate issued for another name
puts the host in it, and ``http.client`` quotes a header value it will not
send, the key among them. The WARNING line names the call, the HTTP status or
the exception's type, and where the base URL came from; the answer and the
exception's text are logged at DEBUG only.
"""

from __future__ import annotations

import http.client
import io
import logging
import ssl
import urllib.error
from typing import Any, Callable

import pytest

import artzain.cloud as cloud
from artzain import credentials

KEY = "cnx_failure_logs_test_0123456789abcdef"
HOST = "tenant-host.example.test"
BASE = "https://" + HOST
SOURCE = "base URL from configure(base_url=...)"
ENV_SOURCE = "base URL from COGNEXUS_API_BASE_URL"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key and a host set with ``configure()`` only, and no proxy."""
    for name in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(credentials, "profile_api_key", lambda: None)
    monkeypatch.setattr(credentials, "profile_base_url", lambda: None)
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    # No sdk_session row ahead of each event, and a fixed User-Agent.
    monkeypatch.setattr(cloud, "_session_logged", True)
    monkeypatch.setattr(cloud, "_package_version", lambda: "test")
    cloud.configure(api_key=KEY, base_url=BASE)


def _post_event() -> None:
    cloud.post_sdk_event("generation", payload={"n": 1})


def _post_decision() -> None:
    cloud.post_policy_human_decision("approved", request_id="req-1")


def _get_rules() -> None:
    assert cloud.fetch_client_policy_rules() == []


#: Each call, and how its line names it when the API answered with an error.
ANSWERED = [
    pytest.param(_post_event, "event POST generation", id="event-post"),
    pytest.param(_post_decision, "policy decision POST approved", id="decision-post"),
    pytest.param(_get_rules, "policy rules GET policy-enforcement", id="rules-get"),
]
#: Each call, and how its line names it when the request raised.
RAISED = [
    pytest.param(_post_event, "event POST generation", id="event-post"),
    pytest.param(_post_decision, "policy decision POST approved", id="decision-post"),
    pytest.param(_get_rules, "policy rules fetch", id="rules-get"),
]


def _above_debug(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno > logging.DEBUG]


def _debug(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]


def _settings_become_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    """From now on the credentials cannot be resolved, as when the profile is
    re-saved in another encoding while a call is in flight."""

    def _unreadable(**kwargs: Any) -> Any:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(cloud, "resolve_credentials", _unreadable)


def _base_url_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The host comes from ``COGNEXUS_API_BASE_URL``, so a line that names
    ``configure(base_url=...)`` names the wrong setting."""
    cloud.configure(api_key=KEY, base_url=None)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", BASE)


def _assert_the_sender_is_alive(worker: Any) -> None:
    """``flush()`` returns once a row is done with, which is before a thread
    that raised afterwards has ended: give it the time to end."""
    thread = worker._thread
    assert thread is not None
    thread.join(timeout=0.5)
    assert thread.is_alive(), "the sender thread stopped"


# ---------------------------------------------------------------------------
# An answer with an HTTP error status
# ---------------------------------------------------------------------------

#: Builds an answer's body from the host and the headers the request was sent with.
Page = Callable[[str, dict[str, str]], bytes]


def _echoing_the_request(host: str, headers: dict[str, str]) -> bytes:
    """An error page that lists the request's headers back, as some proxies do."""
    lines = [f"Host: {host}", *(f"{name}: {value}" for name, value in headers.items())]
    return ("<html><h1>Request headers</h1><pre>" + "\n".join(lines) + "</pre></html>").encode()


def _naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    """A proxy's error page naming the upstream it could not reach."""
    return f"<html><h1>Upstream error</h1><p>{host} did not answer.</p></html>".encode()


def _cdn_code_naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    """A CDN block page that gives its error code and the site, not its name."""
    return f"<html><title>Access denied | {host}</title><p>error code: 1010</p></html>".encode()


def _cdn_name_naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    """A CDN block page that gives its name and the site, not its error code."""
    return (
        f"<html><title>Access denied | {host} used Cloudflare to restrict access</title></html>"
    ).encode()


def _serve(monkeypatch: pytest.MonkeyPatch, status: int, page: Page) -> None:
    """Answer every request, the POSTs and the GET, with *status* and *page*."""

    class _Response:
        def __init__(self, body: bytes) -> None:
            self.status = status
            self._body = body

        def read(self) -> bytes:
            return self._body

    class _Connection:
        def __init__(self, host: str, port: Any = None, **kw: Any) -> None:
            self.host = host
            self._body = b""

        def request(self, method: str, path: str, body: Any = None, headers: Any = None) -> None:
            self._body = page(self.host, dict(headers or {}))

        def getresponse(self) -> _Response:
            return _Response(self._body)

        def close(self) -> None:
            pass

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        body = page(req.host, dict(req.header_items()))
        raise urllib.error.HTTPError(req.full_url, status, "error", {}, io.BytesIO(body))  # type: ignore[arg-type]

    monkeypatch.setattr(cloud.http.client, "HTTPSConnection", _Connection)
    monkeypatch.setattr(cloud.urllib.request, "urlopen", _urlopen)


CDN_HINT = (
    "cloud: {call} failed HTTP 403 (CDN/WAF — use a current artzain package "
    "or allow User-Agent 'artzain-python-sdk/test' on /api/events)"
)

PAGES = [
    pytest.param(
        400,
        _echoing_the_request,
        "Request headers",
        "cloud: {call} failed HTTP 400 (" + SOURCE + ")",
        id="400-echoing-the-headers",
    ),
    pytest.param(
        502,
        _naming_the_host,
        "Upstream error",
        "cloud: {call} failed HTTP 502 (" + SOURCE + ")",
        id="502-naming-the-host",
    ),
    pytest.param(
        403,
        _naming_the_host,
        "Upstream error",
        "cloud: {call} failed HTTP 403 (" + SOURCE + ")",
        id="403-naming-the-host",
    ),
    pytest.param(
        401,
        _echoing_the_request,
        "Request headers",
        "cloud: {call} failed HTTP 401 — invalid or revoked API key (" + SOURCE + ")",
        id="401-echoing-the-headers",
    ),
    pytest.param(403, _cdn_code_naming_the_host, "error code: 1010", CDN_HINT, id="403-cdn-code"),
    pytest.param(403, _cdn_name_naming_the_host, "used Cloudflare", CDN_HINT, id="403-cdn-name"),
]


@pytest.mark.parametrize(("status", "page", "marker", "expected"), PAGES)
@pytest.mark.parametrize(("send", "call"), ANSWERED)
def test_an_error_page_never_reaches_a_warning_line(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
    status: int,
    page: Page,
    marker: str,
    expected: str,
) -> None:
    """The WARNING line is the call, the status and where the base URL came
    from; the 401 and CDN/WAF hints stay. The page is logged at DEBUG, on one
    line whatever line breaks it holds."""
    _serve(monkeypatch, status, page)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    lines = _above_debug(caplog)
    assert not [m for m in lines if KEY in m or HOST in m], lines
    assert lines == [expected.format(call=call)]
    logged = [m for m in _debug(caplog) if marker in m]
    assert logged, "the page is not logged at DEBUG"
    assert not [m for m in logged if "\n" in m], logged


@pytest.mark.parametrize(("send", "call"), ANSWERED)
def test_the_label_names_where_the_base_url_came_from(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
) -> None:
    _base_url_from_the_environment(monkeypatch)
    _serve(monkeypatch, 502, _naming_the_host)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    assert _above_debug(caplog) == [f"cloud: {call} failed HTTP 502 ({ENV_SOURCE})"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        pytest.param(502, "cloud: {call} failed HTTP 502 (" + SOURCE + ")", id="502"),
        pytest.param(
            401,
            "cloud: {call} failed HTTP 401 — invalid or revoked API key (" + SOURCE + ")",
            id="401",
        ),
    ],
)
@pytest.mark.parametrize(("send", "call"), ANSWERED)
def test_an_answer_is_logged_when_the_settings_can_no_longer_be_read(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
    status: int,
    expected: str,
) -> None:
    """The line gives the label the call's credentials were resolved with, so
    logging the failure reads no settings, and the call still never raises."""

    def _page(host: str, headers: dict[str, str]) -> bytes:
        _settings_become_unreadable(monkeypatch)
        return _naming_the_host(host, headers)

    _serve(monkeypatch, status, _page)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    assert _above_debug(caplog) == [expected.format(call=call)]


# ---------------------------------------------------------------------------
# A request that raised
# ---------------------------------------------------------------------------


def _certificate_for_another_name(host: str) -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError(
        1,
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, "
        f"certificate is not valid for '{host}'. (_ssl.c:1032)",
    )


def _fail(monkeypatch: pytest.MonkeyPatch, error: Callable[[str], OSError]) -> None:
    """Make every request, the POSTs and the GET, raise ``error(host)``; the
    GET's comes wrapped in a ``URLError``, as ``urlopen`` wraps it."""

    class _Connection:
        def __init__(self, host: str, port: Any = None, **kw: Any) -> None:
            self.host = host

        def request(self, method: str, path: str, body: Any = None, headers: Any = None) -> None:
            raise error(self.host)

        def getresponse(self) -> Any:
            raise AssertionError("the request raised")

        def close(self) -> None:
            pass

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        raise urllib.error.URLError(error(req.host))

    monkeypatch.setattr(cloud.http.client, "HTTPSConnection", _Connection)
    monkeypatch.setattr(cloud.urllib.request, "urlopen", _urlopen)


@pytest.mark.parametrize(("send", "call"), RAISED)
def test_a_certificate_for_another_name_is_not_named_in_a_warning_line(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
) -> None:
    """The WARNING line gives the error's type, the one a ``URLError`` wraps
    for the GET; its text, which names the host, is logged at DEBUG."""
    _fail(monkeypatch, _certificate_for_another_name)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    lines = _above_debug(caplog)
    assert lines == [f"cloud: {call} failed: SSLCertVerificationError ({SOURCE})"]
    assert [m for m in _debug(caplog) if "certificate verify failed" in m]


@pytest.mark.parametrize(("send", "call"), RAISED)
def test_the_label_names_where_the_base_url_came_from_for_a_raised_error(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
) -> None:
    _base_url_from_the_environment(monkeypatch)
    _fail(monkeypatch, _certificate_for_another_name)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    assert _above_debug(caplog) == [f"cloud: {call} failed: SSLCertVerificationError ({ENV_SOURCE})"]


@pytest.mark.parametrize(("send", "call"), RAISED)
def test_an_error_is_logged_when_the_settings_can_no_longer_be_read(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_sync_cloud_threads: None,
    send: Callable[[], None],
    call: str,
) -> None:
    def _error(host: str) -> ssl.SSLCertVerificationError:
        _settings_become_unreadable(monkeypatch)
        return _certificate_for_another_name(host)

    _fail(monkeypatch, _error)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    assert _above_debug(caplog) == [f"cloud: {call} failed: SSLCertVerificationError ({SOURCE})"]


def test_a_url_error_whose_reason_names_the_host_is_logged_by_its_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A ``URLError`` can carry its reason as text rather than as an error."""

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        raise urllib.error.URLError(f"Tunnel connection to {req.host} failed")

    monkeypatch.setattr(cloud.urllib.request, "urlopen", _urlopen)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        _get_rules()

    assert _above_debug(caplog) == [f"cloud: policy rules fetch failed: URLError ({SOURCE})"]
    assert [m for m in _debug(caplog) if HOST in m], "the reason is not logged at DEBUG"


def test_a_host_no_request_can_be_made_with_is_named_by_its_setting(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``http.client`` quotes a host it refuses. The fetch's own line for it
    names the setting, taken from the credentials the fetch was made with."""
    _base_url_from_the_environment(monkeypatch)

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        _settings_become_unreadable(monkeypatch)
        raise http.client.InvalidURL(f"URL can't contain control characters. {req.host!r}")

    monkeypatch.setattr(cloud.urllib.request, "urlopen", _urlopen)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        _get_rules()

    assert _above_debug(caplog) == [
        "cloud: policy rules fetch failed: no request can be made with the base URL "
        "(from COGNEXUS_API_BASE_URL) and the API key that are set"
    ]


def test_a_key_no_request_can_carry_is_not_quoted_in_a_warning_line(
    caplog: pytest.LogCaptureFixture, artzain_sync_cloud_threads: None
) -> None:
    """``http.client`` refuses a header value with a line break in it, before
    anything is sent, and its error quotes the value: here the API key, pasted
    with one. The requests go through the real ``http.client``; no connection
    is made."""
    head, tail = "cnx_failure_logs_head_0123456789", "tail_abcdefghijklmnopqrstuvwxyz"
    cloud.configure(api_key=head + "\n" + tail, base_url=BASE)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        _post_event()
        _post_decision()
        _get_rules()

    lines = _above_debug(caplog)
    assert not [m for m in lines if head in m or tail in m], lines
    assert lines == [
        f"cloud: event POST generation failed: ValueError ({SOURCE})",
        f"cloud: policy decision POST approved failed: ValueError ({SOURCE})",
        "cloud: policy rules fetch failed: no request can be made with the base URL "
        "(from configure(base_url=...)) and the API key that are set",
    ]


# ---------------------------------------------------------------------------
# Every other way a call can fail
# ---------------------------------------------------------------------------


def _breaking(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Any]:
    """A stand-in that makes the settings unreadable, then raises an error
    whose text names the host and holds the key."""

    def _break(*args: Any, **kwargs: Any) -> Any:
        _settings_become_unreadable(monkeypatch)
        raise RuntimeError(f"failed for {HOST} with {KEY}")

    return _break


@pytest.mark.parametrize(
    ("send", "call"),
    [
        pytest.param(_post_event, "event POST generation", id="event-post"),
        pytest.param(_post_decision, "policy decision POST approved", id="decision-post"),
    ],
)
def test_a_call_that_cannot_be_queued_is_logged_without_the_error_text(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    send: Callable[[], None],
    call: str,
) -> None:
    _base_url_from_the_environment(monkeypatch)
    monkeypatch.setattr(cloud, "_enqueue_post", _breaking(monkeypatch))
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        send()

    assert _above_debug(caplog) == [f"cloud: {call} failed: RuntimeError ({ENV_SOURCE})"]
    assert [m for m in _debug(caplog) if HOST in m], "the error text is not logged at DEBUG"


def test_the_sender_thread_logs_a_failed_delivery_without_the_error_text(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_fresh_cloud_worker: Any,
) -> None:
    """The catch-all around each delivery, which ``_deliver_post`` never lets
    an exception reach in practice. It logs the row's own label."""
    _base_url_from_the_environment(monkeypatch)
    monkeypatch.setattr(cloud, "_deliver_post", _breaking(monkeypatch))
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        _post_event()
        assert artzain_fresh_cloud_worker.flush(timeout_sec=5.0)

    assert _above_debug(caplog) == [
        f"cloud: event POST generation failed: RuntimeError ({ENV_SOURCE})"
    ]
    _assert_the_sender_is_alive(artzain_fresh_cloud_worker)


def test_the_sender_thread_survives_settings_that_can_no_longer_be_read(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    artzain_fresh_cloud_worker: Any,
) -> None:
    """Logging a failed delivery reads no settings, so it cannot raise out of
    the sender thread and stop it."""

    def _error(host: str) -> ssl.SSLCertVerificationError:
        _settings_become_unreadable(monkeypatch)
        return _certificate_for_another_name(host)

    _fail(monkeypatch, _error)
    with caplog.at_level(logging.DEBUG, logger="artzain.cloud"):
        _post_event()
        assert artzain_fresh_cloud_worker.flush(timeout_sec=5.0)

    assert _above_debug(caplog) == [
        f"cloud: event POST generation failed: SSLCertVerificationError ({SOURCE})"
    ]
    _assert_the_sender_is_alive(artzain_fresh_cloud_worker)
