"""A failed request is reported without its error's text.

``artzain quickstart`` prints why the API key could not be verified, and
``decide()`` raises why the Decision API could not be reached; a CLI command
prints what its request was answered with. None of that may carry the error's
text, or a page the API did not write: a certificate issued for another name
puts the host in the text, ``http.client`` quotes a header value it will not
send, the API key among them, and a proxy's error page can name the host or
echo the request headers back. What is reported is the error's type and where
the base URL came from, or that no request can be made with the base URL and
the API key that are set; the text and the page are logged at DEBUG. The calls
that log a failure instead of reporting it are covered by
:mod:`tests.test_cloud_failure_logs`.
"""

from __future__ import annotations

import argparse
import io
import logging
import ssl
import traceback
import urllib.error
from pathlib import Path
from typing import Any, Callable, NamedTuple

import pytest

import artzain.cli as cli
import artzain.cloud as cloud
from artzain.decide import DecisionError, decide

KEY = "cnx_failed_request_text_0123456789abcdef"
HOST = "tenant-host.example.test"
BASE = "https://" + HOST
SOURCE = "configure(base_url=...)"
ENV_SOURCE = "COGNEXUS_API_BASE_URL"
#: How settings no request can be made with are reported (the wording of the
#: policy rules fetch's line, :mod:`tests.test_cloud_failure_logs`).
UNSENDABLE = "no request can be made with the base URL (from {source}) and the API key that are set"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A key and a host set with ``configure()`` only, and no proxy. The SDK
    keeps the opener it builds, so one built before this test is not used."""
    for name in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    monkeypatch.setattr(cloud, "_api_opener_built", None)
    monkeypatch.setattr(cloud, "_session_logged", True)
    cloud.configure(api_key=KEY, base_url=BASE)


def _debug(caplog: pytest.LogCaptureFixture, logger: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == logger and r.levelno == logging.DEBUG]


def _above_debug(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno > logging.DEBUG]


# ---------------------------------------------------------------------------
# The surfaces that report a failed request
# ---------------------------------------------------------------------------


class Surface(NamedTuple):
    #: Makes the call and returns what it reported: the ``error`` value, the
    #: quickstart line, or the ``DecisionError`` message.
    report: Callable[[], str]
    #: How the report reads a description of the failure.
    frame: Callable[[str], str]
    #: The logger the error's text goes to, at DEBUG.
    logger: str


def _identity() -> str:
    info = cloud.fetch_api_key_identity()
    assert info["valid"] is False
    return str(info["error"])


def _probe() -> str:
    info = cloud._probe_api_key_via_events()
    assert info["valid"] is False
    return str(info["error"])


def _quickstart_output() -> str:
    buf = io.StringIO()
    assert cloud.announce_cloud_ingest(file=buf) is False
    return buf.getvalue()


def _announce() -> str:
    """The quickstart's ``Event Logs:`` line, the one that reports the failure."""
    text = _quickstart_output()
    lines = [line for line in text.splitlines() if "Event Logs:" in line]
    assert len(lines) == 1, text
    return lines[0]


def _decide() -> DecisionError:
    with pytest.raises(DecisionError) as info:
        decide(action="send_email", target="crm:1", payload="hi", kind="user_input")
    return info.value


def _decision() -> str:
    error = _decide()
    assert error.status is None
    return str(error)


def _unreachable(description: str) -> str:
    if description.startswith("no request can be made"):
        return "decision request not sent: " + description
    return "decision API unreachable: " + description


SURFACES = [
    pytest.param(Surface(_identity, lambda d: d, "artzain.cloud"), id="api-key-check"),
    pytest.param(Surface(_probe, lambda d: d, "artzain.cloud"), id="api-key-probe"),
    pytest.param(
        Surface(
            _announce,
            lambda d: f"  Event Logs:     could not verify key ({d}). Events may not be recorded.",
            "artzain.cloud",
        ),
        id="quickstart",
    ),
    pytest.param(Surface(_decision, _unreachable, "artzain.decide"), id="decide"),
]


# ---------------------------------------------------------------------------
# How a request fails
# ---------------------------------------------------------------------------


def _certificate_for_another_name(host: str) -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError(
        1,
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, "
        f"certificate is not valid for '{host}'. (_ssl.c:1032)",
    )


def _fail(monkeypatch: pytest.MonkeyPatch, error: Callable[[str], BaseException]) -> None:
    """Make every request raise ``error(host)`` wrapped in a ``URLError``, as
    ``urlopen`` wraps a socket or TLS error."""

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        raise urllib.error.URLError(error(req.host))

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)


def _settings_become_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    """From now on the credentials cannot be resolved, as when the profile is
    re-saved in another encoding while a call is in flight."""

    def _unreadable(**kwargs: Any) -> Any:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(cloud, "resolve_credentials", _unreadable)


def _base_url_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    cloud.configure(api_key=KEY, base_url=None)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", BASE)


@pytest.mark.parametrize("surface", SURFACES)
def test_a_certificate_for_another_name_is_reported_by_its_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, surface: Surface
) -> None:
    """The report gives the error's type, the one the ``URLError`` wraps, and
    where the base URL came from; the text, which names the host, goes to the
    log at DEBUG and nowhere above it."""
    _fail(monkeypatch, _certificate_for_another_name)
    with caplog.at_level(logging.DEBUG):
        report = surface.report()

    assert report == surface.frame(f"SSLCertVerificationError (base URL from {SOURCE})")
    assert [m for m in _debug(caplog, surface.logger) if "certificate verify failed" in m]
    assert not [m for m in _above_debug(caplog) if HOST in m]


@pytest.mark.parametrize("surface", SURFACES)
def test_a_url_error_whose_reason_is_text_is_reported_by_its_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, surface: Surface
) -> None:
    """A ``URLError`` can carry its reason as text rather than as an error."""

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        raise urllib.error.URLError(f"Tunnel connection to {req.host} failed")

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)
    with caplog.at_level(logging.DEBUG):
        report = surface.report()

    assert report == surface.frame(f"URLError (base URL from {SOURCE})")
    assert [m for m in _debug(caplog, surface.logger) if HOST in m], "the reason is not logged at DEBUG"


@pytest.mark.parametrize("surface", SURFACES)
def test_the_report_names_where_the_base_url_came_from(
    monkeypatch: pytest.MonkeyPatch, surface: Surface
) -> None:
    _base_url_from_the_environment(monkeypatch)
    _fail(monkeypatch, _certificate_for_another_name)

    assert surface.report() == surface.frame(f"SSLCertVerificationError (base URL from {ENV_SOURCE})")


@pytest.mark.parametrize("surface", SURFACES)
def test_the_report_reads_no_settings(monkeypatch: pytest.MonkeyPatch, surface: Surface) -> None:
    """The label is the one the call's credentials were resolved with, so a
    profile that becomes unreadable while the request is in flight changes
    nothing, and the report is still made."""
    _base_url_from_the_environment(monkeypatch)

    def _error(host: str) -> ssl.SSLCertVerificationError:
        _settings_become_unreadable(monkeypatch)
        return _certificate_for_another_name(host)

    _fail(monkeypatch, _error)

    assert surface.report() == surface.frame(f"SSLCertVerificationError (base URL from {ENV_SOURCE})")


#: Settings no request can be made with, and what ``http.client`` quotes for
#: them: a key pasted with a line break. The requests go through the real
#: transport, with no proxy; none is sent, since each fails before a connection
#: is made. A base URL no request can carry is refused before this, where the
#: credentials are resolved (``credentials._usable_base``).
HEAD, TAIL = "cnx_failed_request_head_0123456789", "tail_abcdefghijklmnopqrstuvwxyz"
SPACED_HOST = "tenant host.example.test"
UNSENDABLE_SETTINGS = [
    pytest.param(dict(api_key=HEAD + "\n" + TAIL, base_url=BASE), (HEAD, TAIL), id="key"),
]


@pytest.mark.parametrize(("settings", "quoted"), UNSENDABLE_SETTINGS)
@pytest.mark.parametrize("surface", SURFACES)
def test_settings_no_request_can_be_made_with_are_not_quoted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    surface: Surface,
    settings: dict[str, str],
    quoted: tuple[str, ...],
) -> None:
    """``http.client`` refuses a header value with a line break in it before
    anything is sent, with an error that quotes the value: here the API key.
    The report names the settings; the error's text is logged at DEBUG."""
    cloud.configure(**settings)
    with caplog.at_level(logging.DEBUG):
        report = surface.report()

    assert not [part for part in quoted if part in report], report
    assert report == surface.frame(UNSENDABLE.format(source=SOURCE))
    assert [m for m in _debug(caplog, surface.logger) if all(part in m for part in quoted)]
    assert not [m for m in _above_debug(caplog) if any(part in m for part in quoted)]


def test_the_quickstart_never_prints_the_key() -> None:
    """The whole of the quickstart's cloud-ingest output, not only its
    ``Event Logs:`` line, for the key ``http.client`` quotes."""
    cloud.configure(api_key=HEAD + "\n" + TAIL, base_url=BASE)
    text = _quickstart_output()

    assert HEAD not in text and TAIL not in text, text
    assert f"  Dashboard API:  {BASE}" in text
    assert "  API key:        invalid or unreachable (cnx_failed_req…)" in text


def test_the_fallback_probe_reports_its_own_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """On a dashboard without ``GET /api/api-keys/me``, the key is probed with
    a POST; the probe's failure is reported the same way."""

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        if req.get_method() == "GET":
            raise urllib.error.HTTPError(req.full_url, 405, "Method Not Allowed", {}, None)
        raise urllib.error.URLError(_certificate_for_another_name(req.host))

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)

    assert _identity() == f"SSLCertVerificationError (base URL from {SOURCE})"


# ---------------------------------------------------------------------------
# An answer
# ---------------------------------------------------------------------------


def _serve(monkeypatch: pytest.MonkeyPatch, status: int, page: Callable[..., bytes]) -> None:
    """Answer every request with the error *status* and ``page(host, headers)``."""

    def _urlopen(req: Any, timeout: Any = None) -> Any:
        body = page(req.host, dict(req.header_items()))
        raise urllib.error.HTTPError(req.full_url, status, "error", {}, io.BytesIO(body))  # type: ignore[arg-type]

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)


def _answer(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    """Answer every request with 200 and *body*."""

    class _Response:
        status = 200

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

        def read(self) -> bytes:
            return body

    monkeypatch.setattr(cloud, "_urlopen", lambda *a, **k: _Response())


#: 200 answers that are not JSON, as a captive portal or a maintenance page
#: answers.
NOT_JSON = [
    pytest.param(b"<html>maintenance</html>", id="html"),
    pytest.param(b"\xff", id="not-utf-8"),
]


# ---------------------------------------------------------------------------
# What decide() raises
# ---------------------------------------------------------------------------


def _json_detail(host: str, headers: dict[str, str]) -> bytes:
    return b'{"detail": "audit_unavailable"}'


#: Each way a decision request can fail. The error each one raises quotes the
#: key, the host or the page.
DECISION_FAILURES = [
    pytest.param(lambda mp: cloud.configure(api_key=HEAD + "\n" + TAIL, base_url=BASE), id="not-sent"),
    pytest.param(lambda mp: _fail(mp, _certificate_for_another_name), id="unreachable"),
    pytest.param(lambda mp: _serve(mp, 503, _json_detail), id="http-error"),
    pytest.param(lambda mp: _answer(mp, b"<html>maintenance</html>"), id="not-json"),
]


@pytest.mark.parametrize("failure", DECISION_FAILURES)
def test_a_decision_error_is_raised_without_the_error_it_stands_for(
    monkeypatch: pytest.MonkeyPatch, failure: Callable[[pytest.MonkeyPatch], None]
) -> None:
    """A caller that logs the error with ``logger.exception`` renders the
    exception chain, and what reads an error's cause or context reaches the
    error it stands for, text included: it is neither."""
    failure(monkeypatch)
    error = _decide()

    assert (error.__cause__, error.__context__) == (None, None)
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    for part in (HEAD, TAIL, HOST, "certificate verify failed", "maintenance"):
        assert part not in rendered, rendered


def test_an_http_error_is_still_reported_with_its_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """``DecisionError.status`` and the API's ``detail`` are what a caller has
    of an HTTP error; the error is not chained to it any longer."""
    _serve(monkeypatch, 503, _json_detail)
    error = _decide()

    assert error.status == 503
    assert str(error) == "decision API returned HTTP 503: audit_unavailable"


@pytest.mark.parametrize("body", NOT_JSON)
def test_an_answer_that_is_not_json_is_a_decision_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, body: bytes
) -> None:
    """A 200 answer that is not JSON is reported as such, not as the API
    being unreachable, and its parse error is not a reason to say no request
    could be made. The start of the answer is logged at DEBUG."""
    _answer(monkeypatch, body)
    with caplog.at_level(logging.DEBUG):
        assert _decision() == "decision API answered with a body that is not JSON"

    excerpt = repr(body.decode("utf-8", errors="replace"))
    assert [m for m in _debug(caplog, "artzain.decide") if excerpt in m], "the answer is not logged at DEBUG"


@pytest.mark.parametrize("body", NOT_JSON)
def test_an_answer_that_is_not_json_is_an_unexpected_response(
    monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    _answer(monkeypatch, body)
    info = cloud.fetch_api_key_identity()

    assert info["valid"] is False
    assert info["error"] == "unexpected_response"


# ---------------------------------------------------------------------------
# What a CLI command prints
# ---------------------------------------------------------------------------

TOKEN = "session-token-0123456789abcdef"
CLI_HEADERS = {"X-Api-Key": KEY, "Authorization": f"Bearer {TOKEN}"}
#: How a CLI command says that no request can be made with its settings.
CLI_NOT_SENT = "no request can be made with the base URL or the credentials this command uses"
PAGE = "the answer is a page, not the API's JSON (HTTP {status})"
CDN_BLOCK = "the CDN/WAF blocked this client before the API (HTTP {status})"


def _echoing_the_request(host: str, headers: dict[str, str]) -> bytes:
    """An error page that lists the request's headers back, as some proxies do."""
    lines = [f"Host: {host}", *(f"{name}: {value}" for name, value in headers.items())]
    return ("<html><h1>Request headers</h1><pre>" + "\n".join(lines) + "</pre></html>").encode()


def _naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    return f"<html><h1>Upstream error</h1><p>{host} did not answer.</p></html>".encode()


def _cdn_code(host: str, headers: dict[str, str]) -> bytes:
    """What the CDN answers a client it does not take for a browser: its code."""
    return b"error code: 1010"


def _cdn_name_naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    """A CDN block page that gives its name and the site, not its error code."""
    return (
        f"<html><title>Access denied | {host} used Cloudflare to restrict access</title></html>"
    ).encode()


def _cdn_words_naming_the_host(host: str, headers: dict[str, str]) -> bytes:
    """A block page in the words the hint has always matched."""
    return (
        f"<html><title>Sorry, you have been blocked | {host}</title>"
        "<p>Your browser's signature was rejected.</p></html>"
    ).encode()


def _cdn_bad_gateway(host: str, headers: dict[str, str]) -> bytes:
    """A CDN's page for an upstream that did not answer: not a block."""
    return f"<html><title>{host} | 502: Bad gateway</title><p>Cloudflare</p></html>".encode()


def _incident_number(host: str, headers: dict[str, str]) -> bytes:
    """A proxy's refusal whose incident number holds the digits of the CDN's
    code: not a CDN block."""
    return f"<html><h1>Access denied</h1><p>{host}: incident 8841010</p></html>".encode()


@pytest.mark.parametrize(
    ("status", "page", "marker", "detail"),
    [
        pytest.param(400, _echoing_the_request, "Request headers", PAGE, id="400-echoing-the-headers"),
        pytest.param(502, _naming_the_host, "Upstream error", PAGE, id="502-naming-the-host"),
        pytest.param(403, _cdn_code, "error code: 1010", CDN_BLOCK, id="403-cdn-code"),
        pytest.param(403, _cdn_name_naming_the_host, "used Cloudflare", CDN_BLOCK, id="403-cdn-name"),
        pytest.param(403, _cdn_words_naming_the_host, "have been blocked", CDN_BLOCK, id="403-cdn-words"),
        pytest.param(502, _cdn_bad_gateway, "Bad gateway", PAGE, id="502-cdn-bad-gateway"),
        pytest.param(403, _incident_number, "incident 8841010", PAGE, id="403-incident-number"),
    ],
)
def test_the_cli_reports_an_error_page_without_the_page(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status: int,
    page: Callable[..., bytes],
    marker: str,
    detail: str,
) -> None:
    """``detail`` is that a page came back, and its status, or, for a CDN/WAF
    block page, that it was one, which the hint for it follows. The page is
    logged at DEBUG, on one line, and nowhere above it."""
    _serve(monkeypatch, status, page)
    with caplog.at_level(logging.DEBUG):
        code, payload = cli._http_json("POST", BASE + "/api/v1/policy-bundles", headers=CLI_HEADERS, body={})

    assert code == status
    assert payload == {"detail": detail.format(status=status)}
    message = cli._append_cli_http_hint(cli._format_api_error(payload))
    assert ("Cloudflare 1010" in message) is (detail == CDN_BLOCK), message
    assert not [part for part in (KEY, TOKEN, HOST, marker) if part in message], message
    logged = [m for m in _debug(caplog, "artzain.cli") if marker in m]
    assert logged, "the page is not logged at DEBUG"
    assert not [m for m in logged if "\n" in m], logged
    assert not [m for m in _above_debug(caplog) if marker in m or KEY in m or TOKEN in m]


def test_the_hint_still_follows_the_api_s_own_words(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``detail`` in the API's JSON that says a browser check blocked the
    client gets the hint, as it did before pages were described."""

    def _detail(host: str, headers: dict[str, str]) -> bytes:
        return b'{"detail": "Request blocked: a browser check is required"}'

    _serve(monkeypatch, 403, _detail)
    code, payload = cli._http_json("POST", BASE + "/api/auth/device/code", body={})

    assert "Cloudflare 1010" in cli._append_cli_http_hint(cli._format_api_error(payload))


@pytest.mark.parametrize("body", NOT_JSON)
def test_the_cli_ends_on_an_answer_that_is_not_json(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, body: bytes
) -> None:
    """With a message, rather than a traceback, and without the page, which is
    logged at DEBUG."""
    _answer(monkeypatch, body)
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        cli._http_json("GET", BASE + "/api/v1/registry/catalog", headers=CLI_HEADERS)

    assert str(info.value) == "Not understood: " + PAGE.format(status=200)
    excerpt = repr(body.decode("utf-8", errors="replace"))
    assert [m for m in _debug(caplog, "artzain.cli") if excerpt in m], "the page is not logged at DEBUG"


#: Requests no request can be made with, and what ``http.client`` or ``urllib``
#: quotes for them. No connection is made.
CLI_UNSENDABLE = [
    pytest.param(BASE + "/api/v1/policy-bundles", {"X-Api-Key": HEAD + "\n" + TAIL}, (HEAD, TAIL), id="key"),
    pytest.param(
        BASE + "/api/v1/policy-bundles", {"Authorization": f"Bearer {HEAD}\n{TAIL}"}, (HEAD, TAIL), id="token"
    ),
    pytest.param("https://" + SPACED_HOST + "/api/v1/policy-bundles", CLI_HEADERS, (SPACED_HOST,), id="base-url"),
    pytest.param(HOST + "/api/v1/policy-bundles", CLI_HEADERS, (HOST,), id="no-scheme"),
]


@pytest.mark.parametrize(("url", "headers", "quoted"), CLI_UNSENDABLE)
def test_the_cli_ends_without_quoting_settings_no_request_can_be_made_with(
    caplog: pytest.LogCaptureFixture, url: str, headers: dict[str, str], quoted: tuple[str, ...]
) -> None:
    """The command ends with a message that names the settings, not with a
    traceback whose error quotes them."""
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        cli._http_json("POST", url, headers=headers, body={})

    message = str(info.value)
    assert not [part for part in quoted if part in message], message
    assert CLI_NOT_SENT in message, message
    assert (info.value.__cause__, info.value.__context__) == (None, None)
    assert [m for m in _debug(caplog, "artzain.cli") if all(part in m for part in quoted)]
    assert not [m for m in _above_debug(caplog) if any(part in m for part in quoted)]


# The licence commands, which talk to the deployment on this machine.

LICENCE_BASE = "http://127.0.0.1:9"


def _licence_get(token: str = TOKEN) -> None:
    args = argparse.Namespace(base_url=LICENCE_BASE, allow_remote=False, session_token=token)
    cli._licence_get(args, "/api/v1/licence/anchors")


def test_a_licence_command_reports_an_error_page_without_the_page(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    _serve(monkeypatch, 400, _echoing_the_request)
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        _licence_get()

    assert info.value.code == 1
    err = capsys.readouterr().err
    assert err == f"{LICENCE_BASE} refused the request (HTTP 400): {PAGE.format(status=400)}\n"
    assert [m for m in _debug(caplog, "artzain.cli") if "Request headers" in m]


def test_a_licence_command_reports_a_failed_request_by_its_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """The deployment is named, as it was set; the error by its type, since
    its text can quote a certificate's names. The text is logged at DEBUG."""
    _fail(monkeypatch, _certificate_for_another_name)
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        _licence_get()

    assert info.value.code == 1
    assert (info.value.__cause__, info.value.__context__) == (None, None)
    assert capsys.readouterr().err == (
        f"Could not reach the deployment at {LICENCE_BASE}: SSLCertVerificationError\n"
    )
    assert [m for m in _debug(caplog, "artzain.cli") if "certificate verify failed" in m]


def test_a_licence_command_ends_without_quoting_a_token_no_request_can_carry(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        _licence_get(token=HEAD + "\n" + TAIL)

    printed = str(info.value) + capsys.readouterr().err
    assert HEAD not in printed and TAIL not in printed, printed
    assert CLI_NOT_SENT in str(info.value)
    assert (info.value.__cause__, info.value.__context__) == (None, None)
    assert [m for m in _debug(caplog, "artzain.cli") if HEAD in m and TAIL in m]
    assert not [m for m in _above_debug(caplog) if HEAD in m or TAIL in m]


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"{}", id="empty-object"),
        pytest.param(b"[]", id="list"),
        pytest.param(b"null", id="null"),
    ],
)
def test_a_licence_command_ends_on_an_answer_without_its_data(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], body: bytes
) -> None:
    """The licence reads use what the answer holds: an answer with nothing in
    it ends the command, rather than an export of nothing or a traceback."""
    _answer(monkeypatch, body)
    with pytest.raises(SystemExit) as info:
        _licence_get()

    assert info.value.code == 1
    assert capsys.readouterr().err == (
        f"{LICENCE_BASE} answered without the data the command reads (HTTP 200)\n"
    )


# The exports, which download a file rather than read JSON.


@pytest.fixture
def _cli_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The CLI's key and host from the environment, and no project ``.env``."""
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", BASE)
    monkeypatch.chdir(tmp_path)


def _audit_export(out: Path) -> None:
    cli.cmd_audit_export(argparse.Namespace(profile=None, from_=None, to=None, out=str(out / "bundle.zip")))


def _registry_export(out: Path) -> None:
    cli.cmd_registry_export(argparse.Namespace(q=None, source=None, lifecycle=None, out=str(out / "catalog.csv")))


EXPORTS = [
    pytest.param(_audit_export, id="audit-export"),
    pytest.param(_registry_export, id="registry-export"),
]


@pytest.mark.usefixtures("_cli_settings")
@pytest.mark.parametrize("export", EXPORTS)
def test_an_export_reports_an_error_page_without_the_page(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    export: Callable[[Path], None],
) -> None:
    _serve(monkeypatch, 400, _echoing_the_request)
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        export(tmp_path)

    assert str(info.value) == "Export failed (400): " + PAGE.format(status=400)
    assert [m for m in _debug(caplog, "artzain.cli") if "Request headers" in m]


@pytest.mark.usefixtures("_cli_settings")
@pytest.mark.parametrize("export", EXPORTS)
def test_an_export_reports_what_the_api_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, export: Callable[[Path], None]
) -> None:
    _serve(monkeypatch, 503, _json_detail)
    with pytest.raises(SystemExit) as info:
        export(tmp_path)

    assert str(info.value) == "Export failed (503): audit_unavailable"


@pytest.mark.usefixtures("_cli_settings")
@pytest.mark.parametrize(
    ("variable", "value", "quoted"),
    [
        pytest.param("COGNEXUS_API_KEY", HEAD + "\n" + TAIL, (HEAD, TAIL), id="key"),
    ],
)
@pytest.mark.parametrize("export", EXPORTS)
def test_an_export_ends_without_quoting_settings_no_request_can_be_made_with(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    export: Callable[[Path], None],
    variable: str,
    value: str,
    quoted: tuple[str, ...],
) -> None:
    monkeypatch.setenv(variable, value)
    with caplog.at_level(logging.DEBUG), pytest.raises(SystemExit) as info:
        export(tmp_path)

    message = str(info.value)
    assert not [part for part in quoted if part in message], message
    assert CLI_NOT_SENT in message, message
    assert (info.value.__cause__, info.value.__context__) == (None, None)
    assert not [m for m in _above_debug(caplog) if any(part in m for part in quoted)]
    assert [m for m in _debug(caplog, "artzain.cli") if all(part in m for part in quoted)]
