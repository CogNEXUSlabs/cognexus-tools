"""``artzain connect openshell``: bind the deb gateway on this host, and undo it.

These run ``up``, ``remove`` and ``status`` against a scripted deb gateway in
a temporary home: ``systemctl --user``, ``openshell-gateway`` and
``openshell`` are played by :class:`_Gateway`, which keeps the units' states,
the gateway's settings, and what a restarted gateway is bound to. The engine
is a function that answers the redeem and the revoke.

What has to hold:

* the token is spent only on a host that can be bound, and the credential
  is saved before anything else can fail, so a run that stops needs no new
  token;
* nothing reaches ``gateway.toml`` that the gateway's own preflight has not
  passed, and the file keeps everything that was in it;
* ``remove`` gives ``gateway.toml`` back byte for byte, and keeps an
  operator's own edits when there are any;
* the self-test is a write the engine denies, refused with its decision id,
  and the setting does not move.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from artzain import _private_files
from artzain.openshell import connect, install, registration, sidecar
from artzain.openshell.state import GatewayLedger

needs_tomllib = pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML")

GATEWAY = "gw_01ABCDEFGHJKMNPQRSTVWXYZ00"
CREDENTIAL = "cnxg_" + "k" * 43
NEW_CREDENTIAL = "cnxg_" + "n" * 43
TOKEN = "cnxt_" + "t" * 43
DECISION = "01JBCDEFGHJKMNPQRSTVWXYZ00"
CONFIG = {"kind": "artzain.openshell.connect", "version": 1,
          "decision_url": "https://engine.example", "openshell_version": "0.1.2",
          "interceptor_timeout_ms": 1500, "decide_timeout_ms": 1200, "telemetry": False}
DIGEST = connect.config_digest(CONFIG)
#: What a sidecar whose first heartbeat and inventory the engine took says.
#: What the sidecar says when no break-glass window is open and nothing waits.
NO_WINDOW = {"enabled": True, "window": None, "pending": 0}
REPORTED = {"reporting": True, "heartbeat": "ok", "inventory": "ok", "sandboxes": 2,
            "partial": False}

#: The deb a host without OpenShell is given, and the pins it is checked
#: against in these tests (the real ones are install.DEB).
PACKAGE = b"the openshell deb"
PINNED_DEB = {"amd64": (("openshell_0.1.2-1_amd64.deb", hashlib.sha256(PACKAGE).hexdigest()),)}
RECEIPT = f"https://engine.example/dashboard.html?receipt={DECISION}"

GATEWAY_TOML = """\
[openshell]
version = 2

[openshell.gateway]
bind_address = "127.0.0.1:8080"
compute_driver = "docker"

[openshell.gateway.gateway_jwt]
signing_key_path = "/home/op/.config/openshell/jwt/signing.pem"
public_key_path = "/home/op/.config/openshell/jwt/public.pem"
gateway_id = "laptop"

[[openshell.gateway.interceptors]]
name = "audit"
grpc_endpoint = "unix:///run/user/1000/audit.sock"
order = 5
binding_policy = "allowlist"
failure_policy = "fail_open"
timeout = "500ms"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["post_commit"]
"""


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def _settings_value(path, name):
    """*name*'s value in the sidecar's settings file, or empty."""
    if not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip('"')
    return ""


def _settings_key(path):
    """The credential in the sidecar's settings file, or empty."""
    return _settings_value(path, "COGNEXUS_API_KEY")


def _stat(mode, uid):
    return os.stat_result((mode, 0, 0, 1, uid, 1000, 0, 0, 0, 0))


def _box(message, width=40):
    """An error as the openshell CLI prints it: coloured, in a box, the
    message wrapped between words at *width*."""
    lines = textwrap.wrap(message, width, break_long_words=False)
    return ("\x1b[31mError:\x1b[0m\n\u256d" + "\u2500" * (width + 2) + "\u256e\n"
            + "".join(f"\u2502 {line.ljust(width)} \u2502\n" for line in lines)
            + "\u2570" + "\u2500" * (width + 2) + "\u256f\n")


class _Gateway:
    """A deb gateway as ``connect`` sees it, and an engine to redeem at."""

    def __init__(self, tmp_path: Path, toml: str = GATEWAY_TOML):
        self.home = tmp_path / "home"
        self.root = tmp_path / "root"
        unit = self.root / "usr" / "lib" / "systemd" / "user" / "openshell-gateway.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Service]\nExecStartPre=openshell-gateway config preflight\n")
        self.toml = self.home / ".config" / "openshell" / "gateway.toml"
        self.toml.parent.mkdir(parents=True)
        if toml is not None:  # None: a package install on its defaults
            self.toml.write_bytes(toml.encode("utf-8"))
        self.calls = []
        self.posts = []
        self.units = {connect.GATEWAY_UNIT: "active", connect.SIDECAR_UNIT: "inactive"}
        self.settings = {"proposal_approval_mode": "manual"}
        self.bound = False          # what the running gateway was started with
        self.version = "openshell-gateway 0.1.2"
        self.preflight = None       # None: check the file; or an exit code
        self.restart = None         # None: as the bound state says; or "failed"
        self.engine_allows = False  # what the engine decides for the self-test
        self.decision_in_reason = True
        self.redeem = (200, None)
        self.revoke_status = 200
        self.revoke_raises = False
        # The gateway's live keys, as the engine holds them, and how the key
        # routes answer (None: as the engine would).
        self.live_keys = [CREDENTIAL]
        self.minted = 0
        self.mint_answer = None
        self.retire_status = None
        self.key_raises = False
        self.cli_reaches = True     # the CLI is registered with the gateway
        self.revision = 3
        #: What the sidecar's /artzain/reports says, one answer per read (the
        #: last one stays).
        self.reported = [dict(REPORTED)]
        # What doctor reads: the socket as the sidecar made it, file modes
        # (a POSIX file's, whatever this test runs on), the engine's /health
        # and the clock.
        self.socket_kind, self.socket_mode, self.socket_uid = stat.S_IFSOCK, 0o600, 1000
        self.socket_dir_mode = 0o700
        self.sidecar_restarts = 0
        self.gateway_after_sidecar_restart = ["active"]
        self.gateway_states = []
        self.silent = False  # the sidecar runs, and nothing answers
        self.socket_gone = False
        self.stray = False   # something answers on the port, not the service
        self.modes = {}
        self.engine_status, self.engine_skew, self.engine_raises = 200, 0.0, False
        self.engine_gets = []
        self.wall_now = 1_800_000_000.0
        # A host without OpenShell: what `up` may install (plan S3.2).
        self.openshell_installed = True
        self.package = PACKAGE  # what the download of the deb serves

    # the commands --------------------------------------------------------
    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        name, args = argv[0], argv[1:]
        if argv == ["dpkg", "--print-architecture"]:
            return _done(0, "amd64\n")
        if name == "curl":
            Path(args[args.index("-o") + 1]).write_bytes(self.package)
            return _done()
        if argv[:4] == ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get"]:
            self.openshell_installed = True
            return _done()
        if name == "openshell" and args[:2] == ["gateway", "add"]:
            return _done()
        if name == "openshell-gateway":
            if args == ["--version"]:
                return _done(0, self.version + "\n")
            if args[:3] == ["config", "preflight", "--path"]:
                if self.preflight is not None:
                    return _done(self.preflight, "", "preflight: bad registration")
                import tomllib
                tomllib.loads(Path(args[3]).read_text(encoding="utf-8"))
                return _done(0, "ok")
        if name == "systemctl":
            assert args[0] == "--user"
            verb = args[1:]
            if verb == ["daemon-reload"]:
                return _done()
            if verb[0] == "is-active" and verb[1] == connect.GATEWAY_UNIT and self.gateway_states:
                state = (self.gateway_states.pop(0) if len(self.gateway_states) > 1
                         else self.gateway_states[0])
                self.units[connect.GATEWAY_UNIT] = state
            if verb[0] == "is-active":
                return _done(0 if self.units.get(verb[1]) == "active" else 3,
                             self.units.get(verb[1], "inactive") + "\n")
            if verb[:2] == ["enable", "--now"]:
                self.units[verb[2]] = "active"
                return _done()
            if verb[:2] == ["disable", "--now"]:
                self.units[verb[2]] = "inactive"
                return _done()
            if verb[0] == "restart" and verb[1] == connect.SIDECAR_UNIT:
                self.units[connect.SIDECAR_UNIT] = "active"
                self.sidecar_restarts += 1
                # The gateway requires the sidecar, so it restarts too: these
                # are its states on the next looks.
                self.gateway_states = list(self.gateway_after_sidecar_restart)
                return _done(0)
            if verb[0] == "restart" and verb[1] == connect.GATEWAY_UNIT:
                registered = self.toml.exists() and connect.BLOCK_BEGIN in self.toml.read_text(
                    encoding="utf-8")
                sidecar_up = self.units[connect.SIDECAR_UNIT] == "active"
                state = self.restart or ("failed" if registered and not sidecar_up else "active")
                self.units[connect.GATEWAY_UNIT] = state
                self.bound = registered and state == "active"
                return _done(0)
        if name == "openshell" and not self.cli_reaches:
            return _done(1, "", _box("status: Unavailable, message: \"tcp connect error\""))
        if name == "openshell" and args[:2] == ["settings", "set"]:
            if "--yes" not in args:  # the real CLI asks before a global change
                return _done(1, "", "Error: refusing a global change without --yes")
            key, value = args[args.index("--key") + 1], args[args.index("--value") + 1]
            if self.bound and not self.engine_allows and value == "auto":
                reason = (f"decision deny ({DECISION})" if self.decision_in_reason
                          else "interceptor transport error")
                return _done(1, "", _box(
                    "status: PermissionDenied, message: \"gateway interceptor 'artzain' "
                    f"denied the request: {reason}\""))
            self.settings[key] = value
            self.revision += 1
            return _done(0, "\x1b[32m\u2713\x1b[0m Updated global setting\n")
        if name == "openshell" and args[:2] == ["settings", "get"]:
            return _done(0, f"\x1b[1mSettings Rev:\x1b[0m {self.revision}\n" + "".join(
                f"  {key} = {value}\n" for key, value in self.settings.items()))
        raise AssertionError(f"unexpected command {argv}")

    def healthy(self, port):
        return ((self.units[connect.SIDECAR_UNIT] == "active" or self.stray)
                and not self.silent)

    def break_glass(self, port, token=""):
        """As the sidecar answers ``GET /artzain/break-glass``: only with its token."""
        expected = _settings_value(self.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
        if self.units[connect.SIDECAR_UNIT] != "active" or not expected or token != expected:
            return None
        return dict(NO_WINDOW)

    def reports(self, port, token=""):
        if self.units[connect.SIDECAR_UNIT] != "active":
            return None
        key = _settings_key(self.paths.sidecar_env)
        # As the sidecar answers: one that holds a gateway credential says
        # nothing to a caller without its token.
        expected = _settings_value(self.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
        if key.startswith("cnxg_") and (not expected or token != expected):
            return None
        if key and key not in self.live_keys:  # the engine refuses its heartbeat
            return dict(REPORTED, heartbeat="failed", heartbeat_error="HTTPError")
        return dict(self.reported.pop(0) if len(self.reported) > 1 else self.reported[0])

    def stat(self, path):
        path, socket = Path(path), self.paths.socket
        if path == socket:
            if self.units[connect.SIDECAR_UNIT] != "active" or self.socket_gone:
                raise FileNotFoundError(str(path))
            return _stat(self.socket_kind | self.socket_mode, self.socket_uid)
        if path == socket.parent:
            return _stat(stat.S_IFDIR | self.socket_dir_mode, 1000)
        real = os.stat(path)
        return _stat(stat.S_IFMT(real.st_mode) | self.modes.get(path.name, 0o600), 1000)

    def get_engine(self, url, *, proxy="", ca_bundle=""):
        import email.utils

        self.engine_gets.append({"url": url, "proxy": proxy, "ca_bundle": ca_bundle})
        if self.engine_raises:
            raise OSError("engine down")
        return self.engine_status, {"Date": email.utils.formatdate(
            self.wall_now + self.engine_skew, usegmt=True)}

    # the engine ----------------------------------------------------------
    def post_json(self, url, *, headers, body, proxy="", ca_bundle=""):
        self.posts.append({"url": url, "headers": dict(headers), "body": dict(body),
                           "proxy": proxy, "ca_bundle": ca_bundle})
        if url.endswith(connect.REDEEM_PATH):
            status, answer = self.redeem
            if answer is None:
                answer = {"gateway_id": GATEWAY, "agent_did": f"openshell:{GATEWAY}",
                          "credential": CREDENTIAL, "key_prefix": CREDENTIAL[:12],
                          "config_digest": DIGEST, "config": CONFIG}
            return status, answer
        if "/keys" in url:
            return self._keys(url, headers["X-Api-Key"])
        if url.endswith("/revoke"):
            if self.revoke_raises:
                raise OSError("engine down")
            return self.revoke_status, {"revoked": True}
        raise AssertionError(url)

    def _keys(self, url, key):
        if self.key_raises:
            raise OSError("engine down")
        assert url.startswith(f"https://engine.example/api/v1/openshell/gateways/{GATEWAY}/keys")
        if key not in self.live_keys:
            return 401, {"detail": "Invalid API key"}
        if url.endswith("/keys/retire-others"):
            if self.retire_status is not None:
                return self.retire_status, {}
            retired = len(self.live_keys) - 1
            self.live_keys = [key]
            return 200, {"gateway_id": GATEWAY, "retired": retired}
        if self.mint_answer is not None:
            return self.mint_answer
        if len(self.live_keys) >= 2:
            return 409, {"detail": "the gateway already holds 2 live keys"}
        # A new key each time: NEW_CREDENTIAL first.
        self.minted += 1
        new = NEW_CREDENTIAL if self.minted == 1 else "cnxg_" + str(self.minted) * 43
        self.live_keys.append(new)
        return 200, {"gateway_id": GATEWAY, "credential": new, "key_prefix": new[:14],
                     "live_keys": len(self.live_keys)}

    def host(self, **overrides) -> connect.Host:
        settings = dict(
            environ={"HOME": str(self.home), "XDG_RUNTIME_DIR": "/run/user/1000",
                     "PATH": "/usr/bin"},
            root=str(self.root), runner=self.run, healthy=self.healthy,
            reports=self.reports, break_glass=self.break_glass, stat=self.stat,
            get_engine=self.get_engine,
            wall=lambda: self.wall_now,
            post_json=self.post_json, which=self.which,
            sleep=lambda _s: None, clock=_Clock(), platform="linux",
            executable="/home/op/.local/share/uv/tools/artzain/bin/python", uid=1000)
        settings.update(overrides)
        return connect.Host(**settings)

    def which(self, name):
        if name in ("openshell", "openshell-gateway") and not self.openshell_installed:
            return None
        return f"/usr/bin/{name}"

    @property
    def paths(self) -> connect.Layout:
        return connect.layout(self.host())

    def commands(self, name):
        return [call for call in self.calls if call[0] == name]


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


@pytest.fixture
def gateway(tmp_path):
    return _Gateway(tmp_path)


def _up(gateway, *, token=TOKEN, **kwargs):
    said = []
    record = connect.up(gateway.host(), token=token, digest=DIGEST,
                        engine="https://engine.example/", out=said.append, **kwargs)
    return record, said


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# The managed block
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("original", [b"", b"a = 1", b"a = 1\n", b"a = 1\n\n", b"[x]\ny = 2\n\n\n",
                                      "s = \"café\"\n".encode("utf-8")])
def test_a_file_nobody_touched_comes_back_byte_for_byte(tmp_path, original):
    path, backup = tmp_path / "f.toml", tmp_path / "f.before"
    path.write_bytes(connect.add_block(original, "[[x.y]]\nz = 1"))
    backup.write_bytes(original)
    assert connect.BLOCK_BEGIN in path.read_text(encoding="utf-8")
    outcome = connect._restore(path, backup, hashlib.sha256(original).hexdigest(),
                               created=not original)
    if not original:
        assert outcome == "removed" and not path.exists()
    else:
        assert outcome == "restored" and path.read_bytes() == original


def test_the_block_goes_after_one_empty_line():
    assert connect.add_block(b"a = 1\n", "b = 2") == (
        b"a = 1\n\n" + connect.BLOCK_BEGIN.encode() + b"\nb = 2\n" + connect.BLOCK_END.encode() + b"\n")
    assert connect.add_block(b"a = 1", "b = 2").startswith(b"a = 1\n\n" + connect.BLOCK_BEGIN.encode())
    assert connect.add_block(b"", "b = 2").startswith(connect.BLOCK_BEGIN.encode())


def test_edits_outside_the_block_are_kept_and_the_block_goes(tmp_path):
    path, backup = tmp_path / "f.toml", tmp_path / "f.before"
    original = b"a = 1\n"
    backup.write_bytes(original)
    edited = connect.add_block(original, "b = 2").replace(b"a = 1", b"a = 9") + b"c = 3\n"
    path.write_bytes(edited)
    assert connect._restore(path, backup, hashlib.sha256(original).hexdigest(), False) == "kept-edits"
    assert path.read_bytes() == b"a = 9\nc = 3\n"


def test_a_saved_copy_that_does_not_match_its_hash_is_not_used(tmp_path):
    path, backup = tmp_path / "f.toml", tmp_path / "f.before"
    path.write_bytes(connect.add_block(b"a = 1", "b = 2"))
    backup.write_bytes(b"a = 1")
    assert connect._restore(path, backup, "0" * 64, False) == "kept-edits"
    assert path.read_bytes() == b"a = 1\n"


@pytest.mark.parametrize("text", [
    "a = 1\n",                                                         # no block
    f"{connect.BLOCK_BEGIN}\nx\n{connect.BLOCK_END}\n{connect.BLOCK_BEGIN}\ny\n{connect.BLOCK_END}\n",
    f"{connect.BLOCK_END}\nx\n{connect.BLOCK_BEGIN}\n",                # the wrong way round
    f"a = 1 {connect.BLOCK_BEGIN}\nx\n{connect.BLOCK_END}\n",          # not at the start of a line
    f"{connect.BLOCK_BEGIN}\nx\n",                                     # no end
])
def test_a_file_without_exactly_one_whole_block_is_left_alone(tmp_path, text):
    assert connect.strip_block(text.encode("utf-8")) is None
    path = tmp_path / "f.toml"
    path.write_text(text, encoding="utf-8")
    assert connect._restore(path, tmp_path / "none", "", False) == "no-block"
    assert path.read_text(encoding="utf-8") == text


def _held_for(times):
    """``os.replace`` as Windows does it while another program (a virus
    scanner reading the file just written, say) has the target open."""
    real, refused = os.replace, []

    def replace(source, target):
        if len(refused) < times:
            refused.append(target)
            raise PermissionError(13, "Access is denied")
        real(source, target)
    return replace, refused


def test_a_write_held_up_by_another_program_waits_for_it(tmp_path, monkeypatch):
    path = tmp_path / "connect.json"
    path.write_bytes(b"old")
    replace, refused = _held_for(3)
    monkeypatch.setattr(_private_files, "_REPLACE_RETRY_SECONDS", 5.0)
    monkeypatch.setattr(connect.os, "replace", replace)
    connect._replace(path, b"new", private=True)
    assert path.read_bytes() == b"new" and len(refused) == 3
    assert sorted(p.name for p in tmp_path.iterdir()) == ["connect.json"]


@pytest.mark.parametrize("seconds", [0.0, 0.05])  # not Windows; a program that never lets go
def test_a_write_that_cannot_be_put_in_place_leaves_the_file_as_it_was(tmp_path, monkeypatch,
                                                                         seconds):
    path = tmp_path / "connect.json"
    path.write_bytes(b"old")
    replace, refused = _held_for(10 ** 6)
    monkeypatch.setattr(_private_files, "_REPLACE_RETRY_SECONDS", seconds)
    monkeypatch.setattr(connect.os, "replace", replace)
    with pytest.raises(PermissionError):
        connect._replace(path, b"new")
    assert path.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["connect.json"]
    assert (len(refused) == 1) == (seconds == 0.0)


# ---------------------------------------------------------------------------
# The configuration
# ---------------------------------------------------------------------------


def test_the_digest_is_the_engines_recipe():
    config = {"b": 1, "a": "café", "c": [1, {"z": True, "y": None}]}
    text = '{"a":"café","b":1,"c":[1,{"y":null,"z":true}]}'
    assert connect.config_digest(config) == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_a_whole_configuration_is_read():
    config = connect.parse_config({**CONFIG, "telemetry": True, "decide_timeout_ms": 900})
    assert config == connect.ConnectConfig("https://engine.example", "0.1.2", 1500, 900, True)
    minimal = {k: CONFIG[k] for k in ("kind", "version", "decision_url", "openshell_version")}
    assert connect.parse_config(minimal) == connect.ConnectConfig(
        "https://engine.example", "0.1.2", 1500, 1200, False)


@pytest.mark.parametrize("change, says", [
    ({"kind": "something.else"}, "not a artzain.openshell.connect"),
    ({"version": 2}, "too old"),
    ({"base_policy": {}}, "upgrade artzain"),
    ({"decision_url": "ftp://engine.example"}, "decision_url"),
    ({"decision_url": "https://"}, "decision_url"),
    ({"decision_url": 'https://engine.example/"x'}, "decision_url"),
    ({"decision_url": 7}, "decision_url"),
    ({"decision_url": "https://engine.example/a b"}, "decision_url"),
    ({"openshell_version": "latest"}, "openshell_version"),
    ({"interceptor_timeout_ms": 4}, "interceptor_timeout_ms"),
    ({"interceptor_timeout_ms": 60_001}, "interceptor_timeout_ms"),
    ({"interceptor_timeout_ms": True}, "interceptor_timeout_ms"),
    ({"interceptor_timeout_ms": "1500"}, "interceptor_timeout_ms"),
    ({"decide_timeout_ms": 49}, "decide_timeout_ms"),
    ({"decide_timeout_ms": 1500}, "below"),
    ({"telemetry": "no"}, "telemetry"),
])
def test_a_configuration_that_is_not_one_is_refused(change, says):
    with pytest.raises(connect.ConnectError, match=says):
        connect.parse_config({**CONFIG, **change})


def test_a_configuration_that_is_not_an_object_is_refused():
    for value in (None, [], "x", 1):
        with pytest.raises(connect.ConnectError, match="not an object"):
            connect.parse_config(value)


# ---------------------------------------------------------------------------
# The redeem
# ---------------------------------------------------------------------------


def _redeem(gateway, **kwargs):
    arguments = dict(engine="https://engine.example/", token=TOKEN, digest=DIGEST)
    arguments.update(kwargs)
    return connect.redeem(gateway.host(), **arguments)


def test_the_redeem_sends_the_token_as_a_bearer_and_checks_what_comes_back(gateway):
    got = _redeem(gateway, proxy="env", ca_bundle="/etc/ssl/corp.pem")
    assert (got.gateway_id, got.credential, got.raw_config) == (GATEWAY, CREDENTIAL, CONFIG)
    assert got.config == connect.parse_config(CONFIG)
    (sent,) = gateway.posts
    assert sent == {"url": "https://engine.example/api/v1/openshell/connect/redeem",
                    "headers": {"Authorization": f"Bearer {TOKEN}"},
                    "body": {"config_digest": DIGEST}, "proxy": "env",
                    "ca_bundle": "/etc/ssl/corp.pem"}
    assert CREDENTIAL not in repr(got)


@pytest.mark.parametrize("token", ["", "cnx_" + "t" * 44, "cnxg_" + "t" * 43, "cnxt_short",
                                   "cnxt_" + "t" * 40 + "'x", "cnxt_" + "t" * 40 + "\nx"])
def test_a_token_that_is_not_an_enroll_token_is_not_sent(gateway, token):
    with pytest.raises(connect.ConnectError, match="not an enroll token") as refused:
        _redeem(gateway, token=token)
    assert gateway.posts == [] and token[5:] not in str(refused.value) or not token


@pytest.mark.parametrize("digest", ["", "A" * 64, "a" * 63, "g" * 64, DIGEST + " "])
def test_a_digest_that_is_not_one_is_not_sent(gateway, digest):
    with pytest.raises(connect.ConnectError, match="config-digest"):
        _redeem(gateway, digest=digest)
    assert gateway.posts == []


@pytest.mark.parametrize("status, says", [
    (401, "not one the engine knows"), (409, "already used"), (410, "expired"),
    (422, "64 lowercase hex"), (429, "too many redeems"), (500, "HTTP 500"),
])
def test_a_refused_redeem_says_why(gateway, status, says):
    gateway.redeem = (status, {"detail": "x"})
    with pytest.raises(connect.ConnectError, match=says):
        _redeem(gateway)


def test_an_unreachable_engine_is_said_without_the_token(gateway, monkeypatch):
    def down(url, **_kwargs):
        raise OSError("Connection refused " + TOKEN)

    with pytest.raises(connect.ConnectError, match="could not be reached") as refused:
        connect.redeem(gateway.host(post_json=down), engine="https://engine.example",
                       token=TOKEN, digest=DIGEST)
    assert TOKEN not in str(refused.value) and "OSError" in str(refused.value)


@pytest.mark.parametrize("answer, says", [
    ([], "not an object"),
    ({"gateway_id": "gw_x", "credential": CREDENTIAL, "config_digest": DIGEST, "config": CONFIG},
     "names no gateway"),
    ({"gateway_id": GATEWAY, "credential": "cnx_account", "config_digest": DIGEST,
      "config": CONFIG}, "no gateway credential"),
    ({"gateway_id": GATEWAY, "credential": CREDENTIAL + '"', "config_digest": DIGEST,
      "config": CONFIG}, "no gateway credential"),
    ({"gateway_id": GATEWAY, "credential": CREDENTIAL, "config_digest": "b" * 64,
      "config": CONFIG}, "not the one the digest names"),
    ({"gateway_id": GATEWAY, "credential": CREDENTIAL, "config_digest": DIGEST,
      "config": {**CONFIG, "telemetry": True}}, "not the one the digest names"),
])
def test_an_answer_that_is_not_what_was_asked_for_is_refused(gateway, answer, says):
    gateway.redeem = (200, answer)
    with pytest.raises(connect.ConnectError, match=says):
        _redeem(gateway)


def test_an_approved_configuration_this_artzain_cannot_read_is_refused(gateway):
    newer = {**CONFIG, "version": 2}
    gateway.redeem = (200, {"gateway_id": GATEWAY, "credential": CREDENTIAL,
                            "config_digest": connect.config_digest(newer), "config": newer})
    with pytest.raises(connect.ConnectError, match="too old"):
        _redeem(gateway, digest=connect.config_digest(newer))


# ---------------------------------------------------------------------------
# The registration
# ---------------------------------------------------------------------------


@needs_tomllib
def test_the_registration_binds_what_the_sidecar_decides():
    import tomllib

    text = registration.render("unix:///run/user/1000/artzain/openshell.sock", version_table=True)
    doc = tomllib.loads(text)
    assert doc["openshell"]["version"] == 2
    deciding, observing = doc["openshell"]["gateway"]["interceptors"]
    assert (deciding["name"], deciding["failure_policy"], deciding["order"]) == (
        "artzain", "fail_closed", 10)
    assert (observing["name"], observing["failure_policy"], observing["order"]) == (
        "artzain-observe", "fail_open", 20)
    for reg in (deciding, observing):
        assert reg["grpc_endpoint"] == "unix:///run/user/1000/artzain/openshell.sock"
        assert reg["binding_policy"] == "allowlist" and reg["timeout"] == "1500ms"

    def bound(reg):
        return sorted((b["rpc"].split("/")[1], tuple(b["phases"])) for b in reg["bindings"])

    assert bound(deciding) == sorted(
        (m, tuple(p)) for m, p in registration.bindings(("modify_operation", "validate")))
    assert bound(observing) == sorted(
        (m, tuple(p)) for m, p in registration.bindings(("post_commit",)))


@pytest.mark.parametrize("endpoint", ["unix://relative", "http://127.0.0.1:1",
                                      'unix:///run/a"b', "unix:///run/a b", "unix:///run/a\nb"])
def test_an_endpoint_the_gateway_would_refuse_is_not_written(endpoint):
    with pytest.raises(ValueError, match="endpoint"):
        registration.render(endpoint)


@pytest.mark.parametrize("timeout", [4, 60_001, True, 1500.0, "1500"])
def test_a_timeout_the_gateway_would_refuse_is_not_written(timeout):
    with pytest.raises(ValueError, match="timeout"):
        registration.render("unix:///run/x.sock", timeout_ms=timeout)


def test_the_servicer_describes_the_same_bindings():
    servicer = pytest.importorskip("artzain.openshell.servicer")
    assert servicer.bindings is registration.bindings


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


@needs_tomllib
def test_up_binds_the_gateway_and_checks_it_is_governed(gateway):
    before = gateway.toml.read_bytes()
    record, said = _up(gateway)
    paths = gateway.paths

    # The gateway.toml: what it had, then the block, which preflight passed.
    after = gateway.toml.read_bytes()
    assert after.startswith(before) and connect.strip_block(after) == before
    import tomllib
    names = [i["name"] for i in tomllib.loads(after.decode())["openshell"]["gateway"]["interceptors"]]
    assert names == ["audit", "artzain", "artzain-observe"]
    preflights = gateway.commands("openshell-gateway")[1:]
    assert len(preflights) == 1 and preflights[0][:3] == ["openshell-gateway", "config", "preflight"]
    assert preflights[0][4].endswith("gateway.toml.candidate")  # never the live file
    assert not Path(preflights[0][4]).exists()
    assert paths.toml_backup.read_bytes() == before

    # The sidecar: its settings, its unit, and the gateway's drop-in.
    env = paths.sidecar_env.read_text(encoding="utf-8")
    assert f'COGNEXUS_API_KEY="{CREDENTIAL}"\n' in env
    assert f'OPENSHELL_GATEWAY_ID="{GATEWAY}"\n' in env
    assert 'ARTZAIN_DECISION_URL="https://engine.example"\n' in env
    assert 'OPENSHELL_SIDECAR_GRPC="unix:///run/user/1000/artzain/openshell.sock"\n' in env
    assert 'OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS="1200"\n' in env
    assert 'OPENSHELL_JWT_PUBLIC_KEY="/home/op/.config/openshell/jwt/public.pem"\n' in env
    assert 'OPENSHELL_JWT_GATEWAY_ID="laptop"\n' in env
    assert ('OPENSHELL_REGISTRATION_DIGEST="' + registration.digest(registration.render(
        "unix:///run/user/1000/artzain/openshell.sock")) + '"\n') in env
    assert connect._saved(paths)["COGNEXUS_API_KEY"] == CREDENTIAL
    unit = paths.sidecar_unit.read_text(encoding="utf-8")
    assert f"EnvironmentFile={paths.sidecar_env.as_posix()}\n" in unit
    assert ('ExecStart="/home/op/.local/share/uv/tools/artzain/bin/python" '
            "-m artzain.cli openshell sidecar\n") in unit
    # Started is when the socket is there: the gateway's unit waits for it.
    assert "Type=notify\nNotifyAccess=main\n" in unit and "Type=simple" not in unit
    assert paths.dropin.read_text(encoding="utf-8").endswith(
        f"[Unit]\nRequires={connect.SIDECAR_UNIT}\nAfter={connect.SIDECAR_UNIT}\n")
    gateway_env = paths.gateway_env.read_text(encoding="utf-8")
    assert "OPENSHELL_TELEMETRY_ENABLED=false\n" in gateway_env

    # The order: approvals manual while unbound; the sidecar up before the
    # gateway is restarted bound; then the self-test.
    sequence = [" ".join(c[:4]) for c in gateway.calls]
    assert sequence.index("openshell settings set --global") < sequence.index(
        "systemctl --user enable --now")
    assert sequence.index("systemctl --user enable --now") < sequence.index(
        "openshell-gateway config preflight --path")
    assert sequence.index("openshell-gateway config preflight --path") < sequence.index(
        f"systemctl --user restart {connect.GATEWAY_UNIT}")
    assert gateway.settings["proposal_approval_mode"] == "manual"

    assert record["connected"] is True and record["self_test_decision_id"] == DECISION
    assert record["steps"] == ["redeemed", "approval-manual", "gateway-env", "sidecar",
                               "toml-saved", "registration", "gateway-restarted", "self-test",
                               "reported"]
    # The governed line, its receipt, then what the engine took of the first
    # reports.
    assert DECISION in said[-3] and GATEWAY in said[-3]
    assert said[-2] == f"its receipt: {RECEIPT}"
    assert not any(CREDENTIAL in line or TOKEN in line for line in said)
    assert CREDENTIAL not in paths.record.read_text(encoding="utf-8")


@needs_tomllib
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_what_up_writes_that_holds_the_credential_is_the_owners_alone(gateway):
    _up(gateway)
    paths = gateway.paths
    for path in (paths.sidecar_env, paths.record, paths.toml_backup):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path
    assert stat.S_IMODE(os.stat(paths.artzain_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.state_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.gateway_env).st_mode) == 0o600  # it created it


@needs_tomllib
def test_a_file_without_an_openshell_table_gets_one(tmp_path):
    gateway = _Gateway(tmp_path, toml='[logging]\nlevel = "info"\n')
    _up(gateway)
    import tomllib
    doc = tomllib.loads(gateway.toml.read_text(encoding="utf-8"))
    assert doc["openshell"]["version"] == 2 and doc["logging"] == {"level": "info"}


@needs_tomllib
@pytest.mark.parametrize("toml, says", [
    ("[openshell]\nversion = 1\n", "version = 2"),
    ("openshell = 3\n", "not a table"),
    ("[openshell]\nversion = 2\n[openshell.gateway]\ninterceptors = 3\n", "laid out"),
    ('[openshell]\nversion = 2\n[[openshell.gateway.interceptors]]\nname = "artzain"\n',
     "already registers artzain"),
    ("[openshell\n", "not valid TOML"),
])
def test_a_gateway_toml_the_block_cannot_go_into_stops_before_the_token_is_spent(
        tmp_path, toml, says):
    gateway = _Gateway(tmp_path, toml=toml)
    with pytest.raises(connect.ConnectError, match=says):
        _up(gateway)
    assert gateway.posts == [] and not gateway.paths.record.exists()


@needs_tomllib
def test_a_failed_preflight_leaves_the_live_file_alone(gateway):
    gateway.preflight = 1
    before = gateway.toml.read_bytes()
    with pytest.raises(connect.ConnectError, match="config preflight failed"):
        _up(gateway)
    paths = gateway.paths
    assert gateway.toml.read_bytes() == before
    assert not paths.toml_backup.exists() and not (paths.artzain_dir / "gateway.toml.candidate").exists()
    assert gateway.commands("systemctl")[-1][2] != "restart"


@needs_tomllib
def test_a_run_that_stopped_after_the_redeem_finishes_without_a_new_token(gateway):
    gateway.version = "openshell-gateway 0.2.0"
    with pytest.raises(connect.ConnectError, match="approved for 0.1.2") as stopped:
        _up(gateway)
    assert "no new token needed" in str(stopped.value)
    assert gateway.paths.sidecar_env.exists() and len(gateway.posts) == 1

    gateway.version = "openshell-gateway 0.1.5"  # the same line
    record, said = _up(gateway, token="")
    assert record["connected"] is True and len(gateway.posts) == 1
    assert "already redeemed" in said[0]


@needs_tomllib
def test_a_gateway_that_does_not_stay_up_is_undone_by_remove_byte_for_byte(gateway):
    before = gateway.toml.read_bytes()
    gateway.restart = "failed"
    with pytest.raises(connect.ConnectError, match="did not stay up") as stopped:
        _up(gateway)
    assert "remove" in str(stopped.value)
    assert connect.BLOCK_BEGIN in gateway.toml.read_text(encoding="utf-8")

    gateway.restart = None
    connect.remove(gateway.host(), out=lambda _s: None)
    assert gateway.toml.read_bytes() == before
    assert not gateway.paths.gateway_env.exists()
    assert gateway.units[connect.GATEWAY_UNIT] == "active"


@needs_tomllib
def test_a_run_that_stopped_after_the_toml_write_is_finished_by_a_second_run(gateway):
    gateway.restart = "failed"
    with pytest.raises(connect.ConnectError):
        _up(gateway)
    gateway.restart = None
    record, _said = _up(gateway, token="")
    text = gateway.toml.read_text(encoding="utf-8")
    assert text.count(connect.BLOCK_BEGIN) == 1 and record["connected"] is True
    assert len(gateway.commands("openshell-gateway")) == 1 + 1 + 1  # two version reads, one preflight


@needs_tomllib
def test_a_self_test_write_that_commits_is_put_back_and_fails_the_run(gateway):
    gateway.engine_allows = True
    with pytest.raises(connect.ConnectError, match="ALLOWED"):
        _up(gateway)
    assert gateway.settings["proposal_approval_mode"] == "manual"
    assert "self-test" not in connect.Record.load(gateway.paths.record).data["steps"]


@needs_tomllib
def test_a_self_test_refused_without_an_artzain_decision_fails_the_run(gateway):
    gateway.decision_in_reason = False
    with pytest.raises(connect.ConnectError, match="not by an ArtzAIn decision"):
        _up(gateway)


@needs_tomllib
def test_a_self_test_after_which_the_setting_is_not_manual_fails_the_run(gateway, monkeypatch):
    real = gateway.run

    def moved(argv, env, timeout):
        done = real(argv, env, timeout)
        if argv[1:3] == ["settings", "get"]:
            return _done(0, done.stdout.replace("proposal_approval_mode = manual",
                                                "proposal_approval_mode = auto"))
        return done

    with pytest.raises(connect.ConnectError, match="does not show"):
        connect.up(gateway.host(runner=moved), token=TOKEN, digest=DIGEST,
                   engine="https://engine.example", out=lambda _s: None)


@needs_tomllib
def test_the_self_test_reads_its_own_setting_not_the_next_one(gateway):
    """The CLI lists every gateway-wide setting; another one reading
    ``manual`` says nothing about ``proposal_approval_mode``."""
    real = gateway.run

    def moved(argv, env, timeout):
        done = real(argv, env, timeout)
        if argv[1:3] == ["settings", "get"]:
            return _done(0, done.stdout.replace(
                "proposal_approval_mode = manual",
                "proposal_approval_mode = auto\n  sandbox_review_mode = manual"))
        return done

    with pytest.raises(connect.ConnectError, match="does not show"):
        connect.up(gateway.host(runner=moved), token=TOKEN, digest=DIGEST,
                   engine="https://engine.example", out=lambda _s: None)


@needs_tomllib
@pytest.mark.parametrize("change, says", [
    ({"platform": "darwin"}, "Linux only"),
    ({"which": lambda name: None if name == "openshell" else f"/usr/bin/{name}"},
     "openshell is not on PATH"),
    ({"root": "/nonexistent-root"}, "not a deb or rpm gateway"),
])
def test_a_host_this_release_cannot_bind_is_refused_before_anything(gateway, change, says):
    with pytest.raises(connect.ConnectError, match=says):
        connect.up(gateway.host(**change), token=TOKEN, digest=DIGEST, out=lambda _s: None)
    assert gateway.posts == []


# ---------------------------------------------------------------------------
# A host without OpenShell (plan S3.2): up installs it when told to
# ---------------------------------------------------------------------------


@pytest.fixture
def bare(gateway, monkeypatch):
    """The gateway's host before OpenShell is installed on it."""
    monkeypatch.setattr(install, "DEB", PINNED_DEB)
    gateway.openshell_installed = False
    return gateway


@needs_tomllib
def test_without_openshell_up_says_how_to_install_it_and_spends_no_token(bare):
    with pytest.raises(connect.ConnectError) as caught:
        _up(bare)
    says = str(caught.value)
    assert says.startswith("openshell-gateway is not on PATH: OpenShell 0.1.2 is not installed")
    assert "--install-openshell" in says
    assert f"echo '{PINNED_DEB['amd64'][0][1]}  openshell_0.1.2-1_amd64.deb' | sha256sum -c -" in says
    assert "no token was spent" in says
    assert bare.posts == []
    assert not any(c[0] in ("curl", "sudo") for c in bare.calls)


@needs_tomllib
def test_up_installs_openshell_when_told_to_then_binds_it(bare):
    record, said = _up(bare, install_openshell=True)
    assert record["connected"] is True and bare.openshell_installed
    sequence = [c[0] for c in bare.calls]
    # Installed, and its CLI answering, before the token is spent.
    assert sequence.index("sudo") < sequence.index("openshell-gateway")
    assert bare.posts[0]["url"].endswith(connect.REDEEM_PATH)
    assert any("installing OpenShell 0.1.2 with apt-get under sudo" in line for line in said)


@needs_tomllib
@pytest.mark.parametrize("answer", ["y", "Y", "yes", " yes \n"])
def test_up_asks_before_installing_and_a_yes_installs(bare, answer):
    asked = []
    record, _said = _up(bare, ask=lambda question: asked.append(question) or answer)
    (question,) = asked
    assert "OpenShell 0.1.2 is not installed" in question
    assert "openshell_0.1.2-1_amd64.deb" in question and PINNED_DEB["amd64"][0][1][:12] in question
    assert "sudo apt-get" in question and question.endswith("[y/N] ")
    assert record["connected"] is True and bare.openshell_installed


@needs_tomllib
@pytest.mark.parametrize("answer", ["", "n", "no", "maybe"])
def test_anything_but_yes_installs_nothing(bare, answer):
    with pytest.raises(connect.ConnectError, match="OpenShell 0.1.2 is not installed"):
        _up(bare, ask=lambda _question: answer)
    assert not any(c[0] in ("curl", "sudo") for c in bare.calls) and bare.posts == []


@needs_tomllib
def test_a_package_that_is_not_its_pinned_build_stops_up_before_the_token(bare):
    bare.package = b"something else"
    with pytest.raises(connect.ConnectError, match="installing OpenShell 0.1.2: "
                                                   "openshell_0.1.2-1_amd64.deb is not the build"):
        _up(bare, install_openshell=True)
    assert not any(c[0] == "sudo" for c in bare.calls) and bare.posts == []


@needs_tomllib
def test_a_host_without_systemd_is_not_offered_an_install(bare):
    host = bare.host(which=lambda name: None if name in ("systemctl", "openshell",
                                                        "openshell-gateway") else f"/usr/bin/{name}")
    with pytest.raises(connect.ConnectError, match="systemctl is not on PATH"):
        connect.up(host, token=TOKEN, digest=DIGEST, install_openshell=True, out=lambda _s: None)
    assert not any(c[0] in ("curl", "sudo") for c in bare.calls)


@needs_tomllib
def test_a_host_with_openshell_is_not_asked(gateway):
    record, _said = _up(gateway, ask=lambda _q: pytest.fail("asked"), install_openshell=True)
    assert record["connected"] is True
    assert not any(c[0] in ("curl", "sudo") for c in gateway.calls)


def test_up_installs_from_the_command_line_when_told_to_or_asks_at_a_terminal(monkeypatch):
    from artzain import cli

    seen = []
    monkeypatch.setattr(connect, "up", lambda host, **kw: seen.append(kw) or {})
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    cli.main(["connect", "openshell", "up", "--install-openshell"])
    cli.main(["connect", "openshell", "up"])
    assert [kw["install_openshell"] for kw in seen] == [True, False]
    assert seen[1]["ask"] is None
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    cli.main(["connect", "openshell", "up"])
    assert callable(seen[2]["ask"])


# ---------------------------------------------------------------------------
# The receipt link (plan S3.2, step 13)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("engine, decision, link", [
    ("https://app.cognexuslabs.ai", DECISION,
     f"https://app.cognexuslabs.ai/dashboard.html?receipt={DECISION}"),
    ("https://engine.example/", DECISION, RECEIPT),
    ("https://engine.example/api/", DECISION, RECEIPT),
    ("http://127.0.0.1:8000", DECISION, f"http://127.0.0.1:8000/dashboard.html?receipt={DECISION}"),
    ("https://engine.example", DECISION[:-1], ""),
    ("https://engine.example", DECISION + "&x=1", ""),
    ("https://engine.example", None, ""),
    ("ftp://engine.example", DECISION, ""),
    ("", DECISION, ""),
])
def test_the_receipt_link_is_the_dashboards_page_of_the_decision(engine, decision, link):
    assert connect.receipt_url(engine, decision) == link


@needs_tomllib
def test_a_gateway_that_does_not_say_its_version_is_refused(gateway):
    gateway.version = "openshell-gateway (unknown)"
    with pytest.raises(connect.ConnectError, match="did not say its version"):
        _up(gateway)
    assert gateway.posts == []


@needs_tomllib
def test_a_package_install_on_its_defaults_gets_a_gateway_toml_and_loses_it_again(tmp_path):
    """A package-managed gateway reads gateway.toml only when it exists, and
    the package writes none."""
    import tomllib

    gateway = _Gateway(tmp_path, toml=None)
    record, _said = _up(gateway)
    doc = tomllib.loads(gateway.toml.read_text(encoding="utf-8"))
    assert doc["openshell"]["version"] == 2
    assert [i["name"] for i in doc["openshell"]["gateway"]["interceptors"]] == [
        "artzain", "artzain-observe"]
    assert record["toml_created"] is True and record["connected"] is True
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(gateway.toml).st_mode) == 0o600

    result = connect.remove(gateway.host(), out=lambda _s: None)
    assert result["gateway.toml"] == "removed" and not gateway.toml.exists()
    assert result["gateway"] == "restarted unbound" and gateway.bound is False


@needs_tomllib
def test_a_cli_that_cannot_reach_the_gateway_stops_up_before_the_token_is_spent(gateway):
    gateway.cli_reaches = False
    with pytest.raises(connect.ConnectError, match="cannot reach the gateway") as stopped:
        _up(gateway)
    assert "openshell gateway add" in str(stopped.value)
    assert gateway.posts == [] and not gateway.paths.record.exists()


@needs_tomllib
def test_the_gateways_own_jwt_bundle_is_used_when_gateway_toml_names_none(tmp_path):
    gateway = _Gateway(tmp_path, toml="[openshell]\nversion = 2\n")
    bundle = gateway.home.joinpath(*connect.LOCAL_JWT_DIR)
    bundle.mkdir(parents=True)
    for name in ("signing.pem", "public.pem", "kid"):
        (bundle / name).write_text("x")
    _record, said = _up(gateway)
    saved = connect._saved(gateway.paths)
    assert saved["OPENSHELL_JWT_PUBLIC_KEY"] == (bundle / "public.pem").as_posix()
    assert saved["OPENSHELL_JWT_GATEWAY_ID"] == "openshell"
    assert not any("gateway_jwt" in line for line in said)


@needs_tomllib
def test_the_gateways_own_jwt_bundle_is_under_home_whatever_the_state_folder(tmp_path):
    """The package's unit sets ``OPENSHELL_LOCAL_TLS_DIR=%h/.local/state/...``,
    which ``XDG_STATE_HOME`` does not move."""
    gateway = _Gateway(tmp_path, toml="[openshell]\nversion = 2\n")
    bundle = gateway.home.joinpath(*connect.LOCAL_JWT_DIR)
    bundle.mkdir(parents=True)
    for name in ("signing.pem", "public.pem", "kid"):
        (bundle / name).write_text("x")
    host = gateway.host(environ={"HOME": str(gateway.home), "XDG_RUNTIME_DIR": "/run/user/1000",
                                 "XDG_STATE_HOME": str(gateway.home / "elsewhere")})
    connect.up(host, token=TOKEN, digest=DIGEST, out=lambda _s: None)
    saved = connect._saved(connect.layout(host))
    assert saved["OPENSHELL_JWT_PUBLIC_KEY"] == (bundle / "public.pem").as_posix()


@needs_tomllib
def test_a_partial_jwt_bundle_is_not_used(tmp_path):
    gateway = _Gateway(tmp_path, toml="[openshell]\nversion = 2\n")
    bundle = gateway.home.joinpath(*connect.LOCAL_JWT_DIR)
    bundle.mkdir(parents=True)
    (bundle / "public.pem").write_text("x")
    _record, said = _up(gateway)
    assert "OPENSHELL_JWT_PUBLIC_KEY" not in connect._saved(gateway.paths)
    assert any("gateway_jwt" in line for line in said)


@needs_tomllib
def test_a_gateway_toml_that_names_a_key_wins_over_the_bundle(gateway):
    bundle = gateway.home.joinpath(*connect.LOCAL_JWT_DIR)
    bundle.mkdir(parents=True)
    for name in ("signing.pem", "public.pem", "kid"):
        (bundle / name).write_text("x")
    _up(gateway)
    assert connect._saved(gateway.paths)["OPENSHELL_JWT_GATEWAY_ID"] == "laptop"


def test_the_cli_is_asked_without_colour():
    assert connect.Host(environ={}).environ["NO_COLOR"] == "1"
    assert connect.Host(environ={"NO_COLOR": ""}).environ["NO_COLOR"] == ""


def test_a_boxed_coloured_refusal_is_read_as_one_line():
    done = _done(1, "", _box("message: \"gateway interceptor 'artzain' denied the "
                             f"request: decision deny ({DECISION})\"", width=33))
    said = connect._said(done)
    assert "\x1b" not in said and not any("\u2500" <= ch <= "\u257f" for ch in said)
    assert said.startswith("Error: message:")
    assert connect._DECISION_ID.search(said).group(1) == DECISION


@needs_tomllib
@pytest.mark.parametrize("executable, says", [
    ("/home/op/.cache/uv/archive-v0/abc/bin/python", "temporary uv environment"),
    ('/opt/a"b/python', "cannot name"),
    ("relative/python", "cannot name"),
])
def test_a_python_the_service_cannot_keep_using_is_refused(gateway, executable, says):
    with pytest.raises(connect.ConnectError, match=says):
        connect.up(gateway.host(executable=executable), token=TOKEN, digest=DIGEST,
                   out=lambda _s: None)


@needs_tomllib
def test_a_sidecar_that_never_answers_stops_the_run_before_the_gateway_is_touched(gateway):
    before = gateway.toml.read_bytes()
    with pytest.raises(connect.ConnectError, match="did not answer"):
        connect.up(gateway.host(healthy=lambda _port: False), token=TOKEN, digest=DIGEST,
                   out=lambda _s: None)
    assert gateway.toml.read_bytes() == before
    assert not any(c[:3] == ["systemctl", "--user", "restart"] for c in gateway.calls)


@needs_tomllib
@pytest.mark.parametrize("change, says", [
    ({"port": 0}, "--port"), ({"port": 65536}, "--port"),
    ({"ca_bundle": '/etc/ssl/corp"x.pem'}, "OPENSHELL_SIDECAR_CA_BUNDLE"),
    ({"proxy": "http://proxy.example:3128/$HOME"}, "OPENSHELL_SIDECAR_PROXY"),
    ({"ca_bundle": "/etc/ssl/corp\n.pem"}, "OPENSHELL_SIDECAR_CA_BUNDLE"),
])
def test_a_setting_systemd_cannot_carry_stops_up_before_the_token_is_spent(
        gateway, change, says):
    with pytest.raises(connect.ConnectError, match=says):
        _up(gateway, **change)
    assert gateway.posts == [] and not gateway.paths.sidecar_env.exists()


@needs_tomllib
def test_a_settings_folder_with_a_space_stops_up_before_the_token_is_spent(gateway):
    host = gateway.host(environ={"HOME": str(gateway.home), "XDG_RUNTIME_DIR": "/run/user/1000",
                                 "XDG_CONFIG_HOME": str(gateway.home / "my config")})
    (gateway.home / "my config" / "openshell").mkdir(parents=True)
    (gateway.home / "my config" / "openshell" / "gateway.toml").write_text(GATEWAY_TOML)
    with pytest.raises(connect.ConnectError, match="XDG_CONFIG_HOME"):
        connect.up(host, token=TOKEN, digest=DIGEST, out=lambda _s: None)
    assert gateway.posts == []


@needs_tomllib
def test_a_state_folder_with_a_space_is_carried_quoted(gateway):
    host = gateway.host(environ={"HOME": str(gateway.home), "XDG_RUNTIME_DIR": "/run/user/1000",
                                 "XDG_STATE_HOME": str(gateway.home / "my state")})
    connect.up(host, token=TOKEN, digest=DIGEST, out=lambda _s: None)
    saved = connect._saved(connect.layout(host))
    assert saved["OPENSHELL_SIDECAR_STATE"].endswith("my state/artzain/openshell/state.json")
    assert saved["COGNEXUS_API_KEY"] == CREDENTIAL


@needs_tomllib
def test_a_gateway_that_comes_up_and_falls_over_did_not_stay_up(gateway):
    real = gateway.run
    seen = {"active": 0}

    def flapping(argv, env, timeout):
        done = real(argv, env, timeout)
        if argv[2:4] == ["is-active", connect.GATEWAY_UNIT] and gateway.bound:
            seen["active"] += 1
            if seen["active"] > 1:  # up at first, then the restart loop
                return _done(3, "activating\n")
        return done

    with pytest.raises(connect.ConnectError, match="did not stay up"):
        connect.up(gateway.host(runner=flapping), token=TOKEN, digest=DIGEST,
                   out=lambda _s: None)


@needs_tomllib
def test_a_gateway_that_cannot_be_set_to_manual_approval_is_not_bound(gateway):
    """Nothing governs the gateway until the restart: an automatic approval
    meanwhile would go through unchecked, so ``up`` stops there."""
    real = gateway.run

    def refusing(argv, env, timeout):
        if argv[1:3] == ["settings", "set"] and argv[argv.index("--value") + 1] == "manual":
            return _done(1, "", _box("status: Internal, message: \"settings store is read-only\""))
        return real(argv, env, timeout)

    with pytest.raises(connect.ConnectError, match="setting proposal_approval_mode to manual"):
        connect.up(gateway.host(runner=refusing), token=TOKEN, digest=DIGEST,
                   out=lambda _s: None)
    record = json.loads(gateway.paths.record.read_text(encoding="utf-8"))
    assert "redeemed" in record["steps"] and "approval-manual" not in record["steps"]
    assert not gateway.paths.dropin.exists() and connect.BLOCK_BEGIN not in (
        gateway.toml.read_text(encoding="utf-8"))


@needs_tomllib
def test_the_token_is_needed_on_a_first_run(gateway):
    with pytest.raises(connect.ConnectError, match="ARTZAIN_ENROLL_TOKEN"):
        _up(gateway, token="")


# ---------------------------------------------------------------------------
# remove and status
# ---------------------------------------------------------------------------


@needs_tomllib
def test_remove_after_up_puts_everything_back(gateway):
    before = gateway.toml.read_bytes()
    _up(gateway)
    paths = gateway.paths
    said = []
    result = connect.remove(gateway.host(), out=said.append)
    assert gateway.toml.read_bytes() == before
    assert hashlib.sha256(gateway.toml.read_bytes()).hexdigest() == hashlib.sha256(before).hexdigest()
    assert result == {"gateway.toml": "restored", "drop-in": "removed",
                      "gateway": "restarted unbound", "sidecar": "removed",
                      "gateway.env": "removed", "credential": "revoked"}
    for path in (paths.dropin, paths.sidecar_unit, paths.sidecar_env, paths.record,
                 paths.toml_backup, paths.env_backup, paths.gateway_env, paths.state_dir):
        assert not path.exists(), path
    assert gateway.units == {connect.GATEWAY_UNIT: "active", connect.SIDECAR_UNIT: "inactive"}
    assert gateway.bound is False
    revoke = gateway.posts[-1]
    assert revoke["url"] == f"https://engine.example/api/v1/openshell/gateways/{GATEWAY}/revoke"
    assert revoke["headers"] == {"X-Api-Key": CREDENTIAL}
    assert not any(CREDENTIAL in line for line in said)


@needs_tomllib
def test_remove_keeps_a_gateway_env_that_was_there_and_the_operators_edits(gateway):
    paths = gateway.paths
    paths.gateway_env.write_text("RUST_LOG=info\n", encoding="utf-8")
    _up(gateway)
    with gateway.toml.open("a", encoding="utf-8") as handle:
        handle.write('\n[openshell.drivers.docker]\nimage_pull_policy = "always"\n')
    result = connect.remove(gateway.host(), out=lambda _s: None)
    assert result["gateway.toml"] == "kept-edits" and result["gateway.env"] == "restored"
    text = gateway.toml.read_text(encoding="utf-8")
    assert connect.BLOCK_BEGIN not in text and 'image_pull_policy = "always"' in text
    assert paths.gateway_env.read_text(encoding="utf-8") == "RUST_LOG=info\n"


@needs_tomllib
@pytest.mark.parametrize("failure", ["raises", 503])
def test_a_revoke_that_did_not_happen_is_kept_for_the_next_remove(gateway, failure):
    _up(gateway)
    if failure == "raises":
        gateway.revoke_raises = True
    else:
        gateway.revoke_status = failure
    said = []
    result = connect.remove(gateway.host(), out=said.append)
    assert result["credential"] == "NOT revoked"
    paths = gateway.paths
    assert paths.sidecar_env.exists() and paths.record.exists()
    assert "revoke-pending" in connect.Record.load(paths.record).data["steps"]
    assert "remove` again" in said[-1]

    gateway.revoke_raises, gateway.revoke_status = False, 401  # already revoked is revoked
    result = connect.remove(gateway.host(), out=lambda _s: None)
    assert result == {"gateway.toml": "no-block", "credential": "revoked"}
    assert not paths.sidecar_env.exists() and not paths.record.exists()


@needs_tomllib
def test_remove_can_leave_the_credential_live(gateway):
    _up(gateway)
    posts = len(gateway.posts)
    result = connect.remove(gateway.host(), keep_credential=True, out=lambda _s: None)
    assert "credential" not in result and len(gateway.posts) == posts
    assert not gateway.paths.sidecar_env.exists()


def test_remove_with_nothing_installed_does_nothing(gateway):
    said = []
    assert connect.remove(gateway.host(), out=said.append) == {"gateway.toml": "no-block"}
    assert gateway.posts == []


@needs_tomllib
def test_status_says_what_is_installed_and_holds_no_credential(gateway):
    before = connect.status(gateway.host())
    assert before["connected"] is False and before["registration_in_gateway_toml"] is False
    _up(gateway)
    after = connect.status(gateway.host())
    assert after == {
        "gateway_id": GATEWAY, "steps": after["steps"], "connected": True,
        "self_test_decision_id": DECISION, "self_test_receipt": RECEIPT, "credential_saved": True,
        "registration_in_gateway_toml": True, "drop_in": True, "sidecar_unit": True,
        "sidecar": "active", "sidecar_answers": True, "gateway": "active",
        "record_error": None, "reports": REPORTED, "break_glass": NO_WINDOW}
    assert CREDENTIAL not in json.dumps(after)


@needs_tomllib
def test_the_sidecar_lists_sandboxes_with_the_operators_own_cli(gateway):
    _up(gateway)
    assert connect._saved(gateway.paths)["OPENSHELL_SIDECAR_LIST_CLI"] == "/usr/bin/openshell"


@needs_tomllib
@pytest.mark.parametrize("where", ['/opt/my"tools/{name}', "bin/{name}"],
                         ids=["quote", "relative"])
def test_a_cli_path_systemd_cannot_carry_stops_up_before_the_token_is_spent(gateway, where):
    """A unit's environment has no working folder to resolve a relative path
    against, and cannot carry a quote."""
    host = gateway.host(which=lambda name: where.format(name=name))
    with pytest.raises(connect.ConnectError, match="OPENSHELL_SIDECAR_LIST_CLI"):
        connect.up(host, token=TOKEN, digest=DIGEST, out=lambda _s: None)
    assert gateway.posts == []


@needs_tomllib
def test_up_says_the_engine_has_the_gateways_heartbeat_and_inventory(gateway):
    record, said = _up(gateway)
    assert said[-1] == ("the engine has this gateway's heartbeat, and its inventory: "
                        "2 sandboxes")
    assert record["reports"] == REPORTED
    assert not any("within a minute" in line for line in said)


@needs_tomllib
def test_up_waits_for_the_first_reports(gateway):
    pending = {"reporting": True, "heartbeat": "pending", "inventory": "pending"}
    one = dict(REPORTED, sandboxes=1)
    gateway.reported = [pending, pending, dict(pending, heartbeat="ok"), one]
    record, said = _up(gateway)
    assert said[-1].endswith("its inventory: 1 sandbox")
    assert record["reports"] == one


@needs_tomllib
@pytest.mark.parametrize("reported, says", [
    ({"reporting": True, "heartbeat": "pending", "inventory": "pending"},
     "has not taken this gateway's heartbeat or its inventory yet"),
    ({"reporting": True, "heartbeat": "failed", "heartbeat_error": "ConnectionError",
      "inventory": "ok", "sandboxes": 0, "partial": False},
     "has not taken this gateway's heartbeat yet (ConnectionError)"),
    ({"reporting": False}, "the sidecar sends no heartbeat"),
    (None, "the sidecar did not say what it reported"),
], ids=["pending", "failed", "not-reporting", "no-answer"])
def test_reports_the_engine_has_not_taken_are_a_note_not_a_failure(gateway, monkeypatch,
                                                                   reported, says):
    gateway.reported = [reported]
    if reported is None:
        monkeypatch.setattr(gateway, "reports", lambda port, token="": None)
    host = gateway.host(reports=gateway.reports)
    said = []
    record = connect.up(host, token=TOKEN, digest=DIGEST, out=said.append)
    assert record["connected"] is True
    assert said[-1].startswith("note: ") and says in said[-1]
    assert "artzain connect openshell status" in said[-1]


@needs_tomllib
def test_a_partial_inventory_is_said_with_its_reason(gateway):
    gateway.reported = [dict(REPORTED, partial=True, listing_error="TimeoutExpired")]
    _record, said = _up(gateway)
    assert said[-1] == ("the engine has this gateway's heartbeat, and its inventory: "
                        "2 sandboxes, not every one (the listing failed: TimeoutExpired)")


@needs_tomllib
def test_a_listing_lost_while_the_gateway_restarts_is_not_what_up_reports(gateway, monkeypatch):
    """``up`` starts the sidecar, then restarts the gateway so it picks up the
    interceptor. The sidecar's first listing can land in that restart and
    fail once. It is tried again at once, and ``up`` says the whole inventory
    the engine took after the gateway was back."""
    sandbox = "1e04e83f-6de7-4f86-b466-2e945af3e724"
    calls = {"n": 0}

    def cli_list(_cli):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("gateway restarting")
        return [{"workspace": "default", "id": sandbox, "name": "box", "phase": "Ready"}]

    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_CLI", "/usr/bin/openshell")
    monkeypatch.setattr(sidecar, "cli_list", cli_list)
    clock = {"now": 0.0}
    posted = []

    def post(path, payload):
        posted.append((path.rsplit("/", 1)[-1], payload))
        return {}

    reporter = sidecar.Reporter(
        GatewayLedger(gateway_id=GATEWAY), post=post, clock=lambda: clock["now"],
        latency=sidecar.LatencyWindow(), undelivered=sidecar.Counter())

    def sleep(seconds):
        clock["now"] += seconds

    def reports(_port, _token=""):
        # The sidecar's loop has been running since the service started.
        reporter.step()
        return reporter.status()

    said = []
    record = connect.up(gateway.host(reports=reports, sleep=sleep), token=TOKEN,
                        digest=DIGEST, engine="https://engine.example/", out=said.append)
    inventories = [payload for name, payload in posted if name == "inventory"]
    assert calls["n"] >= 2 and inventories[0]["partial"] is True
    assert inventories[-1]["partial"] is False
    assert len(inventories[-1]["sandboxes"]) == 1
    assert said[-1] == ("the engine has this gateway's heartbeat, and its inventory: "
                        "1 sandbox")
    assert record["reports"]["partial"] is False and record["reports"]["sandboxes"] == 1


def test_the_sidecar_is_asked_on_loopback_and_never_through_a_proxy(monkeypatch):
    """A host behind a proxy sets ``HTTP_PROXY``; 127.0.0.1 is not the
    proxy's to answer."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Sidecar(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return None

        def do_GET(self):  # noqa: N802
            body = {"/healthz": {"ok": True}, "/artzain/reports": REPORTED}.get(self.path)
            raw = json.dumps(body).encode()
            self.send_response(200 if body else 404)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # nothing listens there
    server = ThreadingHTTPServer(("127.0.0.1", 0), Sidecar)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        assert connect._healthy(port) is True
        assert connect._reports(port) == REPORTED
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert connect._healthy(port) is False and connect._reports(port) is None


@pytest.mark.parametrize("answer", [{}, {"ok": False}, {"ok": "yes"}, [True]])
def test_a_port_that_answers_but_not_as_the_sidecar_is_not_healthy(answer):
    """Something else on the sidecar's port is not the sidecar."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Other(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return None

        def do_GET(self):  # noqa: N802
            raw = json.dumps(answer).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Other)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert connect._healthy(server.server_address[1]) is False
        assert connect._reports(server.server_address[1]) == (
            answer if isinstance(answer, dict) else None)
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_a_record_that_cannot_be_read_is_said(gateway):
    paths = gateway.paths
    paths.record.parent.mkdir(parents=True)
    paths.record.write_text("{not json", encoding="utf-8")
    assert "cannot be read" in connect.status(gateway.host())["record_error"]
    with pytest.raises(connect.ConnectError, match="cannot be read"):
        connect.remove(gateway.host(), out=lambda _s: None)


# ---------------------------------------------------------------------------
# rotate-key
# ---------------------------------------------------------------------------

KEYS = f"https://engine.example/api/v1/openshell/gateways/{GATEWAY}/keys"


def _key_calls(gateway):
    """``(route, the key it was sent with)`` for each call to the key routes."""
    names = {CREDENTIAL: "old", NEW_CREDENTIAL: "new"}
    return [(post["url"][len(KEYS):] or "/keys", names.get(post["headers"]["X-Api-Key"], "?"))
            for post in gateway.posts if post["url"].startswith(KEYS)]


@needs_tomllib
def test_rotate_key_swaps_the_credential_and_retires_the_old_one(gateway):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_text(encoding="utf-8")
    said = []
    result = connect.rotate_key(gateway.host(), out=said.append)
    after = gateway.paths.sidecar_env.read_text(encoding="utf-8")
    assert _settings_key(gateway.paths.sidecar_env) == NEW_CREDENTIAL
    # Only the credential line changed.
    assert after.replace(NEW_CREDENTIAL, CREDENTIAL) == before
    assert gateway.live_keys == [NEW_CREDENTIAL]
    assert _key_calls(gateway) == [("/retire-others", "old"), ("/keys", "old"),
                                   ("/retire-others", "new")]
    assert gateway.sidecar_restarts == 1
    assert result == {"gateway_id": GATEWAY, "rotated": True, "old_key_retired": True}
    record = json.loads(gateway.paths.record.read_text(encoding="utf-8"))
    assert record["key_rotated_at"] == int(gateway.wall_now)
    assert not any(CREDENTIAL in line or NEW_CREDENTIAL in line for line in said)
    assert "rotated" in said[-1]
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(gateway.paths.sidecar_env).st_mode) == 0o600


@needs_tomllib
def test_a_second_key_left_by_an_earlier_rotation_is_retired_first(gateway):
    _up(gateway)
    gateway.live_keys.append("cnxg_" + "s" * 43)  # minted, never put in use
    connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.live_keys == [NEW_CREDENTIAL]
    assert _key_calls(gateway)[0] == ("/retire-others", "old")


@needs_tomllib
def test_a_new_key_the_engine_does_not_take_is_undone(gateway, monkeypatch):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    real = gateway._keys

    def minted_but_dead(url, key):
        status, answer = real(url, key)
        if url.endswith("/keys"):
            gateway.live_keys.remove(NEW_CREDENTIAL)  # the engine will not take it
        return status, answer

    monkeypatch.setattr(gateway, "_keys", minted_but_dead)
    with pytest.raises(connect.ConnectError, match="back on the old credential"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.paths.sidecar_env.read_bytes() == before
    assert gateway.sidecar_restarts == 2
    assert _key_calls(gateway)[-1] == ("/retire-others", "old")
    assert gateway.live_keys == [CREDENTIAL]


@needs_tomllib
@pytest.mark.parametrize("status, says", [
    (401, "revoked"), (409, "two live keys"), (429, "wait"), (503, "run it again")])
def test_a_mint_the_engine_refuses_changes_nothing(gateway, status, says):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    gateway.mint_answer = (status, {"detail": "no"})
    with pytest.raises(connect.ConnectError, match=says):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.paths.sidecar_env.read_bytes() == before
    assert gateway.sidecar_restarts == 0


@needs_tomllib
@pytest.mark.parametrize("answer", [
    {"gateway_id": GATEWAY}, {"gateway_id": GATEWAY, "credential": "cnx_account_key_00000000"},
    {"gateway_id": GATEWAY, "credential": 'cnxg_"quoted"'}, ["not", "an", "object"],
    {"gateway_id": GATEWAY, "credential": CREDENTIAL}],
    ids=["none", "not-a-gateway-key", "unsafe", "not-an-object", "the-old-one"])
def test_an_answer_with_no_usable_credential_changes_nothing(gateway, answer):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    gateway.mint_answer = (200, answer)
    with pytest.raises(connect.ConnectError, match="no gateway credential"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.paths.sidecar_env.read_bytes() == before
    assert gateway.sidecar_restarts == 0
    # Whatever the engine minted, the key still in use takes it back.
    assert _key_calls(gateway)[-1] == ("/retire-others", "old")


@needs_tomllib
def test_a_heartbeat_that_is_never_taken_is_not_taken_as_working(gateway, monkeypatch):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    real = gateway.reports

    def pending_with_the_new_key(port, token=""):
        if _settings_key(gateway.paths.sidecar_env) == NEW_CREDENTIAL:
            return {"reporting": True, "heartbeat": "pending", "inventory": "pending"}
        return real(port, token)

    monkeypatch.setattr(gateway, "reports", pending_with_the_new_key)
    with pytest.raises(connect.ConnectError, match="back on the old credential"):
        connect.rotate_key(gateway.host(reports=pending_with_the_new_key), out=lambda _s: None)
    assert gateway.paths.sidecar_env.read_bytes() == before
    assert gateway.live_keys == [CREDENTIAL]


@needs_tomllib
def test_an_engine_that_cannot_be_reached_changes_nothing(gateway):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    gateway.key_raises = True
    with pytest.raises(connect.ConnectError, match="could not be reached"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.paths.sidecar_env.read_bytes() == before


@needs_tomllib
def test_an_old_key_that_could_not_be_retired_is_said_and_left_for_the_next_run(gateway):
    _up(gateway)
    real = gateway._keys
    calls = {"retire": 0}

    def last_retire_fails(url, key):
        if url.endswith("/retire-others"):
            calls["retire"] += 1
            if calls["retire"] == 2:
                return 503, {"detail": "down"}
        return real(url, key)

    gateway._keys = last_retire_fails
    said = []
    result = connect.rotate_key(gateway.host(), out=said.append)
    assert result["rotated"] is True and result["old_key_retired"] is False
    assert _settings_key(gateway.paths.sidecar_env) == NEW_CREDENTIAL
    assert "run `artzain connect openshell rotate-key` again" in said[-1]
    # The next run retires the old key with the new one first.
    gateway._keys = real
    connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert len(gateway.live_keys) == 1


@needs_tomllib
def test_rotate_key_waits_for_the_gateway_to_come_back(gateway):
    """The gateway requires the sidecar, so it restarts with it, and is
    `activating` for a while: the rotation ends once it is up again."""
    _up(gateway)
    gateway.gateway_after_sidecar_restart = ["activating", "activating", "active"]
    connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.units[connect.GATEWAY_UNIT] == "active"
    assert gateway.gateway_states == ["active"]  # every state was looked at


@needs_tomllib
def test_a_gateway_that_does_not_come_back_is_said(gateway):
    _up(gateway)
    gateway.gateway_after_sidecar_restart = ["failed"]
    with pytest.raises(connect.ConnectError, match="did not come back up") as stopped:
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert "the credential is rotated" in str(stopped.value)
    assert "journalctl --user -u openshell-gateway.service" in str(stopped.value)
    # The rotation itself was done: the new key is in use, the old one gone.
    assert _settings_key(gateway.paths.sidecar_env) == NEW_CREDENTIAL
    assert gateway.live_keys == [NEW_CREDENTIAL]


@needs_tomllib
def test_rotate_key_brings_an_older_sidecar_unit_up_to_date(gateway):
    """A sidecar connected by 0.6.36 runs as Type=simple, and its gateway
    raced its socket at every restart."""
    _up(gateway)
    unit = gateway.paths.sidecar_unit
    unit.write_text(unit.read_text(encoding="utf-8").replace(
        "Type=notify\nNotifyAccess=main\n", "Type=simple\n"), encoding="utf-8")
    calls = len(gateway.calls)
    connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert unit.read_text(encoding="utf-8") == connect.sidecar_unit(gateway.host(), gateway.paths)
    after = [" ".join(call[1:4]) for call in gateway.calls[calls:] if call[0] == "systemctl"]
    assert after.index("--user daemon-reload") < after.index(f"--user restart {connect.SIDECAR_UNIT}")


def test_rotate_key_needs_a_connected_gateway(gateway):
    with pytest.raises(connect.ConnectError, match="not connected"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert gateway.posts == []


@needs_tomllib
def test_rotate_key_waits_for_an_up_that_stopped_part_way(gateway):
    """A record that names its gateway but never passed the self-test: `up`
    is to be finished first."""
    _up(gateway)
    record = json.loads(gateway.paths.record.read_text(encoding="utf-8"))
    record["connected"] = False
    gateway.paths.record.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(connect.ConnectError, match="not connected"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert _key_calls(gateway) == []


@needs_tomllib
def test_settings_that_do_not_hold_one_credential_are_refused_before_the_engine_is_asked(gateway):
    _up(gateway)
    env = gateway.paths.sidecar_env
    env.write_bytes(env.read_bytes() + f'COGNEXUS_API_KEY="{CREDENTIAL}"\n'.encode())
    posts = len(gateway.posts)
    with pytest.raises(connect.ConnectError, match="one credential"):
        connect.rotate_key(gateway.host(), out=lambda _s: None)
    assert len(gateway.posts) == posts


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

CHECKS = ["record", "gateway", "sidecar", "credential", "socket", "drop_in", "registration",
          "versions", "cli", "engine", "clock", "reports"]


def _results(said):
    return {check["check"]: check["result"] for check in said["checks"]}


@needs_tomllib
def test_doctor_finds_nothing_wrong_with_a_gateway_up_bound(gateway):
    _up(gateway)
    said = connect.doctor(gateway.host())
    assert said["checks"][0]["says"] == (f"gateway {GATEWAY} is connected (self-test decision "
                                         f"{DECISION}, receipt {RECEIPT})")
    assert [check["check"] for check in said["checks"]] == CHECKS
    assert set(_results(said).values()) == {"ok"} and said["ok"] is True
    assert gateway.engine_gets == [{"url": "https://engine.example/health", "proxy": "",
                                    "ca_bundle": ""}]
    assert CREDENTIAL not in json.dumps(said)


@needs_tomllib
def test_doctor_asks_the_engine_the_way_the_sidecar_does(gateway, tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    _up(gateway, proxy="http://proxy.example:3128", ca_bundle=bundle.as_posix())
    connect.doctor(gateway.host())
    assert gateway.engine_gets == [{"url": "https://engine.example/health",
                                    "proxy": "http://proxy.example:3128",
                                    "ca_bundle": bundle.as_posix()}]


@needs_tomllib
def test_doctor_checks_the_registration_for_the_approved_timeout(gateway):
    config = dict(CONFIG, interceptor_timeout_ms=900, decide_timeout_ms=600)
    digest = connect.config_digest(config)
    gateway.redeem = (200, {"gateway_id": GATEWAY, "agent_did": f"openshell:{GATEWAY}",
                            "credential": CREDENTIAL, "key_prefix": CREDENTIAL[:12],
                            "config_digest": digest, "config": config})
    connect.up(gateway.host(), token=TOKEN, digest=digest, out=lambda _s: None)
    assert '"900ms"' in gateway.toml.read_text(encoding="utf-8")
    said = connect.doctor(gateway.host())
    assert set(_results(said).values()) == {"ok"}, said


def test_doctor_before_up_says_to_run_it(gateway):
    said = connect.doctor(gateway.host())
    assert said["ok"] is False
    record = said["checks"][0]
    assert record["check"] == "record" and record["result"] == "fail"
    assert "artzain connect openshell up" in record["says"]


def _edit(path, old, new):
    """Replace *old* once, keeping the file's line ends (``write_text`` would
    make them CRLF on Windows)."""
    data = path.read_bytes()
    assert old.encode() in data
    path.write_bytes(data.replace(old.encode(), new.encode(), 1))


def _move_digest(gateway):
    env = gateway.paths.sidecar_env
    digest = connect._saved(gateway.paths)["OPENSHELL_REGISTRATION_DIGEST"]
    _edit(env, digest, "0" * 64)


BREAKS = {
    "socket-gone": (lambda g: setattr(g, "socket_gone", True), "socket", "fail", "is missing"),
    "socket-mode": (lambda g: setattr(g, "socket_mode", 0o660), "socket", "fail", "0660"),
    "socket-folder": (lambda g: setattr(g, "socket_dir_mode", 0o755), "socket", "fail", "0755"),
    "socket-owner": (lambda g: setattr(g, "socket_uid", 0), "socket", "fail", "another user"),
    "not-a-socket": (lambda g: setattr(g, "socket_kind", stat.S_IFREG), "socket", "fail",
                     "not a socket"),
    "credential-mode": (lambda g: g.modes.update({"sidecar.env": 0o644}), "credential", "fail",
                        "0644"),
    "credential-gone": (lambda g: g.paths.sidecar_env.unlink(), "credential", "fail",
                        "holds no credential"),
    "credential-group": (lambda g: g.modes.update({"sidecar.env": 0o640}), "credential", "fail",
                         "0640"),
    "reports-partial": (lambda g: setattr(g, "reported", [
        dict(REPORTED, partial=True, listing_error="TimeoutExpired")]),
        "reports", "warn", "TimeoutExpired"),
    "sidecar-down": (lambda g: g.units.update({connect.SIDECAR_UNIT: "inactive"}), "sidecar",
                     "fail", "inactive"),
    "sidecar-silent": (lambda g: setattr(g, "silent", True), "sidecar", "fail",
                       "nothing answers"),
    "sidecar-not-the-service": (
        lambda g: (g.units.update({connect.SIDECAR_UNIT: "failed"}), setattr(g, "stray", True)),
        "sidecar", "fail", "is failed"),
    "gateway-down": (lambda g: g.units.update({connect.GATEWAY_UNIT: "failed"}), "gateway",
                     "fail", "failed"),
    "drop-in-gone": (lambda g: g.paths.dropin.unlink(), "drop_in", "fail", "50-artzain.conf"),
    "block-edited": (lambda g: _edit(g.toml, '"1500ms"', '"900ms"'), "registration", "fail",
                     "gateway.toml"),
    "digest-moved": (_move_digest, "registration", "fail", "sidecar"),
    "upgraded": (lambda g: setattr(g, "version", "openshell-gateway 0.2.0"), "versions", "fail",
                 "0.2.0"),
    "cli-unregistered": (lambda g: setattr(g, "cli_reaches", False), "cli", "fail",
                         "openshell gateway add"),
    "engine-down": (lambda g: setattr(g, "engine_raises", True), "engine", "fail", "OSError"),
    "engine-5xx": (lambda g: setattr(g, "engine_status", 503), "engine", "fail", "503"),
    "clock-drift": (lambda g: setattr(g, "engine_skew", 120.0), "clock", "warn", "120"),
    "clock-off": (lambda g: setattr(g, "engine_skew", -900.0), "clock", "fail", "900"),
    "reports-pending": (lambda g: setattr(g, "reported", [
        {"reporting": True, "heartbeat": "pending", "inventory": "pending"}]),
        "reports", "warn", "not yet"),
    "reports-failed": (lambda g: setattr(g, "reported", [
        dict(REPORTED, heartbeat="failed", heartbeat_error="ConnectionError")]),
        "reports", "fail", "ConnectionError"),
    "not-reporting": (lambda g: setattr(g, "reported", [{"reporting": False}]), "reports",
                      "fail", "no gateway credential"),
}


@needs_tomllib
@pytest.mark.parametrize("name", sorted(BREAKS))
def test_doctor_names_what_is_wrong(gateway, name):
    breaks, check, result, says = BREAKS[name]
    _up(gateway)
    breaks(gateway)
    said = connect.doctor(gateway.host())
    found = next(item for item in said["checks"] if item["check"] == check)
    assert found["result"] == result and says in found["says"], found
    assert said["ok"] is (result != "fail")
    if result == "warn":  # nothing else is wrong
        assert [c for c in said["checks"] if c["result"] != "ok"] == [found]


def test_the_engine_is_asked_for_its_health_and_its_time(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    asked = []

    class Engine(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return None

        def do_GET(self):  # noqa: N802
            asked.append(self.path)
            raw = b'{"status": "healthy"}'
            self.send_response(200)  # with a Date header
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    for name in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")  # not the sidecar's proxy setting
    server = ThreadingHTTPServer(("127.0.0.1", 0), Engine)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers = connect._get_engine(f"http://127.0.0.1:{server.server_address[1]}/health")
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert status == 200 and asked == ["/health"]
    assert connect._engine_time(headers["Date"]) is not None


def test_a_proxy_password_is_never_said():
    assert connect._through("http://user:s3cret@proxy.example:3128") == (
        " through the proxy proxy.example:3128")
    assert connect._through("env") == " through the environment's proxy"
    assert connect._through("") == ""
    assert connect._origin("https://user:pw@engine.example:8443/api/v1/decisions") == (
        "https://engine.example:8443")


@needs_tomllib
def test_doctor_does_not_say_the_proxy_password(gateway):
    _up(gateway, proxy="http://user:s3cret@proxy.example:3128")
    gateway.engine_raises = True
    said = connect.doctor(gateway.host())
    assert "s3cret" not in json.dumps(said)
    engine = next(c for c in said["checks"] if c["check"] == "engine")
    assert "proxy.example:3128" in engine["says"]


@needs_tomllib
def test_doctor_compares_no_clock_when_the_engine_does_not_answer(gateway):
    _up(gateway)
    gateway.engine_raises = True
    clock = next(c for c in connect.doctor(gateway.host())["checks"] if c["check"] == "clock")
    assert clock["result"] == "warn" and "no time" in clock["says"]


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_the_command_takes_the_token_from_the_environment_only(monkeypatch):
    from artzain import cli

    seen = {}

    def up(host, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(connect, "up", up)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setenv("ARTZAIN_ENROLL_TOKEN", f"  {TOKEN}  ")
    cli.main(["connect", "openshell", "up", "--config-digest", DIGEST.upper(),
              "--engine", "https://engine.example", "--proxy", "env", "--port", "8090"])
    assert seen == {"token": TOKEN, "digest": DIGEST, "engine": "https://engine.example",
                    "proxy": "env", "ca_bundle": "", "port": 8090,
                    "install_openshell": False, "ask": None}
    with pytest.raises(SystemExit):
        cli.main(["connect", "openshell", "up", "--token", TOKEN])


def test_a_refusal_ends_the_command_with_its_reason(monkeypatch):
    from artzain import cli

    def up(host, **kwargs):
        raise connect.ConnectError("the enroll token expired")

    monkeypatch.setattr(connect, "up", up)
    with pytest.raises(SystemExit) as stopped:
        cli.main(["connect", "openshell", "up"])
    assert str(stopped.value) == "artzain connect openshell up: the enroll token expired"


_DIAGNOSED = {"ok": False, "checks": [
    {"check": "socket", "result": "fail", "says": "the socket is 0660: group can connect"},
    {"check": "clock", "result": "warn", "says": "this host's clock is 120 s off"},
    {"check": "engine", "result": "ok", "says": "https://engine.example answers"}]}


def test_doctor_prints_each_check_and_fails_when_one_does(monkeypatch, capsys):
    from artzain import cli

    monkeypatch.setattr(connect, "doctor", lambda host: _DIAGNOSED)
    with pytest.raises(SystemExit) as stopped:
        cli.main(["connect", "openshell", "doctor"])
    assert stopped.value.code == 1
    assert capsys.readouterr().out.splitlines() == [
        "FAIL  socket        the socket is 0660: group can connect",
        "warn  clock         this host's clock is 120 s off",
        "ok    engine        https://engine.example answers"]


def test_rotate_key_runs_from_the_command_line(monkeypatch):
    from artzain import cli

    seen = []
    monkeypatch.setattr(connect, "rotate_key", lambda host, **kw: seen.append(host) or {})
    cli.main(["connect", "openshell", "rotate-key"])
    assert len(seen) == 1

    def refused(host, **kw):
        raise connect.ConnectError("too many rotations in an hour")

    monkeypatch.setattr(connect, "rotate_key", refused)
    with pytest.raises(SystemExit) as stopped:
        cli.main(["connect", "openshell", "rotate-key"])
    assert str(stopped.value) == "artzain connect openshell rotate-key: too many rotations in an hour"


def test_doctor_with_only_warnings_succeeds_and_can_print_json(monkeypatch, capsys):
    from artzain import cli

    warned = {"ok": True, "checks": _DIAGNOSED["checks"][1:]}
    monkeypatch.setattr(connect, "doctor", lambda host: warned)
    cli.main(["connect", "openshell", "doctor", "--json"])
    assert json.loads(capsys.readouterr().out) == warned


# ---------------------------------------------------------------------------
# The sidecar's token, and the engine over HTTPS (0.6.41)
# ---------------------------------------------------------------------------


def _without_token(path, *names):
    names = names or ("OPENSHELL_SIDECAR_TOKEN",)
    text = path.read_text(encoding="utf-8")
    kept = "".join(line for line in text.splitlines(keepends=True)
                   if not line.startswith(tuple(name + "=" for name in names)))
    path.write_text(kept, encoding="utf-8")
    return kept


@needs_tomllib
def test_up_again_brings_a_pre_0_6_41_sidecars_settings_up_to_date(gateway):
    """0.6.40 wrote neither the token nor where gateway.toml is: `up` again
    adds both, keeps the rest, and restarts the sidecar once."""
    _up(gateway)
    env = gateway.paths.sidecar_env
    kept = _without_token(env, "OPENSHELL_SIDECAR_TOKEN", "OPENSHELL_GATEWAY_TOML")
    restart = ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]
    restarts = gateway.commands("systemctl").count(restart)
    said = []
    connect.up(gateway.host(), out=said.append, engine="https://engine.example/")
    assert _settings_value(env, "OPENSHELL_GATEWAY_TOML") == gateway.paths.gateway_toml.as_posix()
    assert len(_settings_value(env, "OPENSHELL_SIDECAR_TOKEN")) >= 43
    assert env.read_text(encoding="utf-8").startswith(kept)
    assert gateway.commands("systemctl").count(restart) == restarts + 1
    assert any("gateway.toml" in line for line in said), said


VENV_PYTHON = "/home/op/.local/share/artzain/openshell/venv-0.6.41/bin/python"


@needs_tomllib
def test_up_from_another_environment_moves_the_service_there(gateway):
    """The connect script of 0.6.41 installs artzain into an environment of
    its own and runs `up` from there: the sidecar's unit is rewritten to run
    from it, and the sidecar restarts once (the gateway with it). The uv
    tool the earlier script installed can then go."""
    _up(gateway)
    restart = ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]
    restarts = gateway.commands("systemctl").count(restart)
    reloads = gateway.commands("systemctl").count(["systemctl", "--user", "daemon-reload"])
    said = []
    connect.up(gateway.host(executable=VENV_PYTHON), out=said.append,
               engine="https://engine.example/")
    unit = gateway.paths.sidecar_unit.read_text(encoding="utf-8")
    assert f'ExecStart="{VENV_PYTHON}" -m artzain.cli openshell sidecar' in unit
    assert gateway.commands("systemctl").count(restart) == restarts + 1
    assert gateway.commands("systemctl").count(
        ["systemctl", "--user", "daemon-reload"]) == reloads + 1
    assert any("sidecar" in line and "restart" in line for line in said), said


@needs_tomllib
def test_a_gateway_that_does_not_come_back_after_the_move_stops_up(gateway):
    _up(gateway)
    gateway.gateway_after_sidecar_restart = ["failed"]
    with pytest.raises(connect.ConnectError, match="did not stay up"):
        connect.up(gateway.host(executable=VENV_PYTHON), out=lambda _s: None,
                   engine="https://engine.example/")


@needs_tomllib
def test_settings_and_environment_brought_up_to_date_restart_the_sidecar_once(gateway):
    _up(gateway)
    _without_token(gateway.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN", "OPENSHELL_GATEWAY_TOML")
    restart = ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]
    restarts = gateway.commands("systemctl").count(restart)
    connect.up(gateway.host(executable=VENV_PYTHON), out=lambda _s: None,
               engine="https://engine.example/")
    assert gateway.commands("systemctl").count(restart) == restarts + 1
    assert _settings_value(gateway.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
    assert VENV_PYTHON in gateway.paths.sidecar_unit.read_text(encoding="utf-8")


@needs_tomllib
def test_up_again_on_an_up_to_date_sidecar_changes_nothing(gateway):
    _up(gateway)
    before = gateway.paths.sidecar_env.read_bytes()
    restart = ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]
    restarts = gateway.commands("systemctl").count(restart)
    connect.up(gateway.host(), out=lambda _s: None, engine="https://engine.example/")
    assert gateway.paths.sidecar_env.read_bytes() == before
    assert gateway.commands("systemctl").count(restart) == restarts


@needs_tomllib
def test_the_sidecar_watches_the_registration_up_wrote(gateway):
    """What the heartbeat reports from gateway.toml is the digest the
    sidecar was installed for, until someone changes the file."""
    _up(gateway)
    env, toml = gateway.paths.sidecar_env, gateway.paths.gateway_toml
    installed = _settings_value(env, "OPENSHELL_REGISTRATION_DIGEST")
    assert sidecar.registration_found(_settings_value(env, "OPENSHELL_GATEWAY_TOML")) == installed
    toml.write_bytes(connect.strip_block(toml.read_bytes()))
    assert sidecar.registration_found(toml.as_posix()) == "missing"


@needs_tomllib
def test_up_gives_the_sidecar_a_token_of_its_own(gateway):
    """The sidecar speaks for the gateway, so its loopback routes answer
    only a caller with its token; `up` writes one beside the credential."""
    record, _said = _up(gateway)
    token = _settings_value(gateway.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
    assert len(token) >= 43 and token.replace("-", "").replace("_", "").isalnum()
    assert token not in (CREDENTIAL, TOKEN)
    # It reads the sidecar's reports with it.
    assert record["reports"] == REPORTED
    assert connect.status(gateway.host())["reports"] == REPORTED


@needs_tomllib
def test_up_again_gives_a_sidecar_connected_before_the_token_one(gateway):
    """A gateway connected by 0.6.40 or earlier has no token: running `up`
    again with this artzain adds one, keeps every other setting as it was,
    and restarts the sidecar so it takes it."""
    _up(gateway)
    kept = _without_token(gateway.paths.sidecar_env)
    restarts = gateway.commands("systemctl").count(
        ["systemctl", "--user", "restart", connect.SIDECAR_UNIT])
    said = []
    record = connect.up(gateway.host(), out=said.append, engine="https://engine.example/")
    after = gateway.paths.sidecar_env.read_text(encoding="utf-8")
    token = _settings_value(gateway.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
    assert len(token) >= 43
    assert [line for line in after.splitlines()
            if not line.startswith("OPENSHELL_SIDECAR_TOKEN=")] == kept.splitlines()
    assert gateway.commands("systemctl").count(
        ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]) == restarts + 1
    assert record["reports"] == REPORTED
    assert any("token" in line for line in said), said
    assert token not in "\n".join(said)


@needs_tomllib
def test_doctor_says_when_the_sidecar_has_no_token(gateway):
    _up(gateway)
    _without_token(gateway.paths.sidecar_env)
    said = connect.doctor(gateway.host())
    found = next(item for item in said["checks"] if item["check"] == "credential")
    assert found["result"] == "fail", found
    assert "OPENSHELL_SIDECAR_TOKEN" in found["says"]
    assert "artzain connect openshell up" in found["says"]
    assert said["ok"] is False


def test_the_sidecars_reports_are_asked_with_its_token(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    asked = []

    class Sidecar(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return None

        def do_GET(self):  # noqa: N802
            asked.append((self.path, self.headers.get("Authorization")))
            raw = json.dumps(REPORTED).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Sidecar)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        assert connect._reports(port, "sidecar-secret") == REPORTED
        connect._healthy(port)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert asked == [("/artzain/reports", "Bearer sidecar-secret"), ("/healthz", None)]


@pytest.mark.parametrize("engine", ["http://engine.example", "http://10.0.0.5:8000",
                                    "HTTP://engine.example"])
def test_the_enroll_token_never_goes_to_an_engine_over_plain_http(gateway, engine):
    with pytest.raises(connect.ConnectError, match="https"):
        connect.redeem(gateway.host(), engine=engine, token=TOKEN, digest=DIGEST)
    assert gateway.posts == []


@pytest.mark.parametrize("engine", ["http://127.0.0.1:8000", "http://localhost:8000",
                                    "http://[::1]:8000", "https://engine.example"])
def test_an_engine_on_this_host_may_be_plain_http(gateway, engine):
    connect.redeem(gateway.host(), engine=engine, token=TOKEN, digest=DIGEST)
    assert gateway.posts[0]["url"].startswith(engine)


@pytest.mark.parametrize("url, refused", [("http://engine.example", True),
                                          ("http://192.168.1.4:8000", True),
                                          ("http://127.0.0.1:8000", False),
                                          ("https://engine.example", False)])
def test_a_configuration_that_sends_decisions_over_plain_http_is_refused(url, refused):
    """The sidecar sends the gateway's credential to the decision URL."""
    config = dict(CONFIG, decision_url=url)
    if refused:
        with pytest.raises(connect.ConnectError, match="https"):
            connect.parse_config(config)
    else:
        assert connect.parse_config(config).decision_url == url
