"""``artzain connect openshell`` on NVIDIA's OpenShell Homebrew formula.

On a Mac with Apple silicon, the formula installs ``openshell`` and
``openshell-gateway``, and ``brew services`` runs the gateway as a launchd
agent of the user, through the formula's wrapper. The wrapper reads the
user's own ``~/.config/openshell/gateway.toml`` when there is one, and else
the formula's ``var/openshell/gateway.toml``; it sources ``gateway.env``
the same way, and copies the gateway's JWT bundle to
``~/.local/state/openshell/homebrew/tls`` at each start.

These run ``up``, ``remove``, ``status``, ``doctor`` and ``rotate-key``
against :class:`_BrewHost`, which plays Homebrew (``brew`` and ``brew
services``), launchd (``launchctl``), the formula's wrapper and gateway, the
``openshell`` CLI, and an engine to redeem at.

What has to hold:

* the registration goes into the ``gateway.toml`` the wrapper reads, and
  the telemetry choice into the ``gateway.env`` it sources; ``up`` creates
  neither in Homebrew's own folders;
* the sidecar is a launchd agent of the user's, loaded again from its file
  whenever it restarts (launchd does not reread a loaded agent's file);
* launchd has no start order: a gateway restarted before the sidecar
  answers is started again until it does, and ``up`` waits for that;
* ``doctor`` fails when the wrapper now reads another ``gateway.toml``,
  which runs the gateway unbound;
* ``remove`` puts back the files the record names.
"""

from __future__ import annotations

import email.utils
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from artzain.openshell import brew, connect

pytestmark = [
    pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML"),
    # The Homebrew shape is a Mac's, and writes POSIX paths into its agent.
    pytest.mark.skipif(sys.platform == "win32", reason="the Homebrew shape is a Mac's"),
]

GATEWAY = "gw_01ABCDEFGHJKMNPQRSTVWXYZ00"
CREDENTIAL = "cnxg_" + "k" * 43
NEW_CREDENTIAL = "cnxg_" + "n" * 43
TOKEN = "cnxt_" + "t" * 43
DECISION = "01JBCDEFGHJKMNPQRSTVWXYZ00"
CONFIG = {"kind": "artzain.openshell.connect", "version": 1,
          "decision_url": "https://engine.example", "openshell_version": "0.1.3",
          "interceptor_timeout_ms": 1500, "decide_timeout_ms": 1200, "telemetry": False}
DIGEST = connect.config_digest(CONFIG)
REPORTED = {"reporting": True, "heartbeat": "ok", "inventory": "ok", "sandboxes": 1,
            "partial": False}
UID, GID = 501, 20
PYTHON = "/Users/op/.local/share/uv/tools/artzain/bin/python"
#: What the formula's post_install writes.
FORMULA_TOML = b"[openshell]\nversion = 2\n\n[openshell.gateway]\n"
DECIDING = re.compile(r'grpc_endpoint\s*=\s*"(unix://[^"]+)"')
#: The state folders the fake Macs made, removed after each test.
_STATE_FOLDERS: list = []


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def _stat(mode, uid):
    return os.stat_result((mode, 0, 0, 1, uid, GID, 0, 0, 0, 0))


def _settings_value(path, name):
    if not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip('"')
    return ""


@pytest.fixture(autouse=True)
def _state_folders_removed():
    yield
    while _STATE_FOLDERS:
        shutil.rmtree(_STATE_FOLDERS.pop(), ignore_errors=True)


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


class _BrewHost:
    """A Mac with Homebrew, NVIDIA's openshell formula (its gateway started
    with ``brew services``), launchd, and an engine."""

    def __init__(self, tmp_path: Path, user: str = "op"):
        self.home = tmp_path / "Users" / user
        self.home.mkdir(parents=True)
        # The socket is under XDG_STATE_HOME, and a socket's path holds 103
        # bytes: a short folder, as /Users/<name>/.local/state is (pytest's
        # own temporary folders are longer).
        self.state = Path(tempfile.mkdtemp(prefix="brew-"))
        _STATE_FOLDERS.append(self.state)
        self.prefix = tmp_path / "opt" / "homebrew"
        self.var = self.prefix / "var" / "openshell"
        self.var.mkdir(parents=True)
        (self.var / "gateway.toml").write_bytes(FORMULA_TOML)
        self.installed = True
        self.version = "0.1.3"
        self.cli_reaches = True
        self.preflight_ok = True
        #: How many CLI calls fail after the gateway (re)starts: launchd
        #: starts it again until the sidecar answers.
        self.answer_after = 0
        self.unanswered = 0
        self.calls: list = []
        self.posts: list = []
        self.live_keys = [CREDENTIAL]
        self.settings = {"proposal_approval_mode": "<unset>"}
        self.gateway_running = True
        self.agents: dict = {}            # label -> the plist launchd loaded
        #: The sidecar's agent is loaded, and its process has exited.
        self.sidecar_exited = False
        #: How many bootstraps after a bootout fail while launchd is still
        #: taking the old agent out.
        self.tearing_down = 0
        self.torn_down = 0
        #: How many ``launchctl print`` calls after a bootout still show the
        #: agent: launchd takes it out after ``bootout`` returns.
        self.lingering = 0
        self.lingers = 0
        #: launchd refuses the agent's file outright (exit, message).
        self.refused = None
        self.bound = False
        self.telemetry = None
        self.wall_now = 1_800_000_000.0
        self.jwt.parent.mkdir(parents=True)
        self.jwt.write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                            encoding="utf-8")

    # --- where things are ------------------------------------------------
    @property
    def xdg(self) -> Path:
        return self.home / ".config" / "openshell"

    @property
    def jwt(self) -> Path:
        return self.home / ".local" / "state" / "openshell" / "homebrew" / "tls" / "jwt" / "public.pem"

    @property
    def socket(self) -> Path:
        return self.state / "artzain" / "openshell" / "run" / "openshell.sock"

    @property
    def agent_file(self) -> Path:
        return self.home / "Library" / "LaunchAgents" / f"{brew.LABEL}.plist"

    @property
    def sidecar_env(self) -> Path:
        return self.home / ".config" / "artzain" / "openshell" / "sidecar.env"

    def read_by_wrapper(self, name: str) -> Path:
        """The file the formula's wrapper reads: the user's own, else the
        formula's."""
        return self.xdg / name if (self.xdg / name).exists() else self.var / name

    # --- commands -----------------------------------------------------------
    def which(self, name):
        if name in ("brew", "openshell", "openshell-gateway"):
            return f"{self.prefix}/bin/{name}"
        if name == "launchctl":
            return "/bin/launchctl"
        return None

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        name, args = argv[0], argv[1:]
        if name == "brew":
            return self._brew(args)
        if name == "launchctl":
            return self._launchctl(args)
        if name == "openshell-gateway":
            return self._gateway(args)
        if name == "openshell":
            return self._cli(args)
        raise AssertionError(f"unexpected command {argv}")

    def _brew(self, args):
        if args == ["list", "--formula", "--versions", "openshell"]:
            if not self.installed:
                return _done(1, "", "Error: No such keg: /opt/homebrew/Cellar/openshell\n")
            return _done(0, f"openshell {self.version}\n")
        if args == ["--prefix"]:
            return _done(0, f"{self.prefix}\n")
        if args == ["services", "info", "openshell", "--json"]:
            return _done(0, json.dumps([{"name": "openshell", "service_name": "sh.brew.openshell",
                                         "running": self.gateway_running, "loaded": True}]))
        if args == ["services", "restart", "openshell"]:
            self._gateway_restart()
            return _done(0, "==> Successfully started `openshell` (label: sh.brew.openshell)\n")
        raise AssertionError(f"unexpected brew {args}")

    def _launchctl(self, args):
        if args[0] == "bootstrap":
            assert args[1] == f"gui/{UID}", args
            path = Path(args[2])
            if self.refused:
                return _done(self.refused[0], "", self.refused[1])
            with open(path, "rb") as handle:
                loaded = plistlib.load(handle)  # a file launchd cannot read fails here
            label = loaded["Label"]
            if label in self.agents or self.torn_down:
                self.torn_down = max(self.torn_down - 1, 0)
                return _done(5, "", "Bootstrap failed: 5: Input/output error\n")
            self.agents[label] = loaded
            self.socket.parent.mkdir(parents=True, exist_ok=True)
            return _done()
        if args[0] == "bootout":
            label = args[1].rsplit("/", 1)[1]
            if self.agents.pop(label, None) is None:
                return _done(3, "", "Boot-out failed: 3: No such process\n")
            self.torn_down = self.tearing_down
            self.lingers = self.lingering
            return _done()
        if args[0] == "print":
            label = args[1].rsplit("/", 1)[1]
            if self.lingers and label not in self.agents:
                self.lingers -= 1
                return _done(0, f"{args[1]} = {{\n\tactive count = 0\n\tstate = exiting\n}}\n")
            if label not in self.agents:
                return _done(113, "", f"Could not find service \"{label}\" in domain\n")
            state = "not running" if self.sidecar_exited else "running"
            return _done(0, f"{args[1]} = {{\n\tactive count = 1\n\tstate = {state}\n}}\n")
        raise AssertionError(f"unexpected launchctl {args}")

    def _gateway(self, args):
        if args == ["--version"]:
            return _done(0, f"openshell-gateway {self.version}\n")
        if args[:3] == ["config", "preflight", "--path"]:
            if not self.preflight_ok:
                return _done(1, "", "configuration error: interceptor name collides")
            import tomllib  # 3.11 on; the module skips on 3.10

            data = tomllib.loads(Path(args[3]).read_text(encoding="utf-8"))
            return _done(0 if data["openshell"]["version"] == 2 else 1)
        raise AssertionError(f"unexpected openshell-gateway {args}")

    def _gateway_restart(self):
        """The wrapper starts the gateway with the files it reads now. One
        registered with an interceptor that does not answer exits, and
        launchd starts it again (the formula keeps it alive)."""
        text = self.read_by_wrapper("gateway.toml").read_text(encoding="utf-8")
        env = self.read_by_wrapper("gateway.env")
        found = re.search(r"OPENSHELL_TELEMETRY_ENABLED=(\w+)",
                          env.read_text(encoding="utf-8") if env.exists() else "")
        self.telemetry = found.group(1) if found else None
        endpoint = DECIDING.search(text)
        registered = connect.BLOCK_BEGIN in text and endpoint is not None
        reaches = registered and endpoint.group(1) == f"unix://{self.socket.as_posix()}"
        self.gateway_running = not registered or (brew.LABEL in self.agents and reaches)
        self.bound = registered and self.gateway_running
        self.unanswered = self.answer_after

    def _cli(self, args):
        if not self.cli_reaches or not self.gateway_running:
            return _done(1, "", "Error: tcp connect error")
        if self.unanswered:
            self.unanswered -= 1
            return _done(1, "", "Error: tcp connect error: Connection refused")
        if args[:2] == ["settings", "set"]:
            assert "--yes" in args
            key, value = args[args.index("--key") + 1], args[args.index("--value") + 1]
            if self.bound and value == "auto":
                return _done(1, "", "status: PermissionDenied, message: \"gateway interceptor "
                                    f"'artzain' denied the request: decision deny ({DECISION})\"")
            self.settings[key] = value
            return _done(0, "Updated global setting\n")
        if args[:2] == ["settings", "get"]:
            return _done(0, "".join(f"  {key} = {value}\n" for key, value in self.settings.items()))
        raise AssertionError(f"unexpected openshell {args}")

    # --- the sidecar, the socket, the engine ----------------------------------
    def healthy(self, port):
        return brew.LABEL in self.agents and not self.sidecar_exited

    def reports(self, port, token=""):
        return dict(REPORTED) if self.healthy(port) else None

    def stat(self, path):
        path = Path(path)
        if path == self.socket:
            if not self.healthy(0):
                raise FileNotFoundError(str(path))
            return _stat(stat.S_IFSOCK | 0o600, UID)
        if path == self.socket.parent:
            return _stat(stat.S_IFDIR | 0o700, UID)
        real = os.stat(path)
        return _stat(stat.S_IFMT(real.st_mode) | 0o600, UID)

    def get_engine(self, url, *, proxy="", ca_bundle=""):
        return 200, {"Date": email.utils.formatdate(self.wall_now, usegmt=True)}

    def post_json(self, url, *, headers, body, proxy="", ca_bundle=""):
        self.posts.append(url)
        if url.endswith(connect.REDEEM_PATH):
            return 200, {"gateway_id": GATEWAY, "credential": CREDENTIAL,
                         "config_digest": DIGEST, "config": CONFIG}
        if url.endswith("/revoke"):
            return 200, {"revoked": True}
        key = headers["X-Api-Key"]
        if key not in self.live_keys:
            return 401, {}
        if url.endswith("/keys/retire-others"):
            self.live_keys = [key]
            return 200, {"retired": 1}
        if url.endswith("/keys"):
            self.live_keys.append(NEW_CREDENTIAL)
            return 200, {"credential": NEW_CREDENTIAL}
        raise AssertionError(url)

    def host(self, **overrides) -> connect.Host:
        settings = dict(
            environ={"HOME": str(self.home), "PATH": f"{self.prefix}/bin:/usr/bin:/bin",
                     "XDG_STATE_HOME": str(self.state)},
            runner=self.run, healthy=self.healthy, reports=self.reports,
            break_glass=lambda port, token="": None, stat=self.stat,
            get_engine=self.get_engine, wall=lambda: self.wall_now, post_json=self.post_json,
            which=self.which, sleep=lambda _s: None, clock=_Clock(), platform="darwin",
            executable=PYTHON, uid=UID, gid=GID)
        settings.update(overrides)
        return connect.Host(**settings)

    def up(self, **overrides):
        return connect.up(self.host(**overrides), token=TOKEN, digest=DIGEST,
                          engine="https://engine.example", out=lambda _s: None)

    def launchctl(self, reads=False):
        """The launchctl verbs run, in order; with *reads*, ``print`` too."""
        return [call[1] for call in self.calls
                if call[0] == "launchctl" and (reads or call[1] != "print")]


@pytest.fixture
def mac(tmp_path):
    return _BrewHost(tmp_path)


def _doctor(host):
    said = connect.doctor(host.host())
    return said, {check["check"]: check for check in said["checks"]}


# ---------------------------------------------------------------------------
# What the formula is
# ---------------------------------------------------------------------------


def test_the_formula_says_its_prefix_release_and_the_files_its_wrapper_reads(mac):
    found = brew.find(mac.host())
    assert (found.prefix, found.version) == (mac.prefix, "0.1.3")
    # The formula's gateway.toml; and no gateway.env yet, so the user's own,
    # which `up` creates (never one in Homebrew's folders).
    assert found.gateway_toml == mac.var / "gateway.toml"
    assert found.gateway_env == mac.xdg / "gateway.env"


def test_the_users_own_files_are_the_ones_the_wrapper_reads(mac):
    (mac.var / "gateway.env").write_text("OPENSHELL_COMPUTE_DRIVER=vm\n", encoding="utf-8")
    assert brew.find(mac.host()).gateway_env == mac.var / "gateway.env"
    mac.xdg.mkdir(parents=True)
    (mac.xdg / "gateway.toml").write_bytes(FORMULA_TOML)
    (mac.xdg / "gateway.env").write_text("", encoding="utf-8")
    found = brew.find(mac.host())
    assert (found.gateway_toml, found.gateway_env) == (mac.xdg / "gateway.toml",
                                                       mac.xdg / "gateway.env")


def test_a_mac_is_the_homebrew_shape(mac):
    shape = connect.detect(mac.host())
    paths = shape.paths
    assert (shape.kind, shape.openshell_version) == (connect.SHAPE_HOMEBREW, "0.1.3")
    assert paths.manager == "launchd" and paths.dropins == ()
    assert paths.sidecar_unit == mac.agent_file
    # A Mac has no XDG_RUNTIME_DIR: the socket is in a folder of the user's.
    assert paths.socket == mac.socket
    assert paths.gateway_service == "openshell"


def test_a_mac_without_the_formula_is_refused_before_the_token(mac):
    mac.installed = False
    assert brew.find(mac.host()) is None
    with pytest.raises(connect.ConnectError, match="no OpenShell gateway from NVIDIA's Homebrew"):
        mac.up()
    assert mac.posts == []


@pytest.mark.parametrize("line", ["export OPENSHELL_GATEWAY_CONFIG=/tmp/mine.toml",
                                  "  OPENSHELL_GATEWAY_CONFIG=/tmp/mine.toml"],
                         ids=["export", "set -a"])
def test_a_gateway_env_that_names_another_config_is_refused(mac, line):
    """The wrapper sources gateway.env (with ``set -a``) before it starts the
    gateway: with OPENSHELL_GATEWAY_CONFIG set there, the gateway reads that
    file, and a registration in the file `up` would change governs nothing."""
    (mac.var / "gateway.env").write_text(f"OPENSHELL_COMPUTE_DRIVER=vm\n{line}\n",
                                         encoding="utf-8")
    with pytest.raises(connect.ConnectError, match="sets OPENSHELL_GATEWAY_CONFIG"):
        mac.up()
    assert mac.posts == []


def test_root_is_refused_on_a_mac(mac):
    with pytest.raises(connect.ConnectError, match="not as root"):
        mac.up(uid=0)
    assert mac.posts == []


def test_the_formulas_tools_must_be_on_path(mac):
    def which(name):
        return None if name == "openshell-gateway" else mac.which(name)

    with pytest.raises(connect.ConnectError, match="openshell-gateway is not on PATH: Homebrew"):
        mac.up(which=which)
    assert mac.posts == []


def test_a_cli_that_cannot_reach_the_formulas_gateway_stops_before_the_token(mac):
    mac.cli_reaches = False
    with pytest.raises(connect.ConnectError,
                       match=r"start it \(brew services start openshell\).*gateway add "
                             r"https://localhost:17670 --local --name openshell"):
        mac.up()
    assert mac.posts == []


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


def test_up_binds_the_formulas_gateway(mac):
    record = mac.up()
    assert record["connected"] and record["self_test_decision_id"] == DECISION
    assert record["shape"] == connect.SHAPE_HOMEBREW
    assert record["homebrew"] == {"prefix": mac.prefix.as_posix(), "version": "0.1.3",
                                  "gateway_toml": (mac.var / "gateway.toml").as_posix(),
                                  "gateway_env": (mac.xdg / "gateway.env").as_posix()}
    assert mac.bound and mac.gateway_running
    # The registration is in the file the wrapper reads, and names the socket.
    toml = mac.var / "gateway.toml"
    assert toml.read_bytes().startswith(FORMULA_TOML)
    assert DECIDING.findall(toml.read_text(encoding="utf-8")) == [
        f"unix://{mac.socket.as_posix()}"] * 2
    assert not (mac.xdg / "gateway.toml").exists()


@pytest.mark.parametrize("telemetry", [False, True])
def test_the_telemetry_choice_reaches_the_gateway_through_the_env_it_sources(
        tmp_path, telemetry, monkeypatch):
    mac = _BrewHost(tmp_path)
    monkeypatch.setitem(CONFIG, "telemetry", telemetry)
    monkeypatch.setattr(sys.modules[__name__], "DIGEST", connect.config_digest(CONFIG))
    connect.up(mac.host(), token=TOKEN, digest=connect.config_digest(CONFIG),
               engine="https://engine.example", out=lambda _s: None)
    assert mac.telemetry == str(telemetry).lower()
    # In the user's own gateway.env: Homebrew's folder keeps its mode.
    env = mac.xdg / "gateway.env"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert not (mac.var / "gateway.env").exists()


def test_a_gateway_env_of_the_formulas_takes_the_choice_in_place(mac):
    mine = b"OPENSHELL_COMPUTE_DRIVER=vm\n"
    (mac.var / "gateway.env").write_bytes(mine)
    os.chmod(mac.var, 0o755)
    mac.up()
    assert (mac.var / "gateway.env").read_bytes().startswith(mine)
    assert mac.telemetry == "false"
    assert not (mac.xdg / "gateway.env").exists()
    assert stat.S_IMODE(mac.var.stat().st_mode) == 0o755


def test_the_sidecar_is_a_launchd_agent_that_reads_its_settings(mac):
    mac.up()
    with open(mac.agent_file, "rb") as handle:
        agent = plistlib.load(handle)
    assert agent["Label"] == brew.LABEL
    assert agent["ProgramArguments"] == [
        "/bin/sh", "-c",
        f'set -a; . "{mac.sidecar_env.as_posix()}"; set +a; '
        f'exec "{PYTHON}" -m artzain.cli openshell sidecar']
    assert agent["RunAtLoad"] is True and agent["KeepAlive"] is True
    assert agent["Umask"] == 0o077
    assert agent["StandardErrorPath"] == (
        mac.home / "Library" / "Logs" / "artzain-openshell-sidecar.log").as_posix()
    # launchd loaded it from its file, in the user's own domain.
    assert mac.agents[brew.LABEL] == agent


def test_a_home_with_an_ampersand_still_makes_an_agent_launchd_reads(tmp_path):
    """The agent is XML: a path with ``&`` or ``<`` in it is escaped."""
    mac = _BrewHost(tmp_path, user="R&D<lab>")
    mac.up()
    with open(mac.agent_file, "rb") as handle:
        agent = plistlib.load(handle)
    assert f'. "{mac.sidecar_env.as_posix()}"' in agent["ProgramArguments"][2]
    assert agent["StandardErrorPath"].startswith(mac.home.as_posix())


@pytest.mark.parametrize("state, says", [
    ("with space", "no space"),
    ("x" * 80, "at most 103 bytes"),
], ids=["space", "long"])
def test_a_socket_path_the_gateway_cannot_connect_to_is_refused_before_the_token(
        mac, state, says):
    """A Mac has no XDG_RUNTIME_DIR: the socket is under the user's state
    folder, and a socket's path holds 103 bytes, in a registration that
    takes no space."""
    environ = {"HOME": str(mac.home), "PATH": "/usr/bin",
               "XDG_STATE_HOME": str(mac.state / state)}
    with pytest.raises(connect.ConnectError, match=says):
        mac.up(environ=environ)
    assert mac.posts == []


@pytest.mark.parametrize("python", ["/Users/op/$HOME/bin/python", "bin/python",
                                    '/Users/op/"x"/bin/python'])
def test_a_python_an_agent_cannot_name_is_refused_before_the_token(mac, python):
    with pytest.raises(connect.ConnectError, match="a launchd agent cannot name"):
        mac.up(executable=python)
    assert mac.posts == []


def test_the_settings_are_ones_sh_reads_as_they_are_written(mac):
    """The agent sources sidecar.env with sh: each value is quoted, and holds
    nothing sh would expand."""
    mac.up()
    done = subprocess.run(
        ["sh", "-c", f'set -a; . "{mac.sidecar_env.as_posix()}"; set +a; '
                     'printf "%s\\n" "$OPENSHELL_SIDECAR_GRPC" "$COGNEXUS_API_KEY"'],
        capture_output=True, text=True, check=True, env={"PATH": os.environ.get("PATH", "")})
    assert done.stdout.splitlines() == [f"unix://{mac.socket.as_posix()}", CREDENTIAL]


def test_the_sidecar_checks_the_formula_gateways_signed_calls(mac):
    mac.up()
    assert _settings_value(mac.sidecar_env, "OPENSHELL_JWT_PUBLIC_KEY") == mac.jwt.as_posix()
    assert _settings_value(mac.sidecar_env, "OPENSHELL_JWT_GATEWAY_ID") == "openshell"
    assert _settings_value(mac.sidecar_env, "OPENSHELL_GATEWAY_TOML") == (
        (mac.var / "gateway.toml").as_posix())
    assert _settings_value(mac.sidecar_env, "OPENSHELL_SIDECAR_GRPC") == (
        f"unix://{mac.socket.as_posix()}")
    assert _settings_value(mac.sidecar_env, "OPENSHELL_SIDECAR_LIST_CLI") == (
        f"{mac.prefix}/bin/openshell")


def test_a_gateway_toml_that_names_its_key_is_followed(mac):
    key = mac.home / "keys" / "gateway.pem"
    (mac.var / "gateway.toml").write_bytes(
        FORMULA_TOML + b"\n[openshell.gateway.gateway_jwt]\n"
        + f'public_key_path = "{key.as_posix()}"\ngateway_id = "mine"\n'.encode())
    mac.up()
    assert _settings_value(mac.sidecar_env, "OPENSHELL_JWT_PUBLIC_KEY") == key.as_posix()
    assert _settings_value(mac.sidecar_env, "OPENSHELL_JWT_GATEWAY_ID") == "mine"


def test_without_the_gateways_key_the_sidecar_does_not_check(mac):
    mac.jwt.unlink()
    mac.up()
    assert not _settings_value(mac.sidecar_env, "OPENSHELL_JWT_PUBLIC_KEY")


def test_the_preflight_runs_the_formulas_gateway_on_the_file_as_it_would_be(mac):
    mac.up()
    runs = [call for call in mac.calls if call[:3] == ["openshell-gateway", "config", "preflight"]]
    assert runs == [["openshell-gateway", "config", "preflight", "--path",
                     (mac.home / ".config" / "artzain" / "openshell"
                      / "gateway.toml.candidate").as_posix()]]


def test_a_preflight_that_fails_leaves_gateway_toml_alone(mac):
    mac.preflight_ok = False
    with pytest.raises(connect.ConnectError, match="preflight"):
        mac.up()
    assert (mac.var / "gateway.toml").read_bytes() == FORMULA_TOML
    assert not mac.bound


def test_up_waits_for_the_gateway_launchd_starts_again(mac):
    """launchd starts the two agents in no order: the gateway it restarts
    answers once it has found the sidecar."""
    mac.answer_after = 3
    record = mac.up()
    assert record["connected"]
    restart = mac.calls.index(["brew", "services", "restart", "openshell"])
    tries = [call for call in mac.calls[restart:] if call[:2] == ["openshell", "settings"]]
    assert len(tries) >= 4


def test_a_gateway_that_never_answers_stops_up(mac):
    mac.answer_after = 10_000
    with pytest.raises(connect.ConnectError, match="cannot reach it: see `brew services info"):
        mac.up()
    assert "connected" not in json.loads(
        (mac.home / ".config" / "artzain" / "openshell" / "connect.json").read_text())


def test_a_loaded_agent_is_taken_out_before_its_new_file_is_loaded(mac):
    mac.agents[brew.LABEL] = {"Label": brew.LABEL, "ProgramArguments": ["/old/python"]}
    mac.up()
    assert mac.agents[brew.LABEL]["ProgramArguments"][0] == "/bin/sh"
    assert mac.launchctl()[:2] == ["bootout", "bootstrap"]


def test_a_bootstrap_while_launchd_still_takes_the_agent_out_is_tried_again(mac):
    """``launchctl bootout`` can return before launchd has taken the agent
    out; a ``bootstrap`` meanwhile fails with error 5."""
    mac.up()
    mac.tearing_down = 3
    mac.calls.clear()
    mac.up(executable="/Users/op/.local/share/uv/tools/artzain-new/bin/python")
    assert mac.launchctl() == ["bootout"] + ["bootstrap"] * 4
    assert brew.LABEL in mac.agents


def test_the_agent_is_loaded_again_once_launchd_has_taken_the_old_one_out(mac):
    mac.up()
    mac.lingering = 3
    mac.calls.clear()
    mac.up(executable="/Users/op/.local/share/uv/tools/artzain-new/bin/python")
    assert mac.launchctl(reads=True)[:6] == ["bootout"] + ["print"] * 4 + ["bootstrap"]
    assert mac.lingers == 0


def test_a_restart_stops_when_launchd_keeps_the_old_agent(mac):
    mac.up()
    mac.lingering = 10_000
    mac.calls.clear()
    with pytest.raises(connect.ConnectError, match=f"launchd still has gui/{UID}/{brew.LABEL}"):
        mac.up(executable="/Users/op/.local/share/uv/tools/artzain-new/bin/python")
    assert "bootstrap" not in mac.launchctl()


def test_a_bootstrap_launchd_refuses_otherwise_is_said_at_once(mac):
    mac.up()
    mac.refused = (78, "Bootstrap failed: 78: Function not implemented\n")
    mac.calls.clear()
    with pytest.raises(connect.ConnectError, match="failed .exit 78.: Bootstrap failed: 78"):
        mac.up(executable="/Users/op/.local/share/uv/tools/artzain-new/bin/python")
    assert mac.launchctl() == ["bootout", "bootstrap"]


def test_a_bootstrap_that_keeps_failing_is_said(mac):
    mac.up()
    mac.tearing_down = 10_000
    with pytest.raises(connect.ConnectError, match="restarting artzain-openshell-sidecar.service "
                                                   "failed .*Input/output error"):
        mac.up(executable="/Users/op/.local/share/uv/tools/artzain-new/bin/python")


def test_up_again_on_a_bound_gateway_changes_nothing(mac):
    mac.up()
    before = (mac.var / "gateway.toml").read_bytes()
    mac.calls.clear()
    record = mac.up()
    assert record["connected"] and (mac.var / "gateway.toml").read_bytes() == before
    assert mac.launchctl() == [] and ["brew", "services", "restart", "openshell"] not in mac.calls


def test_up_with_another_artzain_loads_the_agent_again_from_its_file(mac):
    """launchd does not reread a loaded agent's file: the sidecar restarts
    from the new one, not as it was loaded."""
    mac.up()
    other = "/Users/op/.local/share/uv/tools/artzain-new/bin/python"
    mac.calls.clear()
    mac.up(executable=other)
    assert mac.launchctl() == ["bootout", "bootstrap"]
    assert f'exec "{other}"' in mac.agents[brew.LABEL]["ProgramArguments"][2]


# ---------------------------------------------------------------------------
# status, doctor
# ---------------------------------------------------------------------------


def test_status_says_the_agent_and_both_services(mac):
    mac.up()
    said = connect.status(mac.host())
    assert said["shape"] == connect.SHAPE_HOMEBREW
    assert said["launch_agent"] and said["registration_in_gateway_toml"]
    assert (said["gateway"], said["sidecar"]) == ("active", "active")
    mac.sidecar_exited = True
    mac.gateway_running = False
    said = connect.status(mac.host())
    assert (said["gateway"], said["sidecar"]) == ("failed", "failed")
    mac.agents.clear()
    assert connect.status(mac.host())["sidecar"] == "inactive"


def test_doctor_finds_a_bound_formula_gateway_well(mac):
    mac.up()
    said, checks = _doctor(mac)
    assert said["ok"], said["checks"]
    assert checks["homebrew"]["result"] == "ok"
    assert checks["launch_agent"]["result"] == "ok" and "drop_in" not in checks
    assert checks["gateway"]["says"] == "openshell is active"
    assert checks["versions"]["result"] == "ok"


def test_doctor_fails_when_the_gateway_is_down_and_the_sidecar_up(mac):
    mac.up()
    mac.gateway_running = False
    said, checks = _doctor(mac)
    assert not said["ok"]
    assert checks["gateway"] == {"check": "gateway", "result": "fail",
                                 "says": "openshell is failed"}
    assert checks["sidecar"]["result"] == "ok"
    assert "gateway add https://localhost:17670 --local" in checks["cli"]["says"]


def test_a_bound_mac_keeps_the_files_its_record_names(mac):
    """Once bound, every verb works on the files `up` changed, even when
    the wrapper would read others now: `remove` puts those back, and
    `doctor` says the gateway runs unbound."""
    mac.up()
    mac.xdg.mkdir(parents=True, exist_ok=True)
    (mac.xdg / "gateway.toml").write_bytes(FORMULA_TOML)
    paths = connect.detect(mac.host()).paths
    assert paths.gateway_toml == mac.var / "gateway.toml"


def test_doctor_fails_when_the_wrapper_now_reads_the_users_own_gateway_toml(mac):
    mac.up()
    mac.xdg.mkdir(parents=True, exist_ok=True)
    (mac.xdg / "gateway.toml").write_bytes(FORMULA_TOML)
    said, checks = _doctor(mac)
    assert not said["ok"] and checks["homebrew"]["result"] == "fail"
    assert f"now reads {mac.xdg / 'gateway.toml'}" in checks["homebrew"]["says"]


def test_doctor_warns_when_the_wrapper_now_sources_another_gateway_env(tmp_path):
    mac = _BrewHost(tmp_path)
    (mac.var / "gateway.env").write_bytes(b"OPENSHELL_COMPUTE_DRIVER=vm\n")
    mac.up()
    mac.xdg.mkdir(parents=True, exist_ok=True)
    (mac.xdg / "gateway.env").write_bytes(b"")
    _said, checks = _doctor(mac)
    assert checks["homebrew"]["result"] == "warn"


def test_doctor_fails_without_the_sidecars_agent(mac):
    mac.up()
    mac.agent_file.unlink()
    said, checks = _doctor(mac)
    assert not said["ok"] and checks["launch_agent"]["result"] == "fail"


def test_doctor_fails_when_the_formula_is_gone(mac):
    mac.up()
    mac.installed = False
    said, checks = _doctor(mac)
    assert not said["ok"] and checks["homebrew"]["says"] == (
        "NVIDIA's openshell formula is not installed")


# ---------------------------------------------------------------------------
# remove, rotate-key
# ---------------------------------------------------------------------------


def test_remove_puts_the_formulas_gateway_back_unbound(mac):
    mac.up()
    result = connect.remove(mac.host(), out=lambda _s: None)
    assert (mac.var / "gateway.toml").read_bytes() == FORMULA_TOML
    assert result["gateway.toml"] == "restored" and result["gateway"] == "restarted unbound"
    assert not (mac.xdg / "gateway.env").exists() and result["gateway.env"] == "removed"
    assert brew.LABEL not in mac.agents and not mac.agent_file.exists()
    assert result["sidecar"] == "removed"
    assert not mac.bound and mac.gateway_running
    assert not mac.socket.parent.exists()
    assert not mac.sidecar_env.exists() and result["credential"] == "revoked"


def test_remove_restores_the_users_own_gateway_toml(mac):
    mac.xdg.mkdir(parents=True)
    mine = b'[openshell]\nversion = 2\n\n[openshell.gateway]\nlog_level = "debug"\n'
    (mac.xdg / "gateway.toml").write_bytes(mine)
    record = mac.up()
    assert record["homebrew"]["gateway_toml"] == (mac.xdg / "gateway.toml").as_posix()
    assert (mac.xdg / "gateway.toml").read_bytes().startswith(mine)
    result = connect.remove(mac.host(), out=lambda _s: None)
    assert result["gateway.toml"] == "restored"
    assert (mac.xdg / "gateway.toml").read_bytes() == mine
    assert (mac.var / "gateway.toml").read_bytes() == FORMULA_TOML


def test_remove_puts_back_the_files_up_changed_even_when_others_are_read_now(mac):
    mac.up()
    mac.xdg.mkdir(parents=True, exist_ok=True)
    mine = b"[openshell]\nversion = 2\n"
    (mac.xdg / "gateway.toml").write_bytes(mine)
    connect.remove(mac.host(), out=lambda _s: None)
    assert (mac.var / "gateway.toml").read_bytes() == FORMULA_TOML
    assert (mac.xdg / "gateway.toml").read_bytes() == mine


def test_remove_waits_until_launchd_has_taken_the_agent_out(mac):
    """``launchctl bootout`` returns while launchd still takes the agent
    out: ``remove`` is done once launchd no longer has it."""
    mac.up()
    mac.lingering = 3
    mac.calls.clear()
    result = connect.remove(mac.host(), out=lambda _s: None)
    assert result["sidecar"] == "removed" and mac.lingers == 0
    assert mac.launchctl(reads=True) == ["bootout"] + ["print"] * 4


def test_an_agent_launchd_keeps_is_said_by_remove(mac):
    mac.up()
    mac.lingering = 10_000
    result = connect.remove(mac.host(), out=lambda _s: None)
    assert result["sidecar"] == (f"NOT taken out of launchd: run `launchctl bootout "
                                 f"gui/{UID}/{brew.LABEL}`")
    assert not mac.agent_file.exists()


def test_rotate_key_loads_the_sidecar_again_with_the_new_credential(mac):
    mac.up()
    mac.calls.clear()
    said = connect.rotate_key(mac.host(), out=lambda _s: None)
    assert said["rotated"] and said["old_key_retired"]
    assert mac.launchctl() == ["bootout", "bootstrap"]
    assert _settings_value(mac.sidecar_env, "COGNEXUS_API_KEY") == NEW_CREDENTIAL


# ---------------------------------------------------------------------------
# launchd, as connect drives it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", [("daemon-reload",), ("reset-failed", "openshell")])
def test_what_launchd_has_no_need_of_is_done_without_a_command(mac, verb):
    assert brew.ctl(mac.host(), "openshell", *verb).returncode == 0
    assert mac.calls == []


def test_a_systemctl_verb_launchd_has_no_form_of_is_refused(mac):
    with pytest.raises(ValueError, match="no launchd form"):
        brew.ctl(mac.host(), "openshell", "stop", "openshell")
