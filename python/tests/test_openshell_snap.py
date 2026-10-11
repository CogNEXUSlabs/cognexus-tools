"""``artzain connect openshell`` on NVIDIA's OpenShell snap.

The snap runs its gateway in one of two modes. In 0.1.3, and in 0.1.4's
``system`` mode, it is a root service of the snap (``openshell.gateway``,
then ``openshell.system-gateway``), with ``gateway.toml`` and its keys in
``/var/snap/openshell/common``. In 0.1.4's ``user`` mode, a fresh install's
default, it is a snap user service (``openshell.user-gateway``) with its
files under ``~/snap/openshell/common``. The snap's AppArmor profile lets
the gateway connect to a socket only in the snap's own folders.

These run ``up``, ``remove``, ``status``, ``doctor`` and ``rotate-key``
against :class:`_SnapHost`, which plays snapd, systemd (the system manager
and the user's), ``sudo``, the snap's own preflight, the snap's ``openshell``
CLI, and an engine to redeem at.

What has to hold:

* the sidecar's socket is where the snap's profile lets the gateway connect,
  and the sidecar's unit can run the snap's CLI (no ``NoNewPrivileges``);
* in system mode, what is root's is written through ``sudo`` and the system
  manager runs the sidecar as the operator; in user mode, nothing but the
  refresh hold needs root;
* the gateway's drop-in carries its telemetry choice (the snap's gateway
  reads no ``gateway.env``), and a system gateway gets one for each name its
  app has had, so a refresh from 0.1.3 to 0.1.4 keeps it bound;
* the snap's refreshes are held, and ``remove`` lifts only a hold ``up`` put;
* ``doctor`` fails when the snap now runs its gateway in another mode, which
  reads another ``gateway.toml`` and so runs unbound.
"""

from __future__ import annotations

import email.utils
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from artzain.openshell import connect, snap

pytestmark = [
    pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML"),
    # The snap shape runs on Linux, and writes POSIX paths into systemd units.
    pytest.mark.skipif(sys.platform == "win32", reason="the snap shape is Linux's"),
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
UID, GID = 1000, 1000
PYTHON = "/home/op/.local/share/uv/tools/artzain/bin/python"

#: The snap's services, as ``snap services openshell`` lists them, by layout.
SERVICES = {
    "0.1.3": "Service            Startup  Current  Notes\n"
             "openshell.gateway  enabled  active   -\n",
    "system": "Service                   Startup   Current  Notes\n"
              "openshell.system-gateway  enabled   active   -\n"
              "openshell.user-gateway    disabled  -        user\n",
    "user": "Service                   Startup   Current   Notes\n"
            "openshell.system-gateway  disabled  inactive  -\n"
            "openshell.user-gateway    enabled   -         user\n",
    "disable": "Service                   Startup   Current   Notes\n"
               "openshell.system-gateway  disabled  inactive  -\n"
               "openshell.user-gateway    disabled  -         user\n",
}
#: ``(version, revision)`` of the snap a layout comes from.
RELEASES = {"0.1.3": ("0.1.3", "1909"), "system": ("0.1.4", "2001"),
            "user": ("0.1.4", "2001"), "disable": ("0.1.4", "2001")}
DECIDING = re.compile(r'grpc_endpoint\s*=\s*"(unix://[^"]+)"')


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


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


class _SnapHost:
    """A host with NVIDIA's OpenShell snap in *layout* (``0.1.3``,
    ``system`` or ``user``), Docker, systemd, sudo, and an engine."""

    def __init__(self, tmp_path: Path, layout: str = "0.1.3", *, held: bool = False):
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.root = tmp_path / "root"
        self.runtime = tmp_path / "run" / "user" / str(UID)
        self.runtime.mkdir(parents=True)
        self.layout = layout
        self.version, self.revision = RELEASES[layout]
        self.held = held
        self.installed = True
        self.cli_reaches = True
        self.preflight_ok = True
        #: systemd gave up on the gateway (five failed starts): a restart is
        #: refused until the unit's failed state is reset.
        self.start_limited = False
        self.calls: list = []
        self.posts: list = []
        self.live_keys = [CREDENTIAL]
        self.settings = {"proposal_approval_mode": "<unset>"}
        self.units = {}            # unit -> "active" | "inactive" | "failed"
        self.bound = False
        self.wall_now = 1_800_000_000.0
        common = self.common
        jwt = common / "tls" / "jwt" if self.system else (
            self.home / "snap" / "openshell" / "common" / ".local" / "state" / "openshell"
            / "tls" / "jwt")
        jwt.mkdir(parents=True)
        (jwt / "public.pem").write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n"
                                        "-----END PUBLIC KEY-----\n", encoding="utf-8")
        self.units[self.gateway_unit] = "active"

    # --- the layout -------------------------------------------------------
    @property
    def system(self) -> bool:
        return self.layout in ("0.1.3", "system")

    @property
    def app(self) -> str:
        return {"0.1.3": "gateway", "system": "system-gateway"}.get(self.layout, "user-gateway")

    @property
    def gateway_unit(self) -> str:
        return f"snap.openshell.{self.app}.service"

    @property
    def common(self) -> Path:
        return self.root / "var" / "snap" / "openshell" / "common"

    @property
    def toml(self) -> Path:
        if self.system:
            return self.common / "gateway.toml"
        return self.home / "snap" / "openshell" / "common" / ".config" / "openshell" / "gateway.toml"

    @property
    def unit_dir(self) -> Path:
        return (self.root / "etc" / "systemd" / "system" if self.system
                else self.home / ".config" / "systemd" / "user")

    @property
    def socket(self) -> Path:
        return (self.common / "artzain" / "openshell.sock" if self.system
                else self.runtime / "snap.openshell" / "artzain" / "openshell.sock")

    @property
    def paths(self) -> connect.Layout:
        return connect.layout(self.host())

    @property
    def sidecar_env(self) -> Path:
        return self.home / ".config" / "artzain" / "openshell" / "sidecar.env"

    def refresh_to(self, layout: str) -> None:
        """``snap refresh`` to another release: 0.1.3's ``gateway`` app is
        gone from 0.1.4, which runs ``system-gateway`` with the same files."""
        old = self.gateway_unit
        self.layout = layout
        self.version, self.revision = RELEASES[layout]
        self.units.pop(old, None)
        self.units[self.gateway_unit] = "active"

    # --- commands -----------------------------------------------------------
    def which(self, name):
        if name == "openshell":
            return "/snap/bin/openshell"
        if name in ("openshell-gateway", "docker"):
            return None
        return f"/usr/bin/{name}"

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        if argv[0] == "sudo":
            return self._as_root(argv[1:])
        name, args = argv[0], argv[1:]
        if name == "snap":
            return self._snap(args, root=False)
        if name == "systemctl":
            user = args[:1] == ["--user"]
            return self._systemctl(args[1:] if user else args, user=user, root=False)
        if name == "openshell":
            return self._cli(args)
        raise AssertionError(f"unexpected command {argv}")

    def _as_root(self, argv):
        name, args = argv[0], argv[1:]
        if name == "snap":
            return self._snap(args, root=True)
        if name == "systemctl":
            assert args[:1] != ["--user"], "sudo systemctl --user"
            return self._systemctl(args, user=False, root=True)
        if name == "install":
            assert args[:8] == ["-D", "-m", args[2], "-o", "root", "-g", "root", "--"], args
            source, dest = Path(args[8]), Path(args[9])
            assert str(dest).startswith(str(self.root)), f"sudo install outside the root: {dest}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
            os.chmod(dest, int(args[2], 8))
            return _done()
        if name == "rm":
            target = Path(argv[-1])
            if "-rf" in args:
                shutil.rmtree(target, ignore_errors=True)
            elif target.exists():
                target.unlink()
            return _done()
        if name == "rmdir":
            target = Path(argv[-1])
            if target.is_dir() and not any(target.iterdir()):
                target.rmdir()
            return _done()
        if name == "test" and args[0] == "-s":
            path = Path(args[1])
            return _done(0 if path.is_file() and path.stat().st_size else 1)
        if name == "cat":
            return _done(0, Path(argv[-1]).read_text(encoding="utf-8"))
        raise AssertionError(f"unexpected sudo command {argv}")

    def _snap(self, args, *, root):
        if args[:2] == ["list", "openshell"]:
            if not self.installed:
                return _done(1, "", "error: no matching snaps installed\n")
            notes = "held" if self.held else "-"
            return _done(0, "Name       Version  Rev   Tracking  Publisher                Notes\n"
                            f"openshell  {self.version}    {self.revision}  -         "
                            f"nvidia-snap-publisher**  {notes}\n")
        if args[:2] == ["services", "openshell"]:
            # snapd 2.77's `snap services` takes neither of `snap list`'s
            # --unicode and --color.
            flags = [arg for arg in args[2:] if arg.startswith(("--unicode", "--color"))]
            if flags:
                return _done(1, "", f"error: unknown flag `{flags[0][2:].split('=')[0]}'\n")
            return _done(0, SERVICES[self.layout])
        if args[:2] == ["refresh", "--hold"]:
            assert root, "a refresh hold needs root"
            self.held = True
            return _done(0, 'General refreshes of "openshell" held indefinitely\n')
        if args[:2] == ["refresh", "--unhold"]:
            assert root
            self.held = False
            return _done(0, 'Removed general refresh hold of "openshell"\n')
        if args[:2] == ["run", "--shell"]:
            # The gateway's own preflight, inside the snap as its gateway app.
            assert args[2] == f"openshell.{self.app}", args
            assert root == self.system, "the system gateway's app runs as root, the user's not"
            path = Path(args[4].rsplit("--path ", 1)[1])
            reach = self.common if self.system else self.home / "snap" / "openshell" / "common"
            if not str(path).startswith(str(reach)):
                return _done(1, "", f"Permission denied: {path}")  # AppArmor
            if not self.preflight_ok:
                return _done(1, "", "configuration error: interceptor name collides")
            import tomllib  # 3.11 on; the module skips on 3.10

            data = tomllib.loads(path.read_text(encoding="utf-8"))
            return _done(0 if data["openshell"]["version"] == 2 else 1)
        raise AssertionError(f"unexpected snap {args}")

    def _systemctl(self, args, *, user, root):
        system_units = (self.root / "etc" / "systemd" / "system")
        manager_is_system = not user
        if manager_is_system != self.system:
            unit = args[-1] if args else ""
            if unit.startswith(("snap.openshell", connect.SIDECAR_UNIT)):
                return _done(1, "", f"Unit {unit} not loaded.")
        if args[0] == "is-active":
            return _done(0, self.units.get(args[1], "inactive") + "\n")
        assert root or user, f"systemctl {args[0]} on the system manager without sudo"
        if args[0] == "reset-failed":
            if args[1:] == [self.gateway_unit]:
                self.start_limited = False
            return _done()
        if args[0] == "daemon-reload":
            return _done()
        if args[:2] == ["enable", "--now"] or args[0] == "restart" and args[1] == connect.SIDECAR_UNIT:
            unit = args[-1]
            assert unit == connect.SIDECAR_UNIT
            text = ((system_units if manager_is_system else self.unit_dir) / unit).read_text(
                encoding="utf-8")
            assert "NoNewPrivileges" not in text.replace("No NoNewPrivileges", "")
            self.units[unit] = "active"
            if manager_is_system:
                # ExecStartPre, as root: the socket's folder, and the key's copy.
                self.socket.parent.mkdir(parents=True, exist_ok=True)
                key = self.common / "tls" / "jwt" / "public.pem"
                if key.exists():
                    shutil.copyfile(key, self.socket.parent / "gateway-jwt.pem")
            else:
                self.socket.parent.mkdir(parents=True, exist_ok=True)
            if args[0] == "restart":
                self._gateway_restart()  # it requires the sidecar
            return _done()
        if args[:2] == ["disable", "--now"]:
            self.units[args[2]] = "inactive"
            return _done()
        if args[0] == "restart" and args[1] == self.gateway_unit:
            if self.start_limited:
                return _done(1, "", f"Job for {args[1]} failed: start request repeated too "
                                    "quickly.")
            self._gateway_restart()
            return _done()
        raise AssertionError(f"unexpected systemctl {args}")

    def _gateway_restart(self):
        text = self.toml.read_text(encoding="utf-8") if self.toml.exists() else ""
        found = DECIDING.search(text)
        registered = connect.BLOCK_BEGIN in text and found is not None
        up = self.units.get(connect.SIDECAR_UNIT) == "active"
        reaches = registered and found.group(1) == f"unix://{self.socket.as_posix()}"
        state = "failed" if registered and not (up and reaches) else "active"
        self.units[self.gateway_unit] = state
        self.bound = registered and state == "active"

    def _cli(self, args):
        if not self.cli_reaches:
            return _done(1, "", "Error: tcp connect error")
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
        return self.units.get(connect.SIDECAR_UNIT) == "active"

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
            environ={"HOME": str(self.home), "XDG_RUNTIME_DIR": str(self.runtime),
                     "PATH": "/usr/bin:/snap/bin"},
            root=str(self.root), runner=self.run, healthy=self.healthy, reports=self.reports,
            break_glass=lambda port, token="": None, stat=self.stat,
            get_engine=self.get_engine, wall=lambda: self.wall_now, post_json=self.post_json,
            which=self.which, sleep=lambda _s: None, clock=_Clock(), platform="linux",
            executable=PYTHON, uid=UID, gid=GID)
        settings.update(overrides)
        return connect.Host(**settings)

    def up(self, **overrides):
        return connect.up(self.host(**overrides), token=TOKEN, digest=DIGEST,
                          engine="https://engine.example", out=lambda _s: None)

    def sudo(self):
        """The commands run as root, each as its first words."""
        return [call[1:4] for call in self.calls if call[0] == "sudo"]


@pytest.fixture(params=["0.1.3", "system", "user"])
def any_snap(request, tmp_path):
    return _SnapHost(tmp_path, request.param)


@pytest.fixture
def system(tmp_path):
    return _SnapHost(tmp_path, "0.1.3")


@pytest.fixture
def user(tmp_path):
    return _SnapHost(tmp_path, "user")


# ---------------------------------------------------------------------------
# What the snap is
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout, mode, app", [
    ("0.1.3", "system", "gateway"),
    ("system", "system", "system-gateway"),
    ("user", "user", "user-gateway"),
])
def test_the_snap_says_its_mode_and_release(tmp_path, layout, mode, app):
    host = _SnapHost(tmp_path, layout, held=True)
    found = snap.find(host.host())
    assert (found.mode, found.app, found.version, found.revision, found.held) == (
        mode, app, *RELEASES[layout], True)
    assert found.unit == f"snap.openshell.{app}.service"


def test_a_snap_that_runs_no_gateway_is_refused(tmp_path):
    host = _SnapHost(tmp_path, "disable")
    with pytest.raises(connect.ConnectError, match="runs no gateway.*gateway-mode=user"):
        connect.up(host.host(), token=TOKEN, digest=DIGEST, out=lambda _s: None)
    assert host.posts == []


def test_no_snap_means_another_shape(tmp_path):
    host = _SnapHost(tmp_path)
    host.installed = False
    assert snap.find(host.host()) is None


def test_the_system_gateway_is_bound_where_its_profile_lets_it_connect(system):
    shape = connect.detect(system.host())
    paths = shape.paths
    assert (shape.kind, shape.openshell_version) == (connect.SHAPE_SNAP, "0.1.3")
    assert paths.gateway_toml == system.common / "gateway.toml"
    # The snap's AppArmor profile refuses /run/user/<uid>/artzain and
    # /run/artzain: the socket is in the snap's own folder.
    assert paths.socket == system.common / "artzain" / "openshell.sock"
    assert paths.system and paths.gateway_service == "snap.openshell.gateway.service"
    units = system.root / "etc" / "systemd" / "system"
    assert paths.sidecar_unit == units / connect.SIDECAR_UNIT
    # A refresh to 0.1.4 renames the app: both names get the drop-in.
    assert paths.dropins == (units / "snap.openshell.gateway.service.d" / "50-artzain.conf",
                             units / "snap.openshell.system-gateway.service.d" / "50-artzain.conf")


def test_the_user_gateway_is_bound_under_the_snaps_user_folders(user):
    shape = connect.detect(user.host())
    paths = shape.paths
    assert shape.openshell_version == "0.1.4"
    assert paths.gateway_toml == user.toml
    assert paths.socket == user.runtime / "snap.openshell" / "artzain" / "openshell.sock"
    assert not paths.system
    assert paths.gateway_service == "snap.openshell.user-gateway.service"
    assert paths.dropins == (user.home / ".config" / "systemd" / "user"
                             / "snap.openshell.user-gateway.service.d" / "50-artzain.conf",)


def test_root_is_refused_on_a_snap_host(system):
    with pytest.raises(connect.ConnectError, match="not as root"):
        connect.up(system.host(uid=0), token=TOKEN, digest=DIGEST, out=lambda _s: None)
    assert system.posts == []


def test_a_cli_that_cannot_reach_the_snap_gateway_stops_before_the_token(any_snap):
    any_snap.cli_reaches = False
    with pytest.raises(connect.ConnectError, match="cannot reach the gateway.*gateway add"):
        any_snap.up()
    assert any_snap.posts == []


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


def test_up_binds_the_snap_gateway(any_snap):
    record = any_snap.up()
    assert record["connected"] and record["self_test_decision_id"] == DECISION
    assert record["shape"] == connect.SHAPE_SNAP
    assert record["snap"] == {"mode": "system" if any_snap.system else "user",
                              "app": any_snap.app, "revision": any_snap.revision,
                              "version": any_snap.version}
    assert any_snap.bound and any_snap.units[any_snap.gateway_unit] == "active"
    # The registration names the socket the gateway can reach.
    found = DECIDING.findall(any_snap.toml.read_text(encoding="utf-8"))
    assert found == [f"unix://{any_snap.socket.as_posix()}"] * 2
    # The snap's gateway reads no gateway.env: none is written.
    assert not (any_snap.home / ".config" / "openshell" / "gateway.env").exists()


def test_up_holds_the_snaps_refreshes(any_snap):
    record = any_snap.up()
    assert any_snap.held and record["refresh_held_by_up"] is True
    assert ["snap", "refresh", "--hold"] in any_snap.sudo()


def test_a_snap_already_held_is_left_as_it_was(tmp_path):
    host = _SnapHost(tmp_path, "0.1.3", held=True)
    record = host.up()
    assert record["refresh_held_by_up"] is False
    assert ["snap", "refresh", "--hold"] not in host.sudo()
    connect.remove(host.host(), out=lambda _s: None)
    assert host.held  # remove lifts only a hold up put
    assert ["snap", "refresh", "--unhold"] not in host.sudo()


def test_the_system_sidecar_runs_as_the_operator_under_the_system_manager(system):
    system.up()
    unit = (system.root / "etc" / "systemd" / "system" / connect.SIDECAR_UNIT).read_text(
        encoding="utf-8")
    folder = (system.common / "artzain").as_posix()
    assert f"User={UID}\n" in unit and f"Group={GID}\n" in unit
    assert (f"ExecStartPre=+/usr/bin/install -d -o {UID} -g {GID} -m 0700 {folder}\n") in unit
    key = (system.common / "tls" / "jwt" / "public.pem").as_posix()
    assert (f"ExecStartPre=+/usr/bin/install -o {UID} -g {GID} -m 0644 {key} "
            f"{folder}/gateway-jwt.pem\n") in unit
    assert f"EnvironmentFile={system.sidecar_env.as_posix()}\n" in unit
    assert f'ExecStart="{PYTHON}" -m artzain.cli openshell sidecar\n' in unit
    assert "WantedBy=multi-user.target\n" in unit
    assert "Before=snap.openshell.gateway.service snap.openshell.system-gateway.service\n" in unit


def test_the_user_sidecar_is_a_user_service(user):
    user.up()
    unit = (user.unit_dir / connect.SIDECAR_UNIT).read_text(encoding="utf-8")
    assert "User=" not in unit and "ExecStartPre" not in unit
    assert "WantedBy=default.target\n" in unit
    assert "Before=snap.openshell.user-gateway.service\n" in unit


def test_the_sidecar_can_run_the_snaps_cli(any_snap):
    """snap-confine is setuid: with NoNewPrivileges the snap's CLI does not
    start, and the sidecar's listing fails."""
    any_snap.up()
    unit = (any_snap.unit_dir / connect.SIDECAR_UNIT).read_text(encoding="utf-8")
    assert not [line for line in unit.splitlines() if line.startswith("NoNewPrivileges")]
    assert _settings_value(any_snap.sidecar_env, "OPENSHELL_SIDECAR_LIST_CLI") == (
        "/snap/bin/openshell")


def test_the_sidecar_checks_the_snap_gateways_signed_calls(any_snap):
    any_snap.up()
    key = (any_snap.common / "artzain" / "gateway-jwt.pem" if any_snap.system else
           any_snap.home / "snap" / "openshell" / "common" / ".local" / "state" / "openshell"
           / "tls" / "jwt" / "public.pem")
    assert _settings_value(any_snap.sidecar_env, "OPENSHELL_JWT_PUBLIC_KEY") == key.as_posix()
    assert _settings_value(any_snap.sidecar_env, "OPENSHELL_JWT_GATEWAY_ID") == "openshell"
    assert _settings_value(any_snap.sidecar_env, "OPENSHELL_GATEWAY_TOML") == (
        any_snap.toml.as_posix())
    assert _settings_value(any_snap.sidecar_env, "OPENSHELL_SIDECAR_GRPC") == (
        f"unix://{any_snap.socket.as_posix()}")


@pytest.mark.parametrize("telemetry", [False, True])
def test_the_gateways_drop_in_carries_its_telemetry_choice(tmp_path, telemetry, monkeypatch):
    host = _SnapHost(tmp_path, "0.1.3")
    monkeypatch.setitem(CONFIG, "telemetry", telemetry)
    monkeypatch.setattr(sys.modules[__name__], "DIGEST", connect.config_digest(CONFIG))
    connect.up(host.host(), token=TOKEN, digest=connect.config_digest(CONFIG),
               engine="https://engine.example", out=lambda _s: None)
    for dropin in connect.detect(host.host()).paths.dropins:
        text = dropin.read_text(encoding="utf-8")
        assert f"Requires={connect.SIDECAR_UNIT}\nAfter={connect.SIDECAR_UNIT}\n" in text
        assert f"Environment=OPENSHELL_TELEMETRY_ENABLED={str(telemetry).lower()}\n" in text


def test_what_is_roots_is_written_through_sudo_on_a_system_gateway(system):
    system.up()
    written = [Path(call[-1]) for call in system.calls if call[:2] == ["sudo", "install"]]
    units = system.root / "etc" / "systemd" / "system"
    assert set(written) == {
        units / connect.SIDECAR_UNIT, system.common / "gateway.toml",
        units / "snap.openshell.gateway.service.d" / "50-artzain.conf",
        units / "snap.openshell.system-gateway.service.d" / "50-artzain.conf"}
    assert stat.S_IMODE(os.stat(system.common / "gateway.toml").st_mode) == 0o644


def test_a_user_gateway_needs_root_for_the_hold_alone(user):
    user.up()
    assert user.sudo() == [["snap", "refresh", "--hold"]]


def test_the_preflight_runs_inside_the_snap(any_snap):
    any_snap.up()
    runs = [call for call in any_snap.calls if "--shell" in call]
    assert len(runs) == 1
    assert (runs[0][0] == "sudo") == any_snap.system
    assert f"openshell.{any_snap.app}" in runs[0]


def test_a_preflight_that_fails_leaves_gateway_toml_alone(system):
    system.preflight_ok = False
    with pytest.raises(connect.ConnectError, match="preflight"):
        system.up()
    assert not system.toml.exists()
    assert not (system.common / "artzain" / "gateway.toml.candidate").exists()
    assert not system.bound


def test_a_system_gateway_systemd_gave_up_on_is_reset_before_its_restart(system):
    # A gateway that could not reach its interceptor five times in a row is
    # left failed by systemd, which then refuses to start it again.
    system.start_limited = True
    system.up()
    assert system.bound
    reset = ["sudo", "systemctl", "reset-failed", "snap.openshell.gateway.service"]
    restart = ["sudo", "systemctl", "restart", "snap.openshell.gateway.service"]
    assert system.calls.index(reset) < system.calls.index(restart)


def test_a_system_snap_without_a_signing_key_leaves_the_sidecar_unchecking(system):
    (system.common / "tls" / "jwt" / "public.pem").unlink()
    system.up()
    assert not _settings_value(system.sidecar_env, "OPENSHELL_JWT_PUBLIC_KEY")
    unit = (system.unit_dir / connect.SIDECAR_UNIT).read_text(encoding="utf-8")
    assert "gateway-jwt.pem" not in unit


def test_up_again_on_a_bound_snap_gateway_changes_nothing(any_snap):
    any_snap.up()
    before = any_snap.toml.read_bytes()
    any_snap.calls.clear()
    record = any_snap.up()
    assert record["connected"] and any_snap.toml.read_bytes() == before
    assert ["snap", "refresh", "--hold"] not in any_snap.sudo()


# ---------------------------------------------------------------------------
# status, doctor
# ---------------------------------------------------------------------------


def test_status_says_the_snaps_mode_revision_and_hold(any_snap):
    any_snap.up()
    said = connect.status(any_snap.host())
    assert said["shape"] == connect.SHAPE_SNAP
    assert (said["snap_mode"], said["snap_revision"], said["refresh_held"]) == (
        "system" if any_snap.system else "user", any_snap.revision, True)
    assert said["drop_in"] and said["sidecar_unit"] and said["registration_in_gateway_toml"]
    assert (said["gateway"], said["sidecar"]) == ("active", "active")


def test_doctor_finds_a_bound_snap_gateway_well(any_snap):
    any_snap.up()
    said = connect.doctor(any_snap.host())
    results = {check["check"]: check["result"] for check in said["checks"]}
    assert said["ok"], said["checks"]
    assert results["snap"] == "ok" and results["versions"] == "ok"


def test_doctor_fails_when_the_snap_runs_its_gateway_in_another_mode(tmp_path):
    host = _SnapHost(tmp_path, "user")
    host.up()
    host.layout = "system"  # sudo snap set openshell gateway-mode=system
    said = connect.doctor(host.host())
    snap_check = next(check for check in said["checks"] if check["check"] == "snap")
    assert not said["ok"] and snap_check["result"] == "fail"
    assert "runs its system gateway, and `up` bound its user one" in snap_check["says"]


def test_doctor_warns_when_the_snaps_refreshes_are_not_held(any_snap):
    any_snap.up()
    any_snap.held = False
    said = connect.doctor(any_snap.host())
    snap_check = next(check for check in said["checks"] if check["check"] == "snap")
    assert snap_check["result"] == "warn" and "not held" in snap_check["says"]


def test_a_system_gateway_refreshed_to_0_1_4_stays_bound(system):
    """0.1.4 runs a 0.1.3 install's gateway as ``system-gateway``, with the
    same files: the drop-in ``up`` wrote for that name applies, and every
    verb drives the new unit."""
    system.up()
    system.refresh_to("system")
    system._gateway_restart()
    assert system.bound
    said = connect.doctor(system.host())
    results = {check["check"]: check for check in said["checks"]}
    assert results["gateway"]["says"] == "snap.openshell.system-gateway.service is active"
    assert results["snap"]["result"] == "warn" and "revision 1909 to 2001" in results["snap"]["says"]
    assert results["drop_in"]["result"] == "ok"
    connect.remove(system.host(), out=lambda _s: None)
    assert ["sudo", "systemctl", "restart", "snap.openshell.system-gateway.service"] in system.calls


# ---------------------------------------------------------------------------
# remove, rotate-key
# ---------------------------------------------------------------------------


def test_remove_puts_the_snap_gateway_back_unbound(any_snap):
    any_snap.up()
    paths = connect.detect(any_snap.host()).paths
    result = connect.remove(any_snap.host(), out=lambda _s: None)
    assert not any_snap.toml.exists()  # up created it
    assert result["gateway.toml"] == "removed" and result["gateway"] == "restarted unbound"
    assert not any(dropin.exists() for dropin in paths.dropins)
    assert not paths.sidecar_unit.exists() and not any_snap.socket.parent.exists()
    assert not any_snap.bound and any_snap.units[any_snap.gateway_unit] == "active"
    assert not any_snap.held and result["refresh hold"] == "lifted"
    assert not any_snap.sidecar_env.exists() and result["credential"] == "revoked"


def test_remove_keeps_the_operators_own_gateway_toml(system):
    system.common.mkdir(parents=True, exist_ok=True)
    mine = b'[openshell]\nversion = 2\n\n[openshell.gateway]\nlog_level = "debug"\n'
    system.toml.write_bytes(mine)
    system.up()
    assert system.toml.read_bytes().startswith(mine)
    result = connect.remove(system.host(), out=lambda _s: None)
    assert result["gateway.toml"] == "restored" and system.toml.read_bytes() == mine


def test_rotate_key_restarts_the_sidecar_on_its_own_manager(any_snap):
    any_snap.up()
    any_snap.calls.clear()
    said = connect.rotate_key(any_snap.host(), out=lambda _s: None)
    assert said["rotated"] and said["old_key_retired"]
    restart = ["systemctl", "restart", connect.SIDECAR_UNIT]
    assert ((["sudo", *restart] if any_snap.system else
             ["systemctl", "--user", "restart", connect.SIDECAR_UNIT]) in any_snap.calls)
    assert _settings_value(any_snap.sidecar_env, "COGNEXUS_API_KEY") == NEW_CREDENTIAL
