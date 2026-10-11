"""``artzain connect openshell`` on a gateway that runs under Docker Compose.

NVIDIA's ``deploy/docker`` compose file runs the gateway as a service of a
Compose project, as root, with ``gateway.toml`` bind-mounted from the
project folder. These run ``up``, ``remove``, ``status``, ``doctor`` and
``rotate-key`` against :class:`_Docker`, which plays ``docker``, ``docker
compose``, cosign and the ``openshell`` CLI on such a host, and an engine to
redeem at.

What has to hold:

* the token is spent only on a project ``up`` can bind: one that reproduces
  the running gateway from its files and ``.env``, whose gateway runs as
  root, and whose sidecar image verifies;
* the sidecar runs from the image of this artzain release, named by the
  digest cosign verified as the mirror's, or by a digest the operator named;
* the operator's compose files are never written: ``up``'s own file is added
  to ``COMPOSE_FILE`` in a marked block of the project's ``.env``, so
  ``docker compose up -d`` in the folder keeps the gateway bound;
* ``remove`` gives ``gateway.toml`` and ``.env`` back byte for byte, brings
  the gateway back as the operator's files alone describe it, and removes
  the sidecar, its volumes and its files.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from artzain import __version__
from artzain.openshell import compose, connect, upgrade

pytestmark = [
    pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML"),
    # The Compose shape runs on Linux, and writes POSIX paths into a compose
    # file and COMPOSE_FILE (":" separates its files).
    pytest.mark.skipif(sys.platform == "win32", reason="the Compose shape is Linux's"),
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
IMAGE_DIGEST = "sha256:" + "6d" * 32
SIGNED_IMAGE = f"{compose.SIDECAR_IMAGE}@{IMAGE_DIGEST}"
GATEWAY_IMAGE_ID = "sha256:" + "ea" * 32
COSIGN_BYTES = b"a cosign binary"
#: What the sidecar of a Compose gateway says: it lists every sandbox with
#: its image's openshell CLI.
REPORTED = {"reporting": True, "heartbeat": "ok", "inventory": "ok", "sandboxes": 1,
            "partial": False}
#: What the host's openshell CLI says of the gateway it is registered with.
CLI_STATUS = {"authentication": {"mode": "gateway", "status": "not_required"},
              "gateway": "http://127.0.0.1:8080", "server": "http://127.0.0.1:8080",
              "status": "connected", "version": "0.1.3"}

COMPOSE_YML = """\
services:
  gateway:
    image: ghcr.io/nvidia/openshell/gateway:${IMAGE_TAG:-latest}
    user: "0"
  init:
    image: ghcr.io/nvidia/openshell/gateway:${IMAGE_TAG:-latest}
"""

#: NVIDIA's deploy/docker/gateway.toml at v0.1.3, in short.
GATEWAY_TOML = """\
[openshell]
version = 2

[openshell.gateway]
bind_address        = "127.0.0.1:8080"
compute_driver      = "docker"
disable_tls         = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "/var/lib/openshell/tls/jwt/signing.pem"
public_key_path  = "/var/lib/openshell/tls/jwt/public.pem"
kid_path         = "/var/lib/openshell/tls/jwt/kid"
gateway_id       = "openshell-docker"
"""


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


class _Docker:
    """A host that runs NVIDIA's compose project ``openshell`` (services
    ``gateway`` and ``init``), Docker, cosign and the openshell CLI, and an
    engine to redeem at."""

    def __init__(self, tmp_path: Path, *, env: str | None = "IMAGE_TAG=0.1.3\n"):
        self.home = tmp_path / "home"
        self.root = tmp_path / "root"
        self.root.mkdir()
        self.folder = tmp_path / "openshell-docker"
        self.folder.mkdir()
        self.compose_yml = self.folder / "docker-compose.yml"
        self.compose_yml.write_text(COMPOSE_YML, encoding="utf-8")
        self.toml = self.folder / "gateway.toml"
        self.toml.write_text(GATEWAY_TOML, encoding="utf-8")
        self.env = self.folder / ".env"
        if env is not None:
            self.env.write_text(env, encoding="utf-8")
        self.calls = []
        self.posts = []
        self.serial = 0
        self.containers = {}
        self.volumes = set()
        self.settings = {"proposal_approval_mode": "manual"}
        self.revision = 3
        # How things answer (None: as they would).
        self.user = "0"
        self.preflight = None
        self.drifted = False           # the project's files no longer give the running gateway
        self.cosign_exit = 0
        self.cosign_said = None        # None: one signature of IMAGE_DIGEST
        self.sidecar_fails = False
        self.gateway_flaps = False
        self.engine_allows = False
        self.redeem = (200, None)
        self.revoke_status = 200
        self.live_keys = [CREDENTIAL]
        self.socket_said = {"socket": [True, 0o600, 10001], "folder": [False, 0o700, 10001]}
        self.reported = dict(REPORTED)
        self.sidecar_env_seen = []     # the settings each sidecar container started with
        self.wall_now = 1_800_000_000.0
        self.starting_calls = 0        # CLI calls a recreated gateway leaves unanswered
        self.unanswered = 0
        self.cli_status = dict(CLI_STATUS)  # what `openshell status -o json` says (None: fails)
        self.gateway_files = (self.compose_yml.as_posix(),)
        self._start("init", (self.compose_yml.as_posix(),), status="exited")
        self._start("gateway", self.gateway_files)
        self.original_hash = self.containers["gateway"]["Config"]["Labels"][
            "com.docker.compose.config-hash"]

    # --- the project --------------------------------------------------------
    def _hash(self, files):
        h = hashlib.sha256()
        for path in files:
            h.update(Path(path).read_bytes())
        if self.drifted and tuple(files) == (self.compose_yml.as_posix(),):
            h.update(b"IMAGE_TAG differs")
        return h.hexdigest()

    @property
    def ours(self) -> Path:
        return self.home / ".config" / "artzain" / "openshell" / compose.FILE

    def _start(self, service, files, *, status="running"):
        self.serial += 1
        labels = {"com.docker.compose.project": "openshell",
                  "com.docker.compose.project.working_dir": self.folder.as_posix(),
                  "com.docker.compose.project.config_files": ",".join(files),
                  "com.docker.compose.service": service,
                  "com.docker.compose.config-hash": self._hash(files)}
        with_ours = self.ours.as_posix() in files
        if service == compose.SERVICE:
            text = self.ours.read_text(encoding="utf-8")
            image = re.search(r'image: "([^"]+)"', text).group(1)
            settings = Path(re.search(r'env_file: \["([^"]+)"\]', text).group(1))
            self.sidecar_env_seen.append(settings.read_text(encoding="utf-8"))
            for volume in (compose.SOCKET_VOLUME, compose.STATE_VOLUME):
                self.volumes.add(f"openshell_{volume}")
            state = ({"Status": "exited"} if self.sidecar_fails else
                     {"Status": "running", "Health": {"Status": "healthy"}})
            self.containers[service] = {
                "Id": f"c{self.serial:03d}", "Image": "sha256:" + "51" * 32,
                "Config": {"Image": image, "User": "", "Env": [], "Labels": labels},
                "Mounts": [{"Type": "volume", "Name": "openshell_artzain-socket",
                            "Destination": "/run/artzain"}],
                "State": state, "RestartCount": 0}
            return
        mounts = [{"Type": "bind", "Source": "/var/run/docker.sock",
                   "Destination": "/var/run/docker.sock"},
                  {"Type": "bind", "Source": "/var/lib/openshell",
                   "Destination": "/var/lib/openshell"}]
        env = ["HOME=/var/lib/openshell"]
        if service == "gateway":
            mounts.append({"Type": "bind", "Source": self.toml.as_posix(),
                           "Destination": "/etc/openshell/gateway.toml"})
            env.append("OPENSHELL_GATEWAY_CONFIG=/etc/openshell/gateway.toml")
            if with_ours:
                mounts.append({"Type": "volume", "Name": "openshell_artzain-socket",
                               "Destination": "/run/artzain"})
            registered = connect.BLOCK_BEGIN in self.toml.read_text(encoding="utf-8")
            sidecar = self.containers.get(compose.SERVICE, {}).get("State", {})
            reachable = with_ours and sidecar.get("Status") == "running"
            if self.gateway_flaps or (registered and not reachable):
                status = "restarting"
            self.gateway_files = tuple(files)
            # How many CLI calls a new gateway container leaves unanswered.
            self.unanswered = self.starting_calls
        self.containers[service] = {
            "Id": f"c{self.serial:03d}", "Image": GATEWAY_IMAGE_ID,
            "Config": {"Image": "ghcr.io/nvidia/openshell/gateway:0.1.3",
                       "User": self.user, "Env": env, "Labels": labels},
            "Mounts": mounts, "State": {"Status": status}, "RestartCount": 0}

    @property
    def bound(self):
        gateway = self.containers.get("gateway", {})
        sidecar = self.containers.get(compose.SERVICE, {})
        return (gateway.get("State", {}).get("Status") == "running"
                and self.ours.as_posix() in self.gateway_files
                and connect.BLOCK_BEGIN in self.toml.read_text(encoding="utf-8")
                and sidecar.get("State", {}).get("Status") == "running")

    def _operator_files(self):
        """What COMPOSE_FILE in .env names, or the default file."""
        files = (self.compose_yml.as_posix(),)
        if self.env.exists():
            for line in self.env.read_text(encoding="utf-8").splitlines():
                if line.startswith("COMPOSE_FILE="):
                    files = tuple(line.split("=", 1)[1].split(":"))
        return files

    # --- docker -------------------------------------------------------------
    def _docker(self, args):
        if args[:2] == ["ps", "--all"]:
            wanted = [a.split("=", 1)[1] for a in args if a.startswith("label=")]
            ids = [c["Id"] for c in self.containers.values()
                   if all(self._labelled(c, w) for w in wanted)]
            return _done(0, "".join(i + "\n" for i in ids))
        if args[0] == "inspect":
            by_id = {c["Id"]: c for c in self.containers.values()}
            return _done(0, json.dumps([by_id[i] for i in args[1:] if i in by_id]))
        if args[0] == "run" and args[-1] == "--version":
            assert args[-2] == GATEWAY_IMAGE_ID and "none" in args
            return _done(0, "openshell-gateway 0.1.3\n")
        if args[0] == "run" and args[-4:-2] == ["config", "preflight"]:
            assert args[-5] == GATEWAY_IMAGE_ID and "none" in args
            source = re.search(r"source=([^,]+)", args[args.index("--mount") + 1]).group(1)
            if self.preflight is not None:
                return _done(self.preflight, "", "gateway config preflight failed")
            import tomllib
            tomllib.loads(Path(source).read_text(encoding="utf-8"))
            return _done(0)
        if args[0] == "rm":
            for service, c in list(self.containers.items()):
                if c["Id"] == args[-1]:
                    del self.containers[service]
            return _done()
        if args[:2] == ["volume", "ls"]:
            volume = [a for a in args if "volume=" in a][0].split("volume=")[1]
            name = f"openshell_{volume}"
            return _done(0, name + "\n" if name in self.volumes else "")
        if args[:2] == ["volume", "rm"]:
            self.volumes.discard(args[2])
            return _done()
        if args[0] == "exec":
            return _done(0, json.dumps(self.socket_said))
        if args[0] == "compose":
            return self._compose(args[1:])
        raise AssertionError(f"unexpected docker {args}")

    def _labelled(self, container, wanted):
        labels = container["Config"]["Labels"]
        name, _, value = wanted.partition("=")
        return name in labels and (not value or labels[name] == value)

    def _compose(self, args):
        files = []
        project = None
        rest = []
        i = 0
        while i < len(args):
            if args[i] == "-f":
                files.append(args[i + 1])
                i += 2
            elif args[i] == "-p":
                project = args[i + 1]
                i += 2
            elif args[i] == "--project-directory":
                assert args[i + 1] == self.folder.as_posix()
                i += 2
            else:
                rest.append(args[i])
                i += 1
        if not files:
            assert project is None, "the operator's own run names no project"
            files = list(self._operator_files())
        else:
            assert project == "openshell"
        if rest[0] == "config":
            service = rest[1].split("=", 1)[1]
            return _done(0, f"{service} {self._hash(files)}\n")
        if rest[:3] in (["up", "-d", "--no-deps"], ["up", "--no-start", "--no-deps"]):
            service = rest[-1]
            current = self.containers.get(service)
            same = (current is not None and current["Config"]["Labels"][
                "com.docker.compose.config-hash"] == self._hash(files))
            if "--force-recreate" in rest or not same:
                self._start(service, tuple(files),
                            status="created" if "--no-start" in rest else "running")
            return _done()
        raise AssertionError(f"unexpected docker compose {args}")

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        name, args = argv[0], argv[1:]
        if name == "docker":
            return self._docker(args)
        if argv[:3] == ["snap", "list", "openshell"]:
            return _done(1, "", "error: no matching snaps installed\n")  # snapd, no OpenShell snap
        if argv == ["uname", "-m"]:
            return _done(0, "x86_64\n")
        if name == "curl":
            url = argv[-1]
            assert url == upgrade.COSIGN_RELEASE + upgrade.COSIGN["x86_64"][0], url
            Path(argv[argv.index("-o") + 1]).write_bytes(COSIGN_BYTES)
            return _done()
        if name.endswith(upgrade.COSIGN_NAME) and args[0] == "verify":
            assert Path(name).read_bytes() == COSIGN_BYTES, "the pinned cosign runs"
            if self.cosign_exit:
                return _done(self.cosign_exit, "", "Error: no matching signatures")
            said = self.cosign_said if self.cosign_said is not None else [
                {"critical": {"identity": {"docker-reference": compose.SIDECAR_IMAGE},
                              "image": {"docker-manifest-digest": IMAGE_DIGEST},
                              "type": "cosign container image signature"}, "optional": {}}]
            return _done(0, json.dumps(said), "Verification for ... --")
        starting = self._not_listening() if name == "openshell" else None
        if starting is not None:
            return starting
        if name == "openshell" and args[:2] == ["settings", "set"]:
            key, value = args[args.index("--key") + 1], args[args.index("--value") + 1]
            if self.bound and not self.engine_allows and value == "auto":
                return _done(1, "", "status: PermissionDenied, message: \"gateway interceptor "
                                    f"'artzain' denied the request: decision deny ({DECISION})\"")
            self.settings[key] = value
            self.revision += 1
            return _done(0, "Updated global setting\n")
        if name == "openshell" and args[:2] == ["settings", "get"]:
            return _done(0, f"Settings Rev: {self.revision}\n" + "".join(
                f"  {k} = {v}\n" for k, v in self.settings.items()))
        if name == "openshell" and args == ["status", "-o", "json"]:
            if self.cli_status is None:
                return _done(1, "", "Error: no gateway configured")
            return _done(0, json.dumps(self.cli_status))
        raise AssertionError(f"unexpected command {argv}")

    def _not_listening(self):
        """A gateway still starting: its port is published, and nothing
        behind it answers yet."""
        if self.unanswered > 0:
            self.unanswered -= 1
            return _done(1, "", "Error: code: 'Unknown error', message: \"transport error\" "
                                "connection reset")
        return None

    # --- the sidecar and the engine ----------------------------------------
    def _sidecar_up(self):
        c = self.containers.get(compose.SERVICE)
        return bool(c) and c["State"]["Status"] == "running"

    def healthy(self, port):
        return self._sidecar_up()

    def reports(self, port, token=""):
        expected = _settings_value(self.paths.sidecar_env, "OPENSHELL_SIDECAR_TOKEN")
        if not self._sidecar_up() or not expected or token != expected:
            return None
        key = self.sidecar_env_seen[-1] if self.sidecar_env_seen else ""
        if not any(k in key for k in self.live_keys):
            return dict(self.reported, heartbeat="failed", heartbeat_error="HTTPError")
        return dict(self.reported)

    def break_glass(self, port, token=""):
        return None

    def get_engine(self, url, *, proxy="", ca_bundle=""):
        import email.utils

        return 200, {"Date": email.utils.formatdate(self.wall_now, usegmt=True)}

    def post_json(self, url, *, headers, body, proxy="", ca_bundle=""):
        self.posts.append({"url": url, "headers": dict(headers), "body": dict(body)})
        if url.endswith(connect.REDEEM_PATH):
            status, answer = self.redeem
            if answer is None:
                answer = {"gateway_id": GATEWAY, "agent_did": f"openshell:{GATEWAY}",
                          "credential": CREDENTIAL, "key_prefix": CREDENTIAL[:12],
                          "config_digest": DIGEST, "config": CONFIG}
            return status, answer
        if url.endswith("/revoke"):
            return self.revoke_status, {"revoked": True}
        if "/keys" in url:
            key = headers["X-Api-Key"]
            if key not in self.live_keys:
                return 401, {}
            if url.endswith("/retire-others"):
                self.live_keys = [key]
                return 200, {"retired": 1}
            self.live_keys.append(NEW_CREDENTIAL)
            return 200, {"gateway_id": GATEWAY, "credential": NEW_CREDENTIAL}
        raise AssertionError(url)

    def stat(self, path):
        import os

        real = os.stat(path)
        return os.stat_result((stat.S_IFMT(real.st_mode) | 0o600, 0, 0, 1, 1000, 1000,
                               0, 0, 0, 0))

    def which(self, name):
        return None if name == "openshell-gateway" else f"/usr/bin/{name}"

    def host(self, **overrides) -> connect.Host:
        settings = dict(
            environ={"HOME": str(self.home), "XDG_RUNTIME_DIR": "/run/user/1000",
                     "PATH": "/usr/bin"},
            root=str(self.root), runner=self.run, healthy=self.healthy,
            reports=self.reports, break_glass=self.break_glass, stat=self.stat,
            get_engine=self.get_engine, wall=lambda: self.wall_now,
            post_json=self.post_json, which=self.which, sleep=lambda _s: None,
            clock=_Clock(), platform="linux",
            executable="/home/op/.local/share/uv/tools/artzain/bin/python", uid=1000)
        settings.update(overrides)
        return connect.Host(**settings)

    @property
    def paths(self) -> connect.Layout:
        return connect.layout(self.host())

    def commands(self, *head):
        return [c for c in self.calls if c[:len(head)] == list(head)]

    def record(self):
        return json.loads(self.paths.record.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def pinned_cosign(monkeypatch):
    monkeypatch.setattr(upgrade, "COSIGN", {
        "x86_64": ("cosign-linux-amd64", _sha(COSIGN_BYTES)),
        "aarch64": ("cosign-linux-arm64", _sha(COSIGN_BYTES))})


@pytest.fixture
def docker(tmp_path):
    return _Docker(tmp_path)


def _up(docker, *, token=TOKEN, **kwargs):
    said = []
    record = connect.up(docker.host(), token=token, digest=DIGEST,
                        engine="https://engine.example/", out=said.append, **kwargs)
    return record, said


def _redeemed(docker):
    return [p for p in docker.posts if p["url"].endswith(connect.REDEEM_PATH)]


# ---------------------------------------------------------------------------
# Finding the gateway
# ---------------------------------------------------------------------------


def test_the_compose_gateway_is_found_by_its_image_and_its_config_mount(docker):
    shape = connect.detect(docker.host())
    assert shape.kind == connect.SHAPE_COMPOSE == "compose"
    assert shape.openshell_version == "0.1.3"
    project = shape.project
    assert (project.name, project.service) == ("openshell", "gateway")
    assert project.directory == docker.folder
    assert project.files == (docker.compose_yml.as_posix(),)
    # The file the gateway reads, on this host: up edits that one.
    assert shape.paths.gateway_toml == docker.toml
    assert shape.paths.gateway_env == docker.env
    # The socket as both containers see it.
    assert shape.paths.socket.as_posix() == "/run/artzain/openshell.sock"


def test_a_deb_gateway_on_the_same_host_is_still_bound_as_the_deb_one(docker):
    unit = docker.root / "usr" / "lib" / "systemd" / "user" / connect.GATEWAY_UNIT
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\n")
    docker.which = lambda name: f"/usr/bin/{name}"

    def run(argv, env, timeout):
        if argv == ["openshell-gateway", "--version"]:
            return _done(0, "openshell-gateway 0.1.2\n")
        return _Docker.run(docker, argv, env, timeout)

    shape = connect.detect(docker.host(runner=run))
    assert shape.kind == connect.SHAPE_SYSTEMD_USER and shape.project is None
    assert not docker.commands("docker", "ps")


def test_two_compose_gateways_are_refused(docker):
    other = json.loads(json.dumps(docker.containers["gateway"]))
    other["Id"] = "c999"
    other["Config"]["Labels"]["com.docker.compose.project"] = "second"
    docker.containers["second-gateway"] = other
    with pytest.raises(connect.ConnectError, match="2 OpenShell gateways under Compose"):
        _up(docker)
    assert not _redeemed(docker)


def test_a_docker_this_user_cannot_use_is_said_before_the_token_is_spent(docker):
    real = docker._docker

    def refused(args):
        if args[:2] == ["ps", "--all"]:
            return _done(1, "", "permission denied while trying to connect to the Docker "
                                "daemon socket at unix:///var/run/docker.sock")
        return real(args)

    docker._docker = refused
    with pytest.raises(connect.ConnectError, match="this user cannot use it.*permission denied"):
        _up(docker)
    assert not _redeemed(docker)


def test_no_install_of_the_deb_is_offered_on_a_compose_host(docker):
    asked = []
    _up(docker, ask=lambda question: asked.append(question) or "n")
    assert asked == []
    assert not docker.commands("sudo") and not docker.commands("curl", "--proto", "=https",
                                                                 "--tlsv1.2", "-fsSL", "-o")


def test_a_gateway_that_does_not_run_as_root_is_refused_before_the_token_is_spent(tmp_path):
    docker = _Docker(tmp_path)
    docker.user = "1000:1000"
    docker._start("gateway", docker.gateway_files)
    with pytest.raises(connect.ConnectError, match="not root"):
        _up(docker)
    assert not _redeemed(docker)


@pytest.mark.parametrize("status", [
    None, {"status": "connected"}, dict(CLI_STATUS, server="unix:///run/gw.sock", gateway="gw"),
    dict(CLI_STATUS, server="grpc://127.0.0.1:8080", gateway="grpc://127.0.0.1:8080"),
    dict(CLI_STATUS, server='http://127.0.0.1:8080/"$(id)"', gateway='http://127.0.0.1:8080/"$(id)"'),
], ids=["fails", "no endpoint", "a socket", "not http", "unsafe"])
def test_a_host_cli_that_names_no_gateway_endpoint_is_refused_before_the_token_is_spent(
        docker, status):
    """The sidecar's own CLI connects where the host's is registered: an
    endpoint it cannot take stops up before anything is spent."""
    docker.cli_status = status
    with pytest.raises(connect.ConnectError, match="endpoint"):
        _up(docker)
    assert not _redeemed(docker)


def test_up_again_gives_a_sidecar_connected_by_0_6_45_its_cli(docker):
    """0.6.45 wrote no CLI and no endpoint into the sidecar's settings: up,
    run again (as `upgrade` runs it), adds them and recreates the sidecar,
    and the gateway with it, without a new token."""
    _up(docker)
    env = docker.paths.sidecar_env
    lines = [line for line in env.read_text(encoding="utf-8").splitlines(keepends=True)
             if not line.startswith(("OPENSHELL_SIDECAR_LIST_CLI=", "OPENSHELL_GATEWAY_ENDPOINT="))]
    env.write_text("".join(lines), encoding="utf-8")
    sidecar_before = docker.containers[compose.SERVICE]["Id"]
    gateway_before = docker.containers["gateway"]["Id"]
    _, said = _up(docker, token="")
    assert _settings_value(env, "OPENSHELL_SIDECAR_LIST_CLI") == "/usr/local/bin/openshell"
    assert _settings_value(env, "OPENSHELL_GATEWAY_ENDPOINT") == "http://127.0.0.1:8080"
    assert docker.containers[compose.SERVICE]["Id"] != sidecar_before
    assert "OPENSHELL_GATEWAY_ENDPOINT" in docker.sidecar_env_seen[-1]
    assert docker.containers["gateway"]["Id"] != gateway_before and docker.bound
    assert len(_redeemed(docker)) == 1
    assert any("openshell CLI" in line for line in said)


def test_a_gateway_toml_the_sidecar_cannot_read_is_refused_before_the_token_is_spent(docker):
    docker.toml.chmod(0o600)
    with pytest.raises(connect.ConnectError, match="not readable by other users"):
        _up(docker)
    assert not _redeemed(docker)


def test_a_project_that_would_not_bring_the_gateway_up_as_it_runs_is_refused(docker):
    # The gateway was brought up with a variable set in a shell, say: the
    # project's files and .env alone would recreate it otherwise.
    docker.drifted = True
    with pytest.raises(connect.ConnectError, match="would not bring the gateway up as it runs"):
        _up(docker)
    assert not _redeemed(docker)
    assert not docker.commands("docker", "compose", "-p", "openshell", "--project-directory",
                               docker.folder.as_posix(), "-f", docker.compose_yml.as_posix(),
                               "up")


def test_an_env_that_sets_compose_file_already_is_refused(tmp_path):
    docker = _Docker(tmp_path, env="COMPOSE_FILE=docker-compose.yml\n")
    with pytest.raises(connect.ConnectError, match="sets COMPOSE_FILE"):
        _up(docker)
    assert not _redeemed(docker)


def test_compose_file_in_the_shell_is_refused(docker):
    with pytest.raises(connect.ConnectError, match="COMPOSE_FILE is set"):
        connect.up(docker.host(environ={"HOME": str(docker.home), "PATH": "/usr/bin",
                                        "COMPOSE_FILE": "x.yml"}),
                   token=TOKEN, digest=DIGEST, engine="https://engine.example",
                   out=lambda _s: None)
    assert not _redeemed(docker)


def test_the_proxy_from_this_shell_is_refused_for_a_container(docker):
    with pytest.raises(connect.ConnectError, match="name the proxy"):
        _up(docker, proxy="env")
    assert not _redeemed(docker)


# ---------------------------------------------------------------------------
# The sidecar's image
# ---------------------------------------------------------------------------


def test_the_sidecar_runs_from_this_releases_image_as_cosign_verified_it(docker):
    _up(docker)
    verify = [c for c in docker.calls if c[0].endswith(upgrade.COSIGN_NAME)]
    assert len(verify) == 1
    assert verify[0][1:3] == ["verify", f"{compose.SIDECAR_IMAGE}:{__version__}"]
    assert verify[0][verify[0].index("--certificate-identity") + 1] == (
        "https://github.com/CogNEXUSlabs/cognexus-tools/.github/workflows/"
        f"sidecar-image.yml@refs/tags/sidecar-v{__version__}")
    assert verify[0][verify[0].index("--certificate-oidc-issuer") + 1] == (
        "https://token.actions.githubusercontent.com")
    # Before the token was spent.
    assert docker.calls.index(verify[0]) < min(
        i for i, c in enumerate(docker.calls) if c[:2] == ["docker", "compose"] and "up" in c)
    assert _redeemed(docker)
    # Named by the digest it verified, not by the tag.
    assert f'image: "{SIGNED_IMAGE}"' in docker.ours.read_text(encoding="utf-8")
    assert docker.containers[compose.SERVICE]["Config"]["Image"] == SIGNED_IMAGE
    assert docker.record()["sidecar_image"] == SIGNED_IMAGE


def test_an_image_cosign_does_not_verify_stops_before_the_token_is_spent(docker):
    docker.cosign_exit = 1
    with pytest.raises(connect.ConnectError, match="does not verify as signed by sidecar-image.yml"):
        _up(docker)
    assert not _redeemed(docker)
    assert not docker.ours.exists()


@pytest.mark.parametrize("said", [
    [],
    [{"critical": {"identity": {"docker-reference": "ghcr.io/someone/else"},
                   "image": {"docker-manifest-digest": IMAGE_DIGEST}}}],
    [{"critical": {"identity": {"docker-reference": compose.SIDECAR_IMAGE},
                   "image": {"docker-manifest-digest": IMAGE_DIGEST}}},
     {"critical": {"identity": {"docker-reference": compose.SIDECAR_IMAGE},
                   "image": {"docker-manifest-digest": "sha256:" + "0" * 64}}}],
    [{"critical": {"identity": {"docker-reference": compose.SIDECAR_IMAGE},
                   "image": {"docker-manifest-digest": "latest"}}}],
])
def test_a_verification_that_names_no_one_digest_of_the_image_is_refused(docker, said):
    docker.cosign_said = said
    with pytest.raises(connect.ConnectError, match="did not name one digest"):
        _up(docker)
    assert not _redeemed(docker)


def test_a_named_image_is_run_as_named_and_said_to_be_unchecked(docker):
    local = "sha256:" + "ab" * 32
    _, said = _up(docker, sidecar_image=local)
    assert not [c for c in docker.calls if c[0].endswith(upgrade.COSIGN_NAME)]
    assert docker.containers[compose.SERVICE]["Config"]["Image"] == local
    assert any("its signature is not checked" in line for line in said)


@pytest.mark.parametrize("named", [
    f"{compose.SIDECAR_IMAGE}:{__version__}", f"{compose.SIDECAR_IMAGE}", "sha256:abc",
    f'{compose.SIDECAR_IMAGE}@sha256:{"ab" * 32}"', f"x@sha256:{'AB' * 32}"])
def test_a_named_image_must_be_named_by_its_digest(docker, named):
    with pytest.raises(connect.ConnectError, match="by its digest"):
        _up(docker, sidecar_image=named)
    assert not _redeemed(docker)


def test_a_named_image_is_for_a_compose_gateway_only(tmp_path):
    from tests.test_openshell_connect import _Gateway

    gateway = _Gateway(tmp_path)
    with pytest.raises(connect.ConnectError, match="for a gateway under Compose"):
        connect.up(gateway.host(), token=TOKEN, digest=DIGEST, out=lambda _s: None,
                   sidecar_image="sha256:" + "ab" * 32)
    assert not [p for p in gateway.posts if p["url"].endswith(connect.REDEEM_PATH)]


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


def test_up_binds_the_compose_gateway(docker):
    toml_before = docker.toml.read_bytes()
    env_before = docker.env.read_bytes()
    compose_before = docker.compose_yml.read_bytes()
    record, said = _up(docker)

    assert record["connected"] is True and record["shape"] == "compose"
    assert record["self_test_decision_id"] == DECISION
    assert any(f"decision {DECISION}" in line for line in said)
    assert any(f"/dashboard.html?receipt={DECISION}" in line for line in said)
    # The operator's compose file is untouched.
    assert docker.compose_yml.read_bytes() == compose_before
    # The registration names the socket where the gateway's container sees it.
    toml = docker.toml.read_text(encoding="utf-8")
    assert toml.startswith(toml_before.decode("utf-8"))
    assert 'grpc_endpoint  = "unix:///run/artzain/openshell.sock"' in toml
    # .env adds up's file to the files the project was brought up from.
    env = docker.env.read_text(encoding="utf-8")
    assert env.startswith(env_before.decode("utf-8"))
    assert (f"COMPOSE_FILE={docker.compose_yml.as_posix()}:{docker.ours.as_posix()}\n"
            in env)
    assert connect.strip_block(docker.env.read_bytes()) == env_before
    # The gateway was recreated from both files, and docker compose in the
    # folder, as the operator runs it, would bring it up the same.
    assert docker.gateway_files == (docker.compose_yml.as_posix(), docker.ours.as_posix())
    labels = docker.containers["gateway"]["Config"]["Labels"]
    assert labels["com.docker.compose.config-hash"] == docker._hash(docker._operator_files())
    assert docker.bound


def test_the_sidecar_settings_name_paths_inside_its_container(docker):
    _up(docker)
    env = docker.paths.sidecar_env
    assert stat.S_IMODE(env.stat().st_mode) == 0o600 or sys.platform == "win32"
    value = lambda name: _settings_value(env, name)  # noqa: E731
    assert value("COGNEXUS_API_KEY") == CREDENTIAL
    assert value("OPENSHELL_GATEWAY_ID") == GATEWAY
    assert value("OPENSHELL_SIDECAR_GRPC") == "unix:///run/artzain/openshell.sock"
    assert (value("OPENSHELL_SIDECAR_HOST"), value("OPENSHELL_SIDECAR_PORT")) == ("127.0.0.1", "8088")
    assert value("OPENSHELL_SIDECAR_STATE") == "/var/lib/artzain/state.json"
    assert value("OPENSHELL_SIDECAR_JOURNAL") == "/var/lib/artzain/journal.json"
    assert value("OPENSHELL_SIDECAR_BASE_POLICY") == "/var/lib/artzain/base-policy.json"
    assert value("OPENSHELL_GATEWAY_TOML") == "/etc/artzain/gateway/gateway.toml"
    assert value("OPENSHELL_JWT_PUBLIC_KEY") == "/etc/artzain/gateway-jwt.pem"
    assert value("OPENSHELL_JWT_GATEWAY_ID") == "openshell-docker"
    assert len(value("OPENSHELL_SIDECAR_TOKEN")) >= 40
    # The image's openshell CLI lists every sandbox, and asks the gateway its
    # release, at the endpoint the host's CLI is registered with (the sidecar
    # is on the host's network).
    assert value("OPENSHELL_SIDECAR_LIST_CLI") == "/usr/local/bin/openshell"
    assert value("OPENSHELL_GATEWAY_ENDPOINT") == "http://127.0.0.1:8080"
    # The container started with these settings.
    assert docker.sidecar_env_seen[-1] == env.read_text(encoding="utf-8")


def test_ups_compose_file_runs_the_sidecar_locked_down_beside_the_gateway(docker):
    _up(docker)
    text = docker.ours.read_text(encoding="utf-8")
    sidecar = text.split("  gateway:\n")[0]
    for line in ("    network_mode: host", "    read_only: true", '    cap_drop: ["ALL"]',
                 '    security_opt: ["no-new-privileges:true"]', "    restart: unless-stopped",
                 f'    env_file: ["{docker.paths.sidecar_env.as_posix()}"]',
                 '      - "artzain-socket:/run/artzain"', '      - "artzain-state:/var/lib/artzain"'):
        assert line in sidecar.splitlines(), line
    # Read-only: the folder of the gateway's file (its heartbeat says whether
    # the registration is still there: the folder, so that a file replaced
    # by a rename is seen), and the gateway's JWT public key, from where the
    # gateway's container mounts it on this host.
    assert (f'source: "{docker.folder.as_posix()}"\n        target: "/etc/artzain/gateway"\n'
            "        read_only: true") in sidecar
    assert ('source: "/var/lib/openshell/tls/jwt/public.pem"\n'
            '        target: "/etc/artzain/gateway-jwt.pem"\n        read_only: true') in sidecar
    gateway = text.split("  gateway:\n")[1]
    assert "artzain-sidecar:\n        condition: service_healthy" in gateway
    assert 'OPENSHELL_TELEMETRY_ENABLED: "false"' in gateway
    assert '- "artzain-socket:/run/artzain"' in gateway
    assert "$" not in text


def test_ups_compose_file_is_yaml_compose_reads(docker):
    yaml = pytest.importorskip("yaml")
    _up(docker)
    model = yaml.safe_load(docker.ours.read_text(encoding="utf-8"))
    sidecar = model["services"][compose.SERVICE]
    assert sidecar["image"] == SIGNED_IMAGE
    assert sidecar["healthcheck"]["test"][:3] == ["CMD", "python", "-c"]
    assert "127.0.0.1:8088/healthz" in sidecar["healthcheck"]["test"][3]
    assert model["services"]["gateway"]["depends_on"] == {
        compose.SERVICE: {"condition": "service_healthy"}}
    assert set(model["volumes"]) == {"artzain-socket", "artzain-state"}


def test_the_sidecar_is_up_before_the_registration_and_the_gateway_restarts_last(docker):
    _up(docker)
    ups = [c for c in docker.calls if c[:2] == ["docker", "compose"] and "up" in c]
    assert [c[-1] for c in ups] == [compose.SERVICE, "gateway"]
    # Both from the operator's files and up's own.
    for call in ups:
        assert call[call.index("-f") + 1] == docker.compose_yml.as_posix()
        assert call[-5:-3] == ["-f", docker.ours.as_posix()] or docker.ours.as_posix() in call
    preflight = docker.commands("docker", "run", "--rm", "--network", "none", "--user")
    assert len(preflight) == 1
    assert docker.calls.index(ups[0]) < docker.calls.index(preflight[0]) < docker.calls.index(ups[1])


def test_preflight_runs_in_the_gateways_image_and_a_refusal_writes_nothing(docker):
    docker.preflight = 1
    toml, env = docker.toml.read_bytes(), docker.env.read_bytes()
    with pytest.raises(connect.ConnectError, match="preflight"):
        _up(docker)
    assert docker.toml.read_bytes() == toml and docker.env.read_bytes() == env
    assert docker.gateway_files == (docker.compose_yml.as_posix(),)


def test_a_gateway_that_does_not_stay_up_is_said_and_remove_puts_it_back(docker):
    docker.gateway_flaps = True
    with pytest.raises(connect.ConnectError, match="did not stay up"):
        _up(docker)
    docker.gateway_flaps = False
    connect.remove(docker.host(), out=lambda _s: None)
    assert docker.toml.read_text(encoding="utf-8") == GATEWAY_TOML
    assert docker.env.read_text(encoding="utf-8") == "IMAGE_TAG=0.1.3\n"
    assert docker.containers["gateway"]["Config"]["Labels"][
        "com.docker.compose.config-hash"] == docker.original_hash


def test_the_self_test_waits_for_the_recreated_gateway_to_answer(docker):
    # Its container runs, and its port is published, before the gateway
    # behind it listens: the first calls are reset.
    docker.starting_calls = 3
    record, said = _up(docker)
    assert record["connected"] is True and record["self_test_decision_id"] == DECISION
    assert docker.unanswered == 0


def test_a_recreated_gateway_the_cli_never_reaches_is_said(docker):
    docker.starting_calls = 10 ** 6
    with pytest.raises(connect.ConnectError, match="the openshell CLI cannot reach it"):
        _up(docker)
    assert docker.settings["proposal_approval_mode"] == "manual"


def test_a_gateway_that_restarts_once_it_has_started_did_not_stay_up(docker):
    real = docker._docker

    def restarting(args):
        done = real(args)
        gateway = docker.containers.get("gateway")
        if args[0] == "inspect" and gateway and docker.ours.as_posix() in docker.gateway_files:
            gateway["RestartCount"] += 1   # running at each look, restarted in between
        return done

    docker._docker = restarting
    with pytest.raises(connect.ConnectError, match="did not stay up"):
        _up(docker)


def test_telemetry_goes_to_the_gateway_service(docker):
    docker.redeem = (200, {"gateway_id": GATEWAY, "credential": CREDENTIAL,
                           "config_digest": connect.config_digest(dict(CONFIG, telemetry=True)),
                           "config": dict(CONFIG, telemetry=True)})
    connect.up(docker.host(), token=TOKEN, digest=connect.config_digest(dict(CONFIG, telemetry=True)),
               engine="https://engine.example", out=lambda _s: None)
    assert 'OPENSHELL_TELEMETRY_ENABLED: "true"' in docker.ours.read_text(encoding="utf-8")


def test_a_project_without_an_env_gets_one_and_remove_deletes_it(tmp_path):
    docker = _Docker(tmp_path, env=None)
    _up(docker)
    assert docker.env.read_text(encoding="utf-8").count("COMPOSE_FILE=") == 1
    connect.remove(docker.host(), out=lambda _s: None)
    assert not docker.env.exists()


def test_the_jwt_key_is_read_from_where_the_gateway_mounts_its_folder_from(docker):
    # The gateway's data folder from elsewhere on the host: the key the
    # sidecar reads is there, not at the path the gateway's container sees.
    gateway = docker.containers["gateway"]
    for mount in gateway["Mounts"]:
        if mount["Destination"] == "/var/lib/openshell":
            mount["Source"] = "/srv/openshell-data"
    _up(docker)
    assert ('source: "/srv/openshell-data/tls/jwt/public.pem"\n'
            '        target: "/etc/artzain/gateway-jwt.pem"') in docker.ours.read_text(
        encoding="utf-8")


def test_a_jwt_key_the_gateway_does_not_mount_from_this_host_is_refused(docker):
    docker.toml.write_text(GATEWAY_TOML.replace("/var/lib/openshell/tls/jwt/public.pem",
                                                "/etc/keys/public.pem"), encoding="utf-8")
    with pytest.raises(connect.ConnectError, match="does not mount from a folder of this host"):
        _up(docker)
    assert not _redeemed(docker)


def test_a_gateway_that_signs_nothing_is_bound_and_the_note_says_so(docker):
    docker.toml.write_text(GATEWAY_TOML.split("[openshell.gateway.gateway_jwt]")[0],
                           encoding="utf-8")
    _, said = _up(docker)
    assert "OPENSHELL_JWT_PUBLIC_KEY" not in docker.paths.sidecar_env.read_text(encoding="utf-8")
    assert "gateway-jwt.pem" not in docker.ours.read_text(encoding="utf-8")
    assert any("gateway_jwt" in line for line in said)


def test_up_again_after_it_stopped_needs_no_new_token(docker):
    docker.preflight = 1
    with pytest.raises(connect.ConnectError):
        _up(docker)
    docker.preflight = None
    record, _ = _up(docker, token="")
    assert record["connected"] is True
    assert len(_redeemed(docker)) == 1
    # The image was verified once, and kept.
    assert len([c for c in docker.calls if c[0].endswith(upgrade.COSIGN_NAME)]) == 1


def test_a_newer_artzain_moves_the_sidecar_to_its_own_image(docker, monkeypatch):
    _up(docker)
    first = docker.containers[compose.SERVICE]["Id"]
    gateway = docker.containers["gateway"]["Id"]
    newer = "sha256:" + "77" * 32
    docker.cosign_said = [{"critical": {"identity": {"docker-reference": compose.SIDECAR_IMAGE},
                                        "image": {"docker-manifest-digest": newer}}}]
    record = docker.record()
    record["sidecar_image_release"] = "0.0.1"   # what an older artzain verified
    docker.paths.record.write_text(json.dumps(record), encoding="utf-8")
    _up(docker, token="")
    assert docker.containers[compose.SERVICE]["Config"]["Image"] == (
        f"{compose.SIDECAR_IMAGE}@{newer}")
    assert docker.containers[compose.SERVICE]["Id"] != first
    # The gateway restarted with it, and is governed still.
    assert docker.containers["gateway"]["Id"] != gateway and docker.bound
    assert docker.record()["sidecar_image_release"] == __version__


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


def test_remove_puts_the_project_back_and_revokes_the_credential(docker):
    toml, env = docker.toml.read_bytes(), docker.env.read_bytes()
    _up(docker)
    paths = docker.paths
    said = []
    result = connect.remove(docker.host(), out=said.append)
    assert docker.toml.read_bytes() == toml and docker.env.read_bytes() == env
    # The gateway, as the operator's files alone describe it, running.
    gateway = docker.containers["gateway"]
    assert gateway["Config"]["Labels"]["com.docker.compose.config-hash"] == docker.original_hash
    assert gateway["State"]["Status"] == "running"
    assert docker.gateway_files == (docker.compose_yml.as_posix(),)
    # The sidecar, its volumes and up's files are gone.
    assert compose.SERVICE not in docker.containers and docker.volumes == set()
    for path in (docker.ours, paths.sidecar_env, paths.record, paths.toml_backup,
                 paths.artzain_dir / compose.ENV_BACKUP):
        assert not path.exists(), path
    assert result["credential"] == "revoked"
    assert [p["url"] for p in docker.posts if p["url"].endswith("/revoke")] == [
        f"https://engine.example/api/v1/openshell/gateways/{GATEWAY}/revoke"]
    # The gateway is unbound before the sidecar goes.
    recreate = [i for i, c in enumerate(docker.calls) if c[:2] == ["docker", "compose"]
                and "up" in c][-1]
    removed = [i for i, c in enumerate(docker.calls) if c[:2] == ["docker", "rm"]][0]
    assert recreate < removed


def test_remove_recreates_a_stopped_gateway_unbound_and_leaves_it_stopped(docker):
    _up(docker)
    docker.containers["gateway"]["State"] = {"Status": "exited"}
    result = connect.remove(docker.host(), out=lambda _s: None)
    gateway = docker.containers["gateway"]
    assert gateway["Config"]["Labels"]["com.docker.compose.config-hash"] == docker.original_hash
    assert gateway["State"]["Status"] == "created"
    assert not [m for m in gateway["Mounts"] if m["Destination"] == "/run/artzain"]
    assert result["gateway"] == "recreated unbound, and left exited"
    assert compose.SERVICE not in docker.containers and docker.volumes == set()


def test_remove_keeps_edits_made_to_env_since(docker):
    _up(docker)
    with docker.env.open("a", encoding="utf-8") as handle:
        handle.write("OPENSHELL_PORT=8080\n")
    connect.remove(docker.host(), out=lambda _s: None)
    assert docker.env.read_text(encoding="utf-8") == "IMAGE_TAG=0.1.3\nOPENSHELL_PORT=8080\n"


# ---------------------------------------------------------------------------
# status and doctor
# ---------------------------------------------------------------------------


def test_status_says_the_shape_and_both_containers(docker):
    _up(docker)
    found = connect.status(docker.host())
    assert found["shape"] == "compose" and found["connected"] is True
    assert found["gateway"] == "running"
    assert found["sidecar"] == "running (healthy)"
    assert found["compose_file"] is True and found["compose_env"] is True
    assert found["registration_in_gateway_toml"] is True
    assert CREDENTIAL not in json.dumps(found)


def test_doctor_finds_nothing_wrong_on_a_bound_compose_gateway(docker):
    _up(docker)
    found = connect.doctor(docker.host())
    results = {c["check"]: c["result"] for c in found["checks"]}
    assert found["ok"], found
    for check in ("record", "gateway", "sidecar", "credential", "socket", "compose",
                  "registration", "versions", "cli", "engine", "clock", "reports"):
        assert results[check] == "ok", (check, found)
    assert "drop_in" not in results


def test_doctor_says_a_sidecar_connected_by_0_6_45_lists_nothing_until_up_runs_again(docker):
    _up(docker)
    # A sidecar whose settings name no CLI: its inventory is what it saw.
    docker.reported = dict(REPORTED, partial=True)
    reports = next(c for c in connect.doctor(docker.host())["checks"] if c["check"] == "reports")
    assert reports["result"] == "warn" and "seen" in reports["says"]
    assert "artzain connect openshell up" in reports["says"]


def test_doctor_fails_when_docker_compose_in_the_folder_would_unbind_the_gateway(docker):
    _up(docker)
    # Someone took the block out of .env: their next `docker compose up -d`
    # recreates the gateway without the sidecar's socket.
    docker.env.write_text("IMAGE_TAG=0.1.3\n", encoding="utf-8")
    found = connect.doctor(docker.host())
    check = next(c for c in found["checks"] if c["check"] == "compose")
    assert not found["ok"] and check["result"] == "fail"
    assert "docker compose up -d" in check["says"] and "COMPOSE_FILE" in check["says"]


def test_doctor_fails_when_the_operators_files_changed_the_gateway_since(docker):
    _up(docker)
    # .env still names up's file, but the next `docker compose up -d` would
    # recreate the gateway from an edited compose file.
    with docker.compose_yml.open("a", encoding="utf-8") as handle:
        handle.write("    restart: always\n")
    found = connect.doctor(docker.host())
    check = next(c for c in found["checks"] if c["check"] == "compose")
    assert not found["ok"] and check["result"] == "fail"
    assert "otherwise than it runs now" in check["says"]


@pytest.mark.parametrize("socket_said, problem", [
    ({"socket": None, "folder": [False, 0o700, 10001]}, "missing"),
    ({"socket": [True, 0o666, 10001], "folder": [False, 0o700, 10001]}, "other users"),
    ({"socket": [True, 0o600, 10001], "folder": [False, 0o755, 10001]}, "folder is 0755"),
    ({"socket": [False, 0o600, 10001], "folder": [False, 0o700, 10001]}, "not a socket"),
])
def test_doctor_fails_on_a_socket_others_can_reach(docker, socket_said, problem):
    _up(docker)
    docker.socket_said = socket_said
    check = next(c for c in connect.doctor(docker.host())["checks"] if c["check"] == "socket")
    assert check["result"] == "fail" and problem in check["says"]


def test_doctor_fails_when_the_gateway_does_not_mount_the_socket(docker):
    _up(docker)
    gateway = docker.containers["gateway"]
    gateway["Mounts"] = [m for m in gateway["Mounts"] if m["Destination"] != "/run/artzain"]
    check = next(c for c in connect.doctor(docker.host())["checks"] if c["check"] == "socket")
    assert check["result"] == "fail" and "does not mount" in check["says"]


# ---------------------------------------------------------------------------
# rotate-key
# ---------------------------------------------------------------------------


def test_rotate_key_recreates_the_sidecar_with_the_new_credential(docker):
    _up(docker)
    before = docker.containers[compose.SERVICE]["Id"]
    result = connect.rotate_key(docker.host(), out=lambda _s: None)
    assert result == {"gateway_id": GATEWAY, "rotated": True, "old_key_retired": True}
    assert docker.containers[compose.SERVICE]["Id"] != before
    assert NEW_CREDENTIAL in docker.sidecar_env_seen[-1]
    assert docker.live_keys == [NEW_CREDENTIAL]
    assert not docker.commands("systemctl")
