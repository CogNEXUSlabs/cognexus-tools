"""``artzain connect openshell up|remove|status|doctor|rotate-key --kubernetes``.

These run the Kubernetes flows against :class:`_Cluster`, which plays helm
(``get metadata``, ``get values``, ``upgrade``), kubectl (the gateway's
workload, its pod and ConfigMap, Secrets, rollouts, ``exec`` into the
sidecar), the ``openshell`` CLI inside the sidecar, and an engine to redeem
at. A helm upgrade with ArtzAIn's post-renderer gives the pod the sidecar;
one without it leaves a registered gateway that does not start, as the kind
spike showed. The post-renderer's own run of ``kubectl kustomize`` is tested
with the real kubectl when it is on PATH.

What has to hold:

* a release this cannot bind is refused before the token is spent;
* the credential lives in the release's Secret, never on this machine, and
  never on a command line;
* the self-test runs inside the sidecar, without the credential in its
  environment;
* ``remove`` gives the release back the operator's own values, telemetry
  choice included, and revokes the credential;
* ``doctor`` fails on a pod without the sidecar.
"""

from __future__ import annotations

import base64
import copy
import email.utils
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from artzain.openshell import connect, kube, registration

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML")

GATEWAY = "gw_01ABCDEFGHJKMNPQRSTVWXYZ00"
CREDENTIAL = "cnxg_" + "k" * 43
NEW_CREDENTIAL = "cnxg_" + "n" * 43
TOKEN = "cnxt_" + "t" * 43
DECISION = "01JBCDEFGHJKMNPQRSTVWXYZ00"
CONFIG = {"kind": "artzain.openshell.connect", "version": 1,
          "decision_url": "https://engine.example", "openshell_version": "0.1.3",
          "interceptor_timeout_ms": 1500, "decide_timeout_ms": 1200, "telemetry": False}
DIGEST = connect.config_digest(CONFIG)
IMAGE = "ghcr.io/cognexuslabs/artzain-openshell-sidecar@sha256:" + "cd" * 32
PYTHON = "/home/op/.local/share/artzain/openshell/venv/bin/python"
REPORTED = {"reporting": True, "heartbeat": "ok", "inventory": "ok", "sandboxes": 0,
            "partial": False}


def _done(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 1.0
        return self.now


class _Cluster:
    """A cluster with a release of NVIDIA's chart, as the operator's kubectl
    and helm reach it, and an engine."""

    def __init__(self, tmp_path: Path, *, values=None, chart="helm-chart", uid=1000,
                 workloads=1, app_version="0.1.3"):
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.chart, self.app_version, self.uid = chart, app_version, uid
        self.workloads = workloads
        self.values = copy.deepcopy(values or {})
        self.pod_values = copy.deepcopy(self.values)  # what the pod started with
        self.secrets: dict = {}
        self.configmaps: dict = {}      # ArtzAIn's own: the chart's is gateway_toml()
        self.ca_bundles: list = []      # the CA bundle each call to the engine trusted
        # The StatefulSet: its template's sidecar image ("" for none), and its
        # generation; the pod, made from the template of one generation.
        self.template_sidecar = ""
        self.generation = 1
        self.pod_revision = 1
        self.sidecar = False            # the pod holds the sidecar
        self.deleted_pods = 0
        self.ready_before = True        # the pod was ready when the template last changed
        self.slow_start = False         # a new pod is ready only once rollout status waits
        self.starting = False
        self.upgrades: list = []        # each helm upgrade's values and post-renderer
        self.calls: list = []
        self.posts: list = []
        self.live_keys = [CREDENTIAL]
        self.settings = {"proposal_approval_mode": "<unset>"}
        self.restarts = 0
        self.revoke_ok = True
        self.sidecar_running = True     # else it crash-loops beside the gateway
        self.sidecar_dies_after_rollout = False
        self.rollout_ok = True
        self.mint_live = True           # the engine takes the credential it mints
        self.socket_stat = ""           # what the sidecar's stat of its socket says
        self.hook_pods: list = []       # the chart's hook Job pods, with the release's labels

    # --- what the release runs ---------------------------------------------
    def interceptors(self, values=None):
        """The release's (its values, and so its ConfigMap's), or *values*'."""
        return kube.ours(self.values if values is None else values)["interceptors"]

    @property
    def bound(self) -> bool:
        return (bool(self.interceptors(self.pod_values)) and self.sidecar
                and self.secret_key() in self.live_keys)

    def gateway_up(self) -> bool:
        """The pod's gateway, as the configuration it started with has it."""
        found = self.interceptors(self.pod_values)
        if not found:
            return True
        reaches = {i.get("grpc_endpoint") for i in found} == {f"unix://{kube.SOCKET}"}
        return self.sidecar and reaches  # fail_closed: no interceptor, no gateway

    def secret_key(self):
        return (self.secrets.get("os-openshell-artzain") or {}).get("COGNEXUS_API_KEY")

    def gateway_toml(self) -> str:
        text = ('[openshell]\nversion = 2\n[openshell.gateway]\nbind_address = "0.0.0.0:8080"\n')
        found = self.interceptors()
        if found:
            text += "interceptors = [" + ", ".join(
                f'{{ name = "{i["name"]}", grpc_endpoint = "{i["grpc_endpoint"]}" }}'
                for i in found) + "]\n"
        return text + ('[openshell.gateway.gateway_jwt]\ngateway_id = "os-openshell"\n'
                       'public_key_path = "/etc/openshell-jwt/public.pem"\n')

    def ready(self) -> bool:
        return (not self.starting and self.gateway_up()
                and (self.sidecar_running or not self.sidecar))

    def roll(self, *, stuck_too: bool = False) -> None:
        """The StatefulSet controller: the pod is made again from the
        template, unless it never became ready (Kubernetes leaves such a pod
        alone, until it is deleted)."""
        if stuck_too or self.ready_before:
            self.pod_revision = self.generation
            self.sidecar = bool(self.template_sidecar)
            self.pod_values = copy.deepcopy(self.values)
            self.starting = self.slow_start

    def new_generation(self, template_sidecar: str) -> None:
        self.ready_before = self.ready()
        self.generation += 1
        self.template_sidecar = template_sidecar

    def operator_upgrade(self) -> None:
        """The operator's own ``helm upgrade --reuse-values``, without
        ArtzAIn's post-renderer."""
        self.new_generation("")
        self.roll()

    def workload(self):
        inits = ([{"name": kube.SIDECAR, "image": self.template_sidecar}]
                 if self.template_sidecar else [])
        return {"kind": "StatefulSet",
                "metadata": {"name": "os-openshell", "generation": self.generation},
                "status": {"observedGeneration": self.generation,
                           "updateRevision": f"os-openshell-{self.generation}"},
                "spec": {"template": {"spec": {
                "initContainers": inits,
                "securityContext": {"fsGroup": 1000},
                "containers": [{"name": "openshell-gateway",
                                "securityContext": {"runAsUser": self.uid, "runAsGroup": self.uid},
                                "ports": [{"name": "grpc", "containerPort": 8080}]}],
                "volumes": [{"name": "gateway-config",
                             "configMap": {"name": "os-openshell-config"}},
                            {"name": "sandbox-jwt",
                             "secret": {"secretName": "os-openshell-jwt-keys"}}]}}}}

    def pod(self):
        gateway = ({"name": "openshell-gateway", "ready": True, "state": {"running": {}}}
                   if self.gateway_up() else
                   {"name": "openshell-gateway", "ready": False,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}})
        sidecar = ({"name": kube.SIDECAR, "ready": True, "state": {"running": {}}}
                   if self.sidecar_running else
                   {"name": kube.SIDECAR, "ready": False,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}}})
        inits = [sidecar] if self.sidecar else []
        return {"metadata": {"name": "os-openshell-0", "labels": {
                    "controller-revision-hash": f"os-openshell-{self.pod_revision}"}},
                "spec": {"initContainers": [{"name": kube.SIDECAR}] if self.sidecar else [],
                         "containers": [{"name": "openshell-gateway"}]},
                "status": {"initContainerStatuses": inits, "containerStatuses": [gateway],
                           "conditions": [{"type": "Ready",
                                           "status": "True" if self.ready() else "False"}]}}

    # --- commands -------------------------------------------------------------
    def which(self, name):
        return f"/usr/local/bin/{name}" if name in ("kubectl", "helm") else None

    def run(self, argv, env, timeout):
        self.calls.append(list(argv))
        if argv[:3] == ["kubectl", "config", "current-context"]:
            return _done(0, "kind-os\n")
        assert argv[1:5] in (["--kube-context", "kind-os", "--namespace", "openshell"],
                             ["--context", "kind-os", "--namespace", "openshell"]), argv
        args = argv[5:]
        return self._helm(args) if argv[0] == "helm" else self._kubectl(args)

    def _helm(self, args):
        if args[:2] == ["get", "metadata"]:
            if args[2] != "os":
                return _done(1, "", "Error: release: not found")
            return _done(0, json.dumps({"name": "os", "chart": self.chart, "version": "0.1.3",
                                        "appVersion": self.app_version, "namespace": "openshell",
                                        "status": "deployed"}))
        if args[:2] == ["get", "values"]:
            if "--all" in args:
                return _done(0, json.dumps({"server": {"tls": {
                    "clientTlsSecretName": "openshell-client-tls"}}, **self.values}))
            return _done(0, json.dumps(self.values) if self.values else "null")
        if args[0] == "upgrade":
            assert args[1:5] == ["os", kube.CHART, "--version", "0.1.3"], args
            # Without --wait: helm would wait out a pod the StatefulSet never replaces.
            assert "--reset-values" in args and "--wait" not in args
            values = json.loads(Path(args[args.index("--values") + 1]).read_text(encoding="utf-8"))
            renderer = None
            if "--post-renderer" in args:
                at = args.index("--post-renderer")
                renderer = args[at:]
            self.upgrades.append({"values": values, "post_renderer": renderer})
            image = ""
            if renderer:
                given = [a for a in renderer[2:] if a != "--post-renderer-args"]
                image = given[given.index("--image") + 1]
            self.new_generation(image)
            self.values = values
            self.roll()
            return _done(0, "Release \"os\" has been upgraded.\n")
        raise AssertionError(f"unexpected helm {args}")

    def _kubectl(self, args):
        if args[:2] == ["get", "statefulsets,deployments"]:
            assert args[3] == kube.selector("os")
            return _done(0, json.dumps({"items": [self.workload()] * self.workloads}))
        if args[:2] == ["get", "configmap"]:
            if args[2] != "os-openshell-config":
                found = self.configmaps.get(args[2])
                return _done(0, json.dumps({"data": found}) if found is not None else "")
            return _done(0, json.dumps({"data": {"gateway.toml": self.gateway_toml()}}))
        if args[:2] == ["get", "pods"]:
            return _done(0, json.dumps({"items": self.hook_pods + [self.pod()]}))
        if args[:2] == ["get", "statefulset"]:
            assert args[2] == "os-openshell"
            return _done(0, json.dumps(self.workload()))
        if args[:2] == ["delete", "pod"]:
            assert args[2] == "os-openshell-0"
            self.deleted_pods += 1
            self.roll(stuck_too=True)
            return _done(0)
        if args[:2] == ["get", "secret"]:
            found = self.secrets.get(args[2])
            if found is None:
                return _done(0, "")
            return _done(0, json.dumps({"data": {k: base64.b64encode(v.encode()).decode()
                                                 for k, v in found.items()}}))
        if args[:2] == ["apply", "-f"]:
            manifest = json.loads(Path(args[2]).read_text(encoding="utf-8"))
            assert manifest["metadata"]["namespace"] == "openshell"
            if manifest["kind"] == "ConfigMap":
                self.configmaps[manifest["metadata"]["name"]] = dict(manifest["data"])
                return _done(0, "configmap/x configured\n")
            assert manifest["kind"] == "Secret"
            self.secrets[manifest["metadata"]["name"]] = dict(manifest["stringData"])
            return _done(0, "secret/x configured\n")
        if args[:2] == ["delete", "secret"]:
            self.secrets.pop(args[2], None)
            return _done(0)
        if args[:2] == ["delete", "configmap"]:
            self.configmaps.pop(args[2], None)
            return _done(0)
        if args[:2] == ["rollout", "status"]:
            self.starting = False  # rollout status waits out a pod's start
            if self.pod_revision != self.generation and self.ready():
                self.roll(stuck_too=True)  # the controller replaces a ready pod
            done = self.pod_revision == self.generation and self.ready() and self.rollout_ok
            if done and self.sidecar_dies_after_rollout:
                self.sidecar_running = False
            return _done(0 if done else 1, "", "error: timed out waiting for the condition")
        if args[:2] == ["rollout", "restart"]:
            self.restarts += 1
            self.new_generation(self.template_sidecar)
            self.roll()
            return _done(0)
        if args[0] == "exec":
            assert args[1:5] == ["os-openshell-0", "-c", kube.SIDECAR, "--"], args
            return self._in_sidecar(args[5:])
        raise AssertionError(f"unexpected kubectl {args}")

    def _in_sidecar(self, argv):
        assert self.sidecar, "exec into a pod without the sidecar"
        if argv[:1] == ["env"]:
            # The CLI runs without the credential or the sidecar's token.
            assert argv[1:6] == ["-u", "COGNEXUS_API_KEY", "-u", "OPENSHELL_SIDECAR_TOKEN",
                                 "NO_COLOR=1"], argv
            assert argv[6] == kube.CLI
            return self._cli(argv[7:])
        if argv[:2] == ["python", "-c"]:
            if "artzain/reports" in argv[2]:
                ok = self.secret_key() in self.live_keys
                return _done(0, json.dumps(dict(REPORTED, heartbeat="ok" if ok else "failed")))
            if "os.stat" in argv[2]:
                return _done(0, (self.socket_stat or f"True 0o600 {self.uid} 0o700 {self.uid}")
                             + "\n")
        raise AssertionError(f"unexpected exec {argv}")

    def _cli(self, args):
        if not self.gateway_up():
            return _done(1, "", "Error: tcp connect error")
        if args[:2] == ["settings", "set"]:
            key, value = args[args.index("--key") + 1], args[args.index("--value") + 1]
            if self.bound and value == "auto":
                return _done(1, "", "status: PermissionDenied, message: \"gateway interceptor "
                                    f"'artzain' denied the request: decision deny ({DECISION})\"")
            self.settings[key] = value
            return _done(0)
        if args[:2] == ["settings", "get"]:
            return _done(0, "".join(f"  {k} = {v}\n" for k, v in self.settings.items()))
        if args[:1] == ["status"]:
            return _done(0, '{"version": "0.1.3"}')
        raise AssertionError(f"unexpected openshell {args}")

    # --- the engine -----------------------------------------------------------
    def post_json(self, url, *, headers, body, proxy="", ca_bundle=""):
        self.posts.append(url)
        self.ca_bundles.append(ca_bundle)
        if url.endswith(connect.REDEEM_PATH):
            return 200, {"gateway_id": GATEWAY, "credential": CREDENTIAL,
                         "config_digest": DIGEST, "config": CONFIG}
        if url.endswith("/revoke"):
            return (200, {"revoked": True}) if self.revoke_ok else (503, {})
        key = headers["X-Api-Key"]
        if key not in self.live_keys:
            return 401, {}
        if url.endswith("/keys/retire-others"):
            self.live_keys = [key]
            return 200, {"retired": 1}
        if url.endswith("/keys"):
            if self.mint_live:
                self.live_keys.append(NEW_CREDENTIAL)
            return 200, {"credential": NEW_CREDENTIAL}
        raise AssertionError(url)

    def host(self, **overrides) -> connect.Host:
        settings = dict(
            environ={"HOME": str(self.home), "PATH": "/usr/bin"}, runner=self.run,
            post_json=self.post_json, which=self.which, sleep=lambda _s: None, clock=_Clock(),
            wall=lambda: 1_800_000_000.0, platform="linux", executable=PYTHON, uid=1000, gid=1000,
            get_engine=lambda url, proxy="", ca_bundle="": (
                200, {"Date": email.utils.formatdate(1_800_000_000.0, usegmt=True)}))
        settings.update(overrides)
        return connect.Host(**settings)

    def target(self, host=None):
        return kube.target(host or self.host(), namespace="openshell", release="os")

    def up(self, **overrides):
        host = self.host()
        return kube.up(host, self.target(host), token=TOKEN, digest=DIGEST,
                       engine="https://engine.example", out=lambda _s: None, **overrides)

    def kubectl_calls(self, verb):
        return [c for c in self.calls if c[0] == "kubectl" and c[5:6] == [verb]]


@pytest.fixture(autouse=True)
def verified_image(monkeypatch):
    """cosign's check of the sidecar image, as compose.verify_image gives it."""
    monkeypatch.setattr(connect, "_sidecar_image",
                        lambda host, record, named, out: (named or IMAGE, "0.6.50"))


@pytest.fixture
def cluster(tmp_path):
    return _Cluster(tmp_path)


# ---------------------------------------------------------------------------
# Which release
# ---------------------------------------------------------------------------


def test_the_target_is_kubectls_current_context_when_none_is_named(cluster):
    found = cluster.target()
    assert (found.context, found.namespace, found.release) == ("kind-os", "openshell", "os")


@pytest.mark.parametrize("change, says", [
    ({"namespace": "Not_A_Name"}, "--namespace"),
    ({"release": "x" * 300}, "--release"),
    ({"context": "has space"}, "--kube-context"),
], ids=["namespace", "release", "context"])
def test_a_target_that_is_not_one_is_refused(cluster, change, says):
    settings = {"namespace": "openshell", "release": "os", **change}
    with pytest.raises(connect.ConnectError, match=says):
        kube.target(cluster.host(), **settings)


def test_without_kubectl_and_helm_nothing_runs(cluster):
    with pytest.raises(connect.ConnectError, match="kubectl is not on PATH"):
        kube.target(cluster.host(which=lambda name: None), namespace="openshell", release="os")


def test_the_release_is_read_from_the_cluster(cluster):
    release = kube.find(cluster.host(), cluster.target())
    assert (release.kind, release.fullname, release.uid, release.port) == (
        "StatefulSet", "os-openshell", 1000, 8080)
    assert (release.gateway_id, release.jwt_secret, release.client_tls) == (
        "os-openshell", "os-openshell-jwt-keys", "openshell-client-tls")
    assert (release.chart_version, release.openshell_version) == ("0.1.3", "0.1.3")


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


def test_up_binds_the_releases_gateway(cluster):
    record = cluster.up()
    assert record["connected"] and record["self_test_decision_id"] == DECISION
    assert record["shape"] == "kubernetes"
    assert record["kubernetes"]["fullname"] == "os-openshell"
    assert cluster.bound
    [upgrade] = cluster.upgrades
    names = [i["name"] for i in upgrade["values"]["gatewayConfig"]["openshell.gateway"]
             ["interceptors"]]
    assert names == list(registration.NAMES)
    release = kube.find(cluster.host(), cluster.target())
    assert upgrade["post_renderer"] == kube.helm_args(PYTHON, release.render(IMAGE, 8088))


def test_the_credential_is_the_secrets_and_never_this_machines(cluster):
    cluster.up()
    settings = cluster.secrets["os-openshell-artzain"]
    assert settings["COGNEXUS_API_KEY"] == CREDENTIAL
    assert settings["OPENSHELL_GATEWAY_ID"] == GATEWAY
    assert len(settings["OPENSHELL_SIDECAR_TOKEN"]) >= 40
    text = registration.render(f"unix://{kube.SOCKET}", timeout_ms=1500)
    assert settings["OPENSHELL_REGISTRATION_DIGEST"] == registration.digest(text)
    # Nothing on this machine holds it, and no command line carried it.
    held = [p for p in cluster.home.rglob("*") if p.is_file()
            and CREDENTIAL in p.read_text(encoding="utf-8", errors="replace")]
    assert held == []
    assert not [c for c in cluster.calls if any(CREDENTIAL in a for a in c)]


def test_the_self_test_runs_inside_the_sidecar(cluster):
    cluster.up()
    sets = [c for c in cluster.kubectl_calls("exec") if "settings" in c and "set" in c]
    assert [c[c.index("--value") + 1] for c in sets] == ["manual", "auto"]
    assert cluster.settings["proposal_approval_mode"] == "manual"


@pytest.mark.parametrize("cluster_settings, says", [
    ({"chart": "someone-elses"}, "not NVIDIA's OpenShell chart"),
    ({"workloads": 2}, "runs 2 gateway workloads"),
    ({"uid": 0}, "as root"),
    ({"values": {"gatewayConfig": {"openshell.gateway": {"interceptors": [
        {"name": "artzain", "grpc_endpoint": "unix:///x.sock"}]}}}}, "already register artzain"),
], ids=["chart", "two", "root", "theirs"])
def test_a_release_this_cannot_bind_spends_no_token(tmp_path, cluster_settings, says):
    cluster = _Cluster(tmp_path, **cluster_settings)
    with pytest.raises(connect.ConnectError, match=says):
        cluster.up()
    assert cluster.posts == [] and cluster.upgrades == [] and cluster.secrets == {}


def test_the_proxy_of_this_shell_is_refused_on_kubernetes(cluster):
    with pytest.raises(connect.ConnectError, match="name the proxy"):
        cluster.up(proxy="env")
    assert cluster.posts == []


def test_another_openshell_line_stops_after_the_redeem(tmp_path):
    cluster = _Cluster(tmp_path, app_version="0.2.0")
    with pytest.raises(connect.ConnectError, match="upgrade the release to that one"):
        cluster.up()
    assert cluster.upgrades == []
    assert cluster.secrets["os-openshell-artzain"]["COGNEXUS_API_KEY"] == CREDENTIAL


def test_up_again_changes_nothing(cluster):
    cluster.up()
    cluster.calls.clear()
    record = cluster.up()
    assert record["connected"] and len(cluster.upgrades) == 1
    assert not [c for c in cluster.calls if c[0] == "helm" and "upgrade" in c]


def test_up_keeps_the_operators_values(tmp_path):
    mine = {"server": {"logLevel": "debug", "extraVolumes": [{"name": "ocsf", "emptyDir": {}}]},
            "replicaCount": 1}
    cluster = _Cluster(tmp_path, values=mine)
    cluster.up()
    values = cluster.upgrades[0]["values"]
    assert values["replicaCount"] == 1 and values["server"]["logLevel"] == "debug"
    assert [v["name"] for v in values["server"]["extraVolumes"]] == [
        "ocsf", kube.RUN_VOLUME, kube.STATE_VOLUME]


# ---------------------------------------------------------------------------
# status, doctor
# ---------------------------------------------------------------------------


def test_status_says_the_release_its_pod_and_the_post_renderer(cluster):
    cluster.up()
    said = kube.status(cluster.host(), cluster.target())
    assert said["shape"] == "kubernetes" and said["connected"]
    assert (said["sidecar"], said["gateway"]) == ("ready", "ready")
    assert said["registration_in_values"] and said["registration_in_gateway_toml"]
    assert said["credential_saved"] and said["reports"]["heartbeat"] == "ok"
    assert said["helm_post_renderer"][:2] == ["--post-renderer", PYTHON]
    assert CREDENTIAL not in json.dumps(said)


def test_doctor_finds_a_bound_release_well(cluster):
    cluster.up()
    said = kube.doctor(cluster.host(), cluster.target())
    assert said["ok"], said["checks"]
    assert {c["check"] for c in said["checks"]} >= {
        "record", "release", "versions", "values", "registration", "credential", "sidecar",
        "gateway", "socket", "cli", "reports"}


def test_doctor_fails_on_a_pod_an_upgrade_left_without_the_sidecar(cluster):
    cluster.up()
    cluster.sidecar = False  # the operator's own helm upgrade, without the post-renderer
    said = kube.doctor(cluster.host(), cluster.target())
    checks = {c["check"]: c for c in said["checks"]}
    assert not said["ok"]
    assert checks["sidecar"]["result"] == "fail" and "post-renderer" in checks["sidecar"]["says"]
    assert checks["gateway"]["says"].endswith("CrashLoopBackOff")


def test_doctor_fails_when_the_values_lost_the_registration(cluster):
    cluster.up()
    cluster.values = {}
    said = kube.doctor(cluster.host(), cluster.target())
    checks = {c["check"]: c for c in said["checks"]}
    assert checks["values"]["result"] == "fail"
    assert checks["registration"]["result"] == "fail"


# ---------------------------------------------------------------------------
# remove, rotate-key
# ---------------------------------------------------------------------------


def test_remove_gives_the_release_back_its_own_values(tmp_path):
    mine = {"server": {"telemetryEnabled": True, "logLevel": "debug"}}
    cluster = _Cluster(tmp_path, values=mine)
    cluster.up()
    assert cluster.values["server"]["telemetryEnabled"] is False  # the approved choice
    result = kube.remove(cluster.host(), cluster.target(), out=lambda _s: None)
    assert cluster.values == mine and not cluster.sidecar
    assert cluster.upgrades[-1]["post_renderer"] is None
    assert result["credential"] == "revoked" and result["secret"] == "deleted"
    assert cluster.secrets == {}
    assert not kube.record_path(cluster.host(), cluster.target()).exists()


def test_remove_without_a_telemetry_choice_of_the_operators_takes_out_up_s(cluster):
    cluster.up()
    kube.remove(cluster.host(), cluster.target(), out=lambda _s: None)
    assert cluster.values == {}


def test_a_credential_the_engine_cannot_revoke_keeps_the_secret(cluster):
    cluster.up()
    cluster.revoke_ok = False
    result = kube.remove(cluster.host(), cluster.target(), out=lambda _s: None)
    assert result["credential"] == "NOT revoked"
    assert "os-openshell-artzain" in cluster.secrets
    assert kube.record_path(cluster.host(), cluster.target()).exists()


def test_rotate_key_restarts_the_pod_with_the_new_credential(cluster):
    cluster.up()
    said = kube.rotate_key(cluster.host(), cluster.target(), out=lambda _s: None)
    assert said["rotated"] and said["old_key_retired"]
    assert cluster.secret_key() == NEW_CREDENTIAL and cluster.restarts == 1
    assert cluster.live_keys == [NEW_CREDENTIAL]


def test_rotate_key_goes_back_to_the_old_credential_when_the_new_one_is_not_taken(cluster):
    cluster.up()
    cluster.mint_live = False  # the engine refuses the heartbeat with the new credential
    with pytest.raises(connect.ConnectError, match="back on the old credential"):
        kube.rotate_key(cluster.host(), cluster.target(), out=lambda _s: None)
    assert cluster.secret_key() == CREDENTIAL and cluster.restarts == 2
    assert cluster.live_keys == [CREDENTIAL]


def test_remove_keeping_the_credential_revokes_nothing(cluster):
    cluster.up()
    cluster.posts.clear()
    result = kube.remove(cluster.host(), cluster.target(), keep_credential=True,
                         out=lambda _s: None)
    assert cluster.posts == [] and "credential" not in result
    assert cluster.secrets == {} and cluster.live_keys == [CREDENTIAL]


# ---------------------------------------------------------------------------
# A pod that is not as up left it
# ---------------------------------------------------------------------------


def test_up_again_mends_an_upgrade_without_the_post_renderer(cluster):
    cluster.up()
    assert cluster.deleted_pods == 0
    cluster.operator_upgrade()  # the gateway crash-loops: fail closed
    assert not cluster.sidecar and not cluster.ready()
    record = cluster.up()
    assert record["connected"] and cluster.bound and cluster.ready()
    assert len(cluster.upgrades) == 2 and cluster.upgrades[-1]["post_renderer"]
    # The StatefulSet replaces no pod that never became ready: up deletes it.
    assert cluster.deleted_pods == 1


#: A hook of the chart's: a Job's pod, with the release's labels, done (named
#: to come before the gateway's pod).
CERTGEN = {"metadata": {"name": "os-hook-certgen-x1", "labels": {}},
           "spec": {"containers": [{"name": "certgen"}]},
           "status": {"containerStatuses": [{"name": "certgen", "ready": False,
                                             "state": {"terminated": {"reason": "Completed"}}}],
                      "conditions": [{"type": "Ready", "status": "False"}]}}


def test_the_charts_hook_pods_are_left_alone(cluster):
    """The chart's certgen Job runs at each install and upgrade, and its pod
    has the release's labels: up neither deletes it nor reads it as the
    gateway's."""
    cluster.hook_pods = [CERTGEN]
    cluster.up()
    cluster.operator_upgrade()
    record = cluster.up()
    assert record["connected"] and cluster.deleted_pods == 1
    said = kube.status(cluster.host(), cluster.target())
    assert (said["pod"], said["sidecar"], said["gateway"]) == ("os-openshell-0", "ready", "ready")


def test_a_pod_still_starting_is_left_to_start(cluster):
    cluster.slow_start = True
    record = cluster.up()
    assert record["connected"] and cluster.deleted_pods == 0


def test_remove_after_an_upgrade_without_the_post_renderer_brings_the_gateway_up(cluster):
    cluster.up()
    cluster.operator_upgrade()
    kube.remove(cluster.host(), cluster.target(), out=lambda _s: None)
    assert not cluster.interceptors() and not cluster.sidecar
    assert cluster.ready() and cluster.pod_revision == cluster.generation
    assert cluster.deleted_pods == 1


def test_up_stops_on_a_gateway_that_does_not_come_up(cluster):
    cluster.rollout_ok = False
    with pytest.raises(connect.ConnectError, match="the gateway did not come up"):
        cluster.up()
    assert not cluster.kubectl_calls("exec")


def test_up_needs_the_sidecar_running(cluster):
    cluster.sidecar_dies_after_rollout = True
    with pytest.raises(connect.ConnectError, match="runs the ArtzAIn sidecar"):
        cluster.up()
    assert not cluster.kubectl_calls("exec")


def test_doctor_fails_on_a_sidecar_that_does_not_run(cluster):
    cluster.up()
    cluster.sidecar_running = False
    said = kube.doctor(cluster.host(), cluster.target())
    checks = {c["check"]: c for c in said["checks"]}
    assert not said["ok"] and checks["sidecar"]["result"] == "fail"
    assert checks["sidecar"]["says"].endswith("CrashLoopBackOff")


@pytest.mark.parametrize("stat, says", [
    ("True 0o666 1000 0o700 1000", "it is 0o666, so other users can call the interceptor"),
    ("True 0o600 1000 0o755 1000", "its folder is 0o755"),
    ("True 0o600 0 0o700 1000", "it is not the gateway's user's"),
    ("True 0o600 1000 0o700 0", "it is not the gateway's user's"),
    ("False 0o600 1000 0o700 1000", "it is not a socket"),
], ids=["open-socket", "open-folder", "socket-owner", "folder-owner", "not-a-socket"])
def test_doctor_fails_on_a_socket_others_can_reach(cluster, stat, says):
    cluster.up()
    cluster.socket_stat = stat
    said = kube.doctor(cluster.host(), cluster.target())
    socket = {c["check"]: c for c in said["checks"]}["socket"]
    assert not said["ok"] and socket["result"] == "fail" and says in socket["says"]


def test_status_says_when_the_values_lost_the_registration(cluster):
    cluster.up()
    cluster.values = {}
    said = kube.status(cluster.host(), cluster.target())
    assert said["registration_in_values"] is False
    assert said["registration_in_gateway_toml"] is False


# ---------------------------------------------------------------------------
# An engine behind a private certificate authority
# ---------------------------------------------------------------------------

#: A certificate authority made for these tests alone (its key is gone).
TEST_CA = """\
-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUcgPMu6NZqQj+a6hSLmYPKEKDiEAwCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUYXJ0emFpbiBrdWJlIHRlc3QgQ0EwIBcNMjYxMDEzMDEyMjQy
WhgPMjEyNjA5MTkwMTIyNDJaMB8xHTAbBgNVBAMMFGFydHphaW4ga3ViZSB0ZXN0
IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzliOUZ1K7iSZgY5gWJvGTRUI
lrh6C12YL0dPE6TzdcVvTy5aISUBIaVUp9wNooqHhbUGbsJk66egCemoffjOHaNT
MFEwHQYDVR0OBBYEFLMIP4GdA3Z/DTAvCxKQDELHpS8xMB8GA1UdIwQYMBaAFLMI
P4GdA3Z/DTAvCxKQDELHpS8xMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID
SAAwRQIgLtYdJIMyULHx/smZ9m2iXrZyp3RcNlXZRKW00CcwHwQCIQC+8F0/pxWx
NFjjzWDf99a4O7zaPaG1Hlh/4JRAfPaBOg==
-----END CERTIFICATE-----
"""
CA_MAP = "os-openshell-artzain-ca"


@pytest.fixture(params=["lf", "crlf"])
def ca_file(tmp_path, request):
    """The bundle, as Linux or Windows writes it: the cluster gets one form."""
    path = tmp_path / "corp-ca.pem"
    ending = "\r\n" if request.param == "crlf" else "\n"
    path.write_bytes(TEST_CA.replace("\n", ending).encode("ascii"))
    return path


def _flag(args, name):
    """The value Helm passes the post-renderer for *name*, or None."""
    given = [a for a in args[2:] if a != "--post-renderer-args"]
    return given[given.index(name) + 1] if name in given else None


def test_a_private_ca_reaches_the_sidecar_in_a_configmap(cluster, ca_file):
    record = cluster.up(ca_bundle=str(ca_file))
    assert record["connected"]
    assert cluster.configmaps == {CA_MAP: {kube.CA_KEY: TEST_CA}}
    assert _flag(cluster.upgrades[0]["post_renderer"], "--ca-bundle-configmap") == CA_MAP
    # This machine's own calls to the engine trust it too.
    assert set(cluster.ca_bundles) == {str(ca_file)}
    said = kube.status(cluster.host(), cluster.target())
    assert _flag(said["helm_post_renderer"], "--ca-bundle-configmap") == CA_MAP


def test_the_sidecar_trusts_the_authorities_in_the_configmap():
    render = kube.Render(kind="StatefulSet", release="os", fullname="os-openshell", image=IMAGE,
                         uid=1000, gid=1000, port=8080, gateway_id="os-openshell",
                         ca_bundle=CA_MAP)
    container = kube.sidecar(render)
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["OPENSHELL_SIDECAR_CA_BUNDLE"] == kube.CA_BUNDLE
    mounts = {m["name"]: m for m in container["volumeMounts"]}
    assert mounts[kube.CA_VOLUME] == {"name": kube.CA_VOLUME, "readOnly": True,
                                      "mountPath": kube.CA_BUNDLE.rsplit("/", 1)[0]}
    volumes = {v["name"]: v for v in kube.patch(render)["spec"]["template"]["spec"]["volumes"]}
    assert volumes[kube.CA_VOLUME]["configMap"]["name"] == CA_MAP
    assert volumes[kube.CA_VOLUME]["configMap"]["items"] == [{"key": kube.CA_KEY,
                                                              "path": kube.CA_KEY}]
    argv = [a for a in kube.helm_args(PYTHON, render)[2:] if a != "--post-renderer-args"]
    assert kube.render_of(_parsed(argv[4:])) == render


def test_without_a_private_ca_the_sidecar_trusts_the_systems():
    render = kube.Render(kind="StatefulSet", release="os", fullname="os-openshell", image=IMAGE,
                         uid=1000, gid=1000, port=8080, gateway_id="os-openshell")
    container = kube.sidecar(render)
    assert "OPENSHELL_SIDECAR_CA_BUNDLE" not in {e["name"] for e in container["env"]}
    assert kube.CA_VOLUME not in {m["name"] for m in container["volumeMounts"]}
    assert "--ca-bundle-configmap" not in render.args()


@pytest.mark.parametrize("content", [
    b"not a certificate\n",
    b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    b"\xff\xfe" + TEST_CA.encode("utf-16-le"),
    TEST_CA.encode("ascii") * 2000,
], ids=["text", "broken", "not-ascii", "too-large"])
def test_a_ca_bundle_this_cannot_read_spends_no_token(cluster, tmp_path, content):
    path = tmp_path / "ca.pem"
    path.write_bytes(content)
    with pytest.raises(connect.ConnectError, match="--ca-bundle"):
        cluster.up(ca_bundle=str(path))
    assert cluster.posts == [] and cluster.configmaps == {} and cluster.upgrades == []


def test_a_ca_bundle_that_is_not_there_spends_no_token(cluster, tmp_path):
    with pytest.raises(connect.ConnectError, match="--ca-bundle"):
        cluster.up(ca_bundle=str(tmp_path / "missing.pem"))
    assert cluster.posts == []


def test_up_again_keeps_the_private_ca(cluster, ca_file):
    cluster.up(ca_bundle=str(ca_file))
    record = cluster.up()
    assert record["connected"] and len(cluster.upgrades) == 1
    assert cluster.configmaps == {CA_MAP: {kube.CA_KEY: TEST_CA}}


def test_up_with_a_private_ca_on_a_bound_release_adds_it(cluster, ca_file):
    cluster.up()
    cluster.up(ca_bundle=str(ca_file))
    assert len(cluster.upgrades) == 2
    assert _flag(cluster.upgrades[-1]["post_renderer"], "--ca-bundle-configmap") == CA_MAP


def test_remove_revokes_through_the_private_ca_and_takes_out_its_configmap(cluster, ca_file):
    cluster.up(ca_bundle=str(ca_file))
    cluster.ca_bundles.clear()
    result = kube.remove(cluster.host(), cluster.target(), out=lambda _s: None)
    assert result["credential"] == "revoked" and cluster.ca_bundles == [str(ca_file)]
    assert cluster.configmaps == {} and result["ca_bundle"] == "deleted"


def test_rotate_key_reaches_the_engine_through_the_private_ca(cluster, ca_file):
    cluster.up(ca_bundle=str(ca_file))
    cluster.ca_bundles.clear()
    kube.rotate_key(cluster.host(), cluster.target(), out=lambda _s: None)
    assert cluster.ca_bundles and set(cluster.ca_bundles) == {str(ca_file)}


# ---------------------------------------------------------------------------
# The post-renderer, with the real kubectl
# ---------------------------------------------------------------------------

_WORKLOADS = """\
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: os-openshell
  labels:
    app.kubernetes.io/name: openshell
    app.kubernetes.io/instance: os
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: openshell
  template:
    metadata:
      labels:
        app.kubernetes.io/name: openshell
    spec:
      initContainers:
        - name: chart-init
          image: busybox
      containers:
        - name: openshell-gateway
          image: ghcr.io/nvidia/openshell/gateway:0.1.3
      volumes:
        - name: gateway-config
          configMap:
            name: os-openshell-config
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: other-openshell
  labels:
    app.kubernetes.io/name: openshell
    app.kubernetes.io/instance: other
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: openshell
  template:
    metadata:
      labels:
        app.kubernetes.io/name: openshell
    spec:
      containers:
        - name: openshell-gateway
          image: ghcr.io/nvidia/openshell/gateway:0.1.3
"""


@pytest.mark.skipif(not shutil.which("kubectl"), reason="needs kubectl (CI has it)")
def test_kustomize_adds_the_sidecar_to_the_release_alone_and_keeps_the_charts_own():
    def run(command):
        return subprocess.run(command, capture_output=True, text=True, timeout=120,
                              check=True).stdout

    render = kube.Render(kind="StatefulSet", release="os", fullname="os-openshell", image=IMAGE,
                         uid=1000, gid=1000, port=8080, gateway_id="os-openshell",
                         jwt_secret="os-openshell-jwt-keys")
    out = kube.post_render(_WORKLOADS, render, run)
    by_name = {doc.split("  name: ", 1)[1].split("\n", 1)[0]: doc
               for doc in out.split("\n---\n")}
    mine, theirs = by_name["os-openshell"], by_name["other-openshell"]
    assert "name: chart-init" in mine and f"name: {kube.SIDECAR}" in mine
    assert "name: gateway-config" in mine and f"name: {kube.TLS_VOLUME}" in mine
    assert kube.SIDECAR not in theirs


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------

_RENDER_ARGS = ["--kind", "StatefulSet", "--release", "os", "--fullname", "os-openshell",
                "--image", IMAGE, "--uid", "1000", "--gid", "1000", "--port", "8080",
                "--gateway-id", "os-openshell", "--jwt-secret", "os-openshell-jwt-keys"]


def _parsed(argv):
    import argparse

    parser = argparse.ArgumentParser()
    kube.render_arguments(parser)
    return parser.parse_args(argv)


@pytest.mark.skipif(not shutil.which("kubectl"), reason="needs kubectl (CI has it)")
def test_kube_render_is_helms_post_renderer(monkeypatch, capsys):
    import artzain.cli as cli

    monkeypatch.setattr(sys, "stdin", io.StringIO(_WORKLOADS))
    cli.main(["openshell", "kube-render", *_RENDER_ARGS])
    out = capsys.readouterr().out
    assert f"name: {kube.SIDECAR}" in out and f"image: {IMAGE}" in out


def test_kube_render_refuses_what_it_cannot_patch(monkeypatch):
    import artzain.cli as cli

    monkeypatch.setattr(sys, "stdin", io.StringIO(_WORKLOADS))
    argv = ["Job" if a == "StatefulSet" else a for a in _RENDER_ARGS]
    with pytest.raises(SystemExit, match="^artzain openshell kube-render: .*Job"):
        cli.main(["openshell", "kube-render", *argv])


def test_kube_render_without_kubectl_says_so(monkeypatch):
    def run(*_args, **_kwargs):
        raise FileNotFoundError(2, "No such file or directory", "kubectl")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(connect.ConnectError, match="kubectl is not on PATH"):
        kube.render_stdio(kube.render_of(_parsed(_RENDER_ARGS)), io.StringIO(_WORKLOADS),
                          io.StringIO())


def test_the_render_options_are_the_ones_helm_args_gives():
    render = kube.Render(kind="Deployment", release="os", fullname="os-openshell", image=IMAGE,
                         uid=1001, gid=1002, port=9090, gateway_id="gw", jwt_secret="jwt",
                         client_tls="tls", sidecar_port=8099)
    given = kube.helm_args(PYTHON, render)
    argv = [a for a in given[2:] if a != "--post-renderer-args"]
    assert argv[:4] == ["-m", "artzain.cli", "openshell", "kube-render"]
    assert kube.render_of(_parsed(argv[4:])) == render


@pytest.fixture
def kube_calls(monkeypatch):
    """``kube``'s flows, as the command line calls them."""
    calls = []

    def flow(name, answer=None):
        def called(host, target, **kwargs):
            calls.append((name, target, kwargs))
            return answer
        return called

    monkeypatch.setattr(kube, "target", lambda host, **kwargs: kwargs)
    monkeypatch.setattr(kube, "up", flow("up"))
    monkeypatch.setattr(kube, "remove", flow("remove"))
    monkeypatch.setattr(kube, "rotate_key", flow("rotate_key"))
    monkeypatch.setattr(kube, "status", flow("status", {"shape": "kubernetes"}))
    monkeypatch.setattr(kube, "doctor", flow("doctor", {"ok": False, "checks": [
        {"check": "sidecar", "result": "fail", "says": "no sidecar"}]}))
    monkeypatch.setattr(connect, "up", lambda *a, **k: calls.append(("host up", None, k)))
    return calls


def test_kubernetes_sends_up_to_the_release(monkeypatch, kube_calls):
    import artzain.cli as cli

    monkeypatch.setenv("ARTZAIN_ENROLL_TOKEN", f" {TOKEN} ")
    cli.main(["connect", "openshell", "up", "--kubernetes", "--namespace", "gw", "--release",
              "os", "--kube-context", "kind-os", "--config-digest", DIGEST.upper(),
              "--sidecar-image", IMAGE])
    [(name, target, kwargs)] = kube_calls
    assert name == "up"
    assert target == {"namespace": "gw", "release": "os", "context": "kind-os"}
    assert (kwargs["token"], kwargs["digest"], kwargs["sidecar_image"]) == (TOKEN, DIGEST, IMAGE)


def test_without_kubernetes_up_is_this_hosts(kube_calls):
    import artzain.cli as cli

    cli.main(["connect", "openshell", "up"])
    assert [c[0] for c in kube_calls] == ["host up"]


@pytest.mark.parametrize("command, name", [
    (["remove", "--keep-credential"], "remove"), (["rotate-key"], "rotate_key"),
    (["status"], "status"),
], ids=["remove", "rotate-key", "status"])
def test_kubernetes_sends_each_command_to_the_release(kube_calls, command, name):
    import artzain.cli as cli

    cli.main(["connect", "openshell", *command, "--kubernetes"])
    [(called, target, kwargs)] = kube_calls
    assert called == name
    assert target == {"namespace": "openshell", "release": "openshell", "context": ""}
    if name == "remove":
        assert kwargs == {"keep_credential": True}


def test_a_failed_kubernetes_doctor_exits_one(kube_calls, capsys):
    import artzain.cli as cli

    with pytest.raises(SystemExit) as exited:
        cli.main(["connect", "openshell", "doctor", "--kubernetes"])
    assert exited.value.code == 1
    assert capsys.readouterr().out.split() == ["FAIL", "sidecar", "no", "sidecar"]
