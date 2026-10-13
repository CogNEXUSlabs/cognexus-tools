"""``artzain connect openshell --kubernetes``: NVIDIA's OpenShell chart.

These test what binding a release is made of, without a cluster: the values
``up`` adds to the release's own (and takes out again), the strategic merge
patch the post-renderer gives ``kubectl kustomize``, and the post-renderer
itself. A kind cluster runs the rest in the OpenShell conformance workflow.

What has to hold:

* the registration goes under the chart's dotted ``gatewayConfig`` key, and
  everything of the operator's in the values stays, through ``up`` and
  ``remove``;
* an ArtzAIn registration ``up`` did not put is refused, not replaced;
* the sidecar runs as the gateway's user, never root, from an image named by
  its digest, reads its settings from a Secret and nothing secret from the
  patch, and keeps its socket where the registration names it;
* the post-renderer refuses output in which it added no sidecar.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from artzain.openshell import connect, kube, registration

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="connect reads TOML")

IMAGE = "ghcr.io/cognexuslabs/artzain-openshell-sidecar@sha256:" + "ab" * 32


def _registration():
    import tomllib  # 3.11 on; the module skips on 3.10

    return tomllib.loads(registration.render(f"unix://{kube.SOCKET}", timeout_ms=1500))


def _render(**overrides):
    settings = dict(kind="StatefulSet", release="os", fullname="os-openshell", image=IMAGE,
                    uid=1000, gid=1000, port=8080, gateway_id="os-openshell",
                    jwt_secret="os-openshell-jwt-keys")
    settings.update(overrides)
    return kube.Render(**settings)


# ---------------------------------------------------------------------------
# The chart's values
# ---------------------------------------------------------------------------


def test_the_registration_goes_under_the_charts_dotted_gateway_key():
    values = kube.bound({}, _registration(), telemetry=False)
    interceptors = values["gatewayConfig"]["openshell.gateway"]["interceptors"]
    assert [i["name"] for i in interceptors] == list(registration.NAMES)
    assert {i["grpc_endpoint"] for i in interceptors} == {f"unix://{kube.SOCKET}"}
    assert "openshell" not in values["gatewayConfig"]
    assert values["server"]["extraVolumes"] == [{"name": kube.RUN_VOLUME, "emptyDir": {}},
                                                {"name": kube.STATE_VOLUME, "emptyDir": {}}]
    assert values["server"]["extraVolumeMounts"] == [{"name": kube.RUN_VOLUME,
                                                      "mountPath": kube.RUN}]
    assert values["server"]["telemetryEnabled"] is False


def test_the_operators_own_values_stay_through_up_and_remove():
    mine = {
        "gatewayConfig": {"openshell": {"version": 2},
                          "openshell.gateway": {"log_level": "debug", "interceptors": [
                              {"name": "audit", "grpc_endpoint": "unix:///run/audit.sock"}]}},
        "server": {"extraVolumes": [{"name": "ocsf", "emptyDir": {}}],
                   "extraVolumeMounts": [{"name": "ocsf", "mountPath": "/ocsf"}],
                   "logLevel": "debug"},
        "replicaCount": 1,
    }
    values = kube.bound(mine, _registration(), telemetry=True)
    gateway = values["gatewayConfig"]["openshell.gateway"]
    assert [i["name"] for i in gateway["interceptors"]] == ["audit", *registration.NAMES]
    assert gateway["log_level"] == "debug" and values["replicaCount"] == 1
    assert [v["name"] for v in values["server"]["extraVolumes"]] == [
        "ocsf", kube.RUN_VOLUME, kube.STATE_VOLUME]
    assert values["server"]["telemetryEnabled"] is True
    unbound = kube.without(values)
    del unbound["server"]["telemetryEnabled"]
    assert unbound == mine


def test_up_again_replaces_its_own_registration_only():
    values = kube.bound({}, _registration(), telemetry=False)
    again = kube.bound(values, _registration(), telemetry=False, replace=True)
    assert again == values


def test_an_artzain_registration_up_did_not_put_is_refused():
    theirs = {"gatewayConfig": {"openshell.gateway": {"interceptors": [
        {"name": "artzain", "grpc_endpoint": "unix:///elsewhere.sock"}]}}}
    with pytest.raises(connect.ConnectError, match="already register artzain"):
        kube.bound(theirs, _registration(), telemetry=False)


@pytest.mark.parametrize("values, says", [
    ({"gatewayConfig": {"openshell": {"version": 2, "gateway": {"log_level": "x"}}}},
     "dotted key"),
    ({"gatewayConfig": {"openshell.gateway": {"interceptors": "x"}}}, "not a list"),
    ({"gatewayConfig": "x"}, "not a map"),
    ({"server": {"extraVolumes": {}}}, "server.extraVolumes is not a list"),
], ids=["nested", "interceptors", "config", "volumes"])
def test_values_up_cannot_add_to_are_refused(values, says):
    with pytest.raises(connect.ConnectError, match=says):
        kube.bound(values, _registration(), telemetry=False)


def test_without_leaves_nothing_up_added():
    assert kube.without(kube.bound({}, _registration(), telemetry=False)) == {
        "server": {"telemetryEnabled": False}}


# ---------------------------------------------------------------------------
# The patch
# ---------------------------------------------------------------------------


def test_the_patch_adds_a_native_sidecar_as_the_gateways_user():
    smp = kube.patch(_render())
    assert (smp["apiVersion"], smp["kind"]) == ("apps/v1", "StatefulSet")
    [sidecar] = smp["spec"]["template"]["spec"]["initContainers"]
    assert sidecar["name"] == kube.SIDECAR and sidecar["image"] == IMAGE
    assert sidecar["restartPolicy"] == "Always"
    assert sidecar["securityContext"] == {
        "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": True,
        "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]}}
    assert sidecar["envFrom"] == [{"secretRef": {"name": "os-openshell-artzain"}}]
    env = {e["name"]: e["value"] for e in sidecar["env"]}
    assert env["OPENSHELL_SIDECAR_GRPC"] == f"unix://{kube.SOCKET}"
    assert env["OPENSHELL_GATEWAY_ENDPOINT"] == "https://127.0.0.1:8080"
    assert env["OPENSHELL_JWT_PUBLIC_KEY"] == kube.JWT_KEY
    assert env["OPENSHELL_JWT_GATEWAY_ID"] == "os-openshell"
    assert env["OPENSHELL_SIDECAR_LIST_CLI"] == kube.CLI
    # Nothing secret in the patch: the credential and the token are the Secret's.
    assert not {"COGNEXUS_API_KEY", "OPENSHELL_SIDECAR_TOKEN"} & set(env)
    mounts = {m["name"]: m["mountPath"] for m in sidecar["volumeMounts"]}
    assert mounts[kube.TLS_VOLUME] == kube.mtls_folder(8080)
    assert mounts[kube.JWT_VOLUME] == "/etc/artzain/jwt"
    assert mounts[kube.CONFIG_VOLUME] == "/etc/artzain/gateway"


def test_the_sidecar_keeps_its_files_in_a_folder_it_makes():
    """kubelet makes an emptyDir's own folder root's, and the sidecar's
    private files refuse a folder of another user's: its state, journal and
    base policy copy go in a folder of the state volume the sidecar makes."""
    [sidecar] = kube.patch(_render())["spec"]["template"]["spec"]["initContainers"]
    env = {e["name"]: e["value"] for e in sidecar["env"]}
    folders = {env[name].rsplit("/", 1)[0] for name in (
        "OPENSHELL_SIDECAR_STATE", "OPENSHELL_SIDECAR_JOURNAL", "OPENSHELL_SIDECAR_BASE_POLICY")}
    mounts = {m["name"]: m["mountPath"] for m in sidecar["volumeMounts"]}
    [folder] = folders
    assert folder.startswith(mounts[kube.STATE_VOLUME] + "/")


def test_without_the_charts_key_the_sidecar_checks_nothing():
    smp = kube.patch(_render(jwt_secret=""))
    [sidecar] = smp["spec"]["template"]["spec"]["initContainers"]
    assert "OPENSHELL_JWT_PUBLIC_KEY" not in {e["name"] for e in sidecar["env"]}
    assert [v["name"] for v in smp["spec"]["template"]["spec"]["volumes"]] == [kube.TLS_VOLUME]


@pytest.mark.parametrize("change, says", [
    ({"image": "ghcr.io/cognexuslabs/artzain-openshell-sidecar:0.6.50"}, "by its digest"),
    ({"uid": 0}, "as root"),
    ({"kind": "DaemonSet"}, "DaemonSet"),
    ({"release": "Bad_Name"}, "not a Kubernetes name"),
    ({"port": 0}, "not a port"),
], ids=["tag", "root", "kind", "name", "port"])
def test_a_render_the_patch_cannot_take_is_refused(change, says):
    with pytest.raises(connect.ConnectError, match=says):
        kube.patch(_render(**change))


def test_the_kustomization_targets_the_releases_gateway_alone():
    text = kube.kustomization(_render())
    assert "kind: StatefulSet" in text
    assert 'labelSelector: "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=os"' in text


def test_the_post_renderer_runs_kustomize_on_its_own_files(tmp_path):
    seen = {}

    def run(argv):
        folder = Path(argv[-1])
        seen["argv"] = argv[:2]
        seen["files"] = sorted(p.name for p in folder.iterdir())
        seen["patch"] = json.loads((folder / "sidecar.json").read_text(encoding="utf-8"))
        return (folder / "all.yaml").read_text(encoding="utf-8") + f"  - name: {kube.SIDECAR}\n"

    out = kube.post_render("kind: StatefulSet\n", _render(), run)
    assert seen["argv"] == ["kubectl", "kustomize"]
    assert seen["files"] == ["all.yaml", "kustomization.yaml", "sidecar.json"]
    assert seen["patch"] == kube.patch(_render())
    assert out.startswith("kind: StatefulSet\n")


def test_output_without_the_sidecar_is_refused():
    with pytest.raises(connect.ConnectError, match="found no StatefulSet of release os"):
        kube.post_render("kind: StatefulSet\n", _render(), lambda argv: "kind: StatefulSet\n")


def test_an_operators_helm_upgrade_gets_the_same_post_renderer():
    args = kube.helm_args("/opt/artzain/bin/python", _render())
    assert args[:2] == ["--post-renderer", "/opt/artzain/bin/python"]
    given = args[2:][1::2]
    assert args[2:][0::2] == ["--post-renderer-args"] * len(given)
    assert given[:4] == ["-m", "artzain.cli", "openshell", "kube-render"]
    assert given[given.index("--image") + 1] == IMAGE


def test_the_settings_are_a_secret_of_the_release():
    made = kube.secret_manifest("os-openshell", "openshell", {"COGNEXUS_API_KEY": "cnxg_x"})
    assert made["metadata"]["name"] == "os-openshell-artzain"
    assert made["metadata"]["namespace"] == "openshell"
    assert made["stringData"] == {"COGNEXUS_API_KEY": "cnxg_x"}
