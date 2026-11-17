import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/charts/saas-auth"


@pytest.fixture
def auth_chart(tmp_path):
    if not shutil.which("helm"):
        pytest.skip("Helm is required for chart validation")
    image = "registry.example.test/saas-auth@sha256:" + "a" * 64
    values = {"workloads": {"auth": {"image": image}, "worker": {"image": image}}}
    path = tmp_path / "values.json"
    path.write_text(json.dumps(values))
    output = subprocess.check_output(
        ["helm", "template", "auth", str(CHART), "-n", "auth-test", "-f", str(path)],
        text=True,
    )
    resources = {(r["kind"], r["metadata"]["name"]): r for r in yaml.safe_load_all(output)}
    return path, resources


def test_auth_chart_owns_api_worker_migration_and_private_boundary(auth_chart):
    path, resources = auth_chart
    assert set(resources) == {
        ("Deployment", "saas-auth"),
        ("Deployment", "saas-worker"),
        ("Service", "saas-auth"),
        ("ConfigMap", "saas-auth-tls"),
        ("Job", "saas-migrate-auth"),
        ("NetworkPolicy", "saas-auth-private"),
        ("Pod", "saas-auth-smoke"),
    }
    job = resources["Job", "saas-migrate-auth"]
    assert job["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade"
    assert job["spec"]["template"]["spec"]["containers"][0]["command"] == [
        "alembic",
        "upgrade",
        "head",
    ]
    service = resources["Service", "saas-auth"]["spec"]
    assert service["type"] == "ClusterIP" and service["ports"][0]["port"] == 443
    api = resources["Deployment", "saas-auth"]["spec"]["template"]["spec"]
    assert api["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    worker = resources["Deployment", "saas-worker"]["spec"]["template"]["spec"]
    assert worker["containers"][0]["command"] == ["saas-auth", "private-tasks-worker"]
    assert worker["containers"][0]["image"] == api["containers"][0]["image"]
    for pod in [api, worker, job["spec"]["template"]["spec"]]:
        assert pod["automountServiceAccountToken"] is False
        for container in pod["containers"]:
            assert container["securityContext"]["readOnlyRootFilesystem"] is True
            assert container["securityContext"]["allowPrivilegeEscalation"] is False
    policy = resources["NetworkPolicy", "saas-auth-private"]["spec"]
    assert policy["ingress"][0]["ports"] == [{"protocol": "TCP", "port": 8443}]
    subprocess.run(["helm", "lint", str(CHART), "-f", str(path)], check=True, capture_output=True)


def test_auth_chart_rejects_mutable_image(auth_chart):
    path, _ = auth_chart
    values = json.loads(path.read_text())
    values["workloads"]["auth"]["image"] = "registry.example.test/saas-auth:latest"
    path.write_text(json.dumps(values))
    result = subprocess.run(
        ["helm", "template", "auth", str(CHART), "-f", str(path)],
        capture_output=True,
    )
    assert result.returncode != 0 and b"Images must use" in result.stderr
