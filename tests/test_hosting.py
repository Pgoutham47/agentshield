from dataclasses import replace
from types import SimpleNamespace

import pytest

from agentshield.github import GitHubSettings
from agentshield.hosting import ROLES, hosted_tokens


@pytest.fixture
def environment(monkeypatch, tmp_path):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("AGENTSHIELD_ENV", "hosted")
    for role in ROLES:
        monkeypatch.setenv(f"AGENTSHIELD_{role.upper()}_TOKEN", role + "x" * 40)
    return tmp_path


def test_hosted_requires_distinct_explicit_tokens(environment, monkeypatch):
    assert len(hosted_tokens(environment, None)) == 4
    monkeypatch.setenv("AGENTSHIELD_WORKER_TOKEN", "")
    with pytest.raises(ValueError, match="32 ASCII"):
        hosted_tokens(environment, None)
    monkeypatch.setenv("AGENTSHIELD_WORKER_TOKEN", "developer" + "x" * 40)
    with pytest.raises(ValueError, match="distinct"):
        hosted_tokens(environment, None)


def test_hosted_refuses_cli_and_missing_app_key(environment):
    settings = GitHubSettings("owner/repo", auth_mode="gh", dev_account="owner")
    with pytest.raises(ValueError, match="CLI auth is local only"):
        hosted_tokens(environment, SimpleNamespace(settings=settings))
    settings = replace(
        settings,
        auth_mode="app",
        app_id="1",
        installation_id="2",
        private_key_path=str(environment / "app.pem"),
    )
    with pytest.raises(ValueError, match="secret file is missing"):
        hosted_tokens(environment, SimpleNamespace(settings=settings))


def test_render_refuses_ephemeral_data(environment, monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    with pytest.raises(ValueError, match="persistent"):
        hosted_tokens(environment, None)


def test_hosted_api_never_creates_fallback_tokens(environment, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AGENTSHIELD_DATA_DIR", str(environment))
    from agentshield.api import create_app

    with TestClient(create_app()) as client:
        assert client.get("/v1/overview").status_code == 401
        response = client.get("/v1/overview", headers={"Authorization": "Bearer operator" + "x" * 40})
        assert response.status_code == 200
        assert "max-age" in response.headers["strict-transport-security"]
        assert not (environment / "local-tokens.json").exists()
