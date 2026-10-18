"""Connection authorization and tenant isolation, on SQLite and PostgreSQL."""

import asyncio
import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from test_auth import ORIGIN, SETTINGS, TOKENS, Provider, sign_in

from agentshield.api import create_app
from agentshield.connections import ConnectionSettings
from agentshield.github import GitHubError
from agentshield.models import Action, Task

HEADERS = {"Origin": ORIGIN}
CONFIG = ConnectionSettings("client", "secret", "1234", "test-app")


class GitHub:
    def __init__(self):
        self.identity = 456
        self.app_id = 1234
        self.suspended = None
        self.revoked = False
        self.removed = False
        self.name = "member/project"
        self.exchanges = []
        self.requests = []
        self.on_exchange = None

    def __call__(self, request):
        path = request.url.path
        if path == "/login/oauth/access_token":
            body = json.loads(request.content)
            self.exchanges.append(body)
            if self.on_exchange:
                self.on_exchange()
            return httpx.Response(
                200,
                json={
                    "access_token": "github-user-secret",
                    "refresh_token": "github-refresh-secret",
                    "expires_in": 28800,
                },
            )
        assert request.method == "GET", "Connection flow must never mutate a repository"
        assert request.headers["authorization"] == "Bearer github-user-secret"
        self.requests.append(str(request.url))
        if self.revoked:
            return httpx.Response(403)
        if path == "/user":
            data = {"id": self.identity}
        elif path == "/user/installations":
            data = {
                "total_count": 1,
                "installations": [
                    {
                        "id": 77,
                        "app_id": self.app_id,
                        "suspended_at": self.suspended,
                        "account": {"login": "member", "type": "User"},
                    }
                ],
            }
        elif path == "/user/installations/77/repositories":
            data = {"total_count": 1, "repositories": [{"id": 20, "full_name": self.name, "private": True}]}
        elif path in ("/repositories/20", "/repos/member/project"):
            data = {"id": 20, "full_name": self.name, "default_branch": "main"}
        elif path == "/repos/member/project/issues/1":
            data = {
                "number": 1,
                "title": "A real issue",
                "body": "<script>untrusted</script>",
                "updated_at": "2026-01-01T00:00:00Z",
                "state": "open",
            }
        elif path == "/repos/member/project/git/ref/heads/main":
            data = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "a" * 40}}
        else:
            raise AssertionError(path)
        if self.removed and path == "/user/installations/77/repositories":
            data = {"total_count": 0, "repositories": []}
        return httpx.Response(200, json=data)


@pytest.fixture
def setup(database_location):
    provider, github = Provider(), GitHub()
    app = create_app(
        database_location,
        TOKENS.copy(),
        auth_settings=SETTINGS,
        auth_transport=httpx.MockTransport(provider),
        connection_settings=CONFIG,
        connection_transport=httpx.MockTransport(github),
    )
    with TestClient(app, base_url=ORIGIN) as client:
        uid, _ = sign_in(client, provider)
        yield app, client, provider, github, uid


def start(client):
    response = client.post("/v1/github/connect", headers=HEADERS)
    assert response.status_code == 200, response.text
    return parse_qs(urlsplit(response.json()["url"]).query)


def callback(client, query):
    return client.get(
        "/github/callback", params={"state": query["state"][0], "code": "code"}, follow_redirects=False
    )


def authorize(client):
    query = start(client)
    assert callback(client, query).headers["location"] == "/?github=connected"
    return query


def select(client, **changes):
    return client.post(
        "/v1/github/repositories",
        headers=HEADERS,
        json={"installation_id": 77, "repository_id": 20, **changes},
    )


def test_pkce_binding_encryption_replay_and_selection(setup):
    app, client, provider, github, uid = setup
    query = authorize(client)
    body = github.exchanges[0]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == [ORIGIN + "/github/callback"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(body["code_verifier"].encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert query["code_challenge"] == [challenge]
    assert callback(client, query).headers["location"] == "/?github=failed"
    assert len(github.exchanges) == 1
    with app.state.auth.store.transaction() as db:
        row = db.execute("SELECT tokens FROM github_accounts").fetchone()
        assert "github-user-secret" not in row["tokens"]
        assert "github-refresh-secret" not in row["tokens"]
    result = select(client)
    assert result.status_code == 200, result.text
    assert "secret" not in result.text
    repo = result.json()["repositories"][0]
    assert select(client).json()["repositories"] == [repo]
    principal, _ = app.state.auth.profile(provider.users[uid])
    assert "repo:member/project" in principal.resources
    assert not app.state.connections.adapter(principal.tenant, "repo:member/project").settings.enable_writes
    preview = client.get(f"/v1/github/repositories/{repo['id']}/issues/1")
    assert preview.status_code == 200 and preview.json()["issue"]["title"] == "A real issue"


def test_wrong_session_account_expiry_and_forged_install_callback(setup):
    app, client, provider, github, uid = setup
    query = start(client)
    with TestClient(app, base_url=ORIGIN) as other:
        sign_in(other, provider)
        assert callback(other, query).headers["location"] == "/?github=failed"
    assert not github.exchanges
    github.identity = 999
    assert callback(client, query).headers["location"] == "/?github=failed"
    assert not client.get("/v1/github/connections").json()["authorized"]
    query = start(client)
    with app.state.auth.store.transaction() as db:
        db.execute("UPDATE github_flows SET expires_at=?", (time.time() - 1,))
    assert callback(client, query).headers["location"] == "/?github=failed"
    client.get("/github/setup?installation_id=77&setup_action=install")
    assert client.get("/v1/github/connections").json()["repositories"] == []
    assert not client.get("/v1/github/connections").json()["authorized"]


def test_csrf_cookie_required_and_provider_proves_selection(setup):
    app, client, provider, github, uid = setup
    assert client.post("/v1/github/connect").status_code == 403
    assert (
        client.delete("/v1/github/connections", headers={"Origin": "https://evil.example"}).status_code == 403
    )
    with TestClient(app, base_url=ORIGIN) as other:
        assert (
            other.get("/v1/github/connections", headers={"Authorization": "Bearer test-operator"}).status_code
            == 401
        )
    authorize(client)
    assert select(client, installation_id=88).status_code == 403
    assert select(client, repository_id=999).status_code == 403
    github.app_id = 999
    assert select(client).status_code == 403
    github.app_id = 1234
    github.suspended = "today"
    assert select(client).status_code == 403
    assert client.get("/v1/github/connections").json()["repositories"] == []
    assert client.get("/v1/github/installations?page=101").status_code == 422


def test_tenant_isolation_disconnect_and_connection_generation(setup):
    app, client, provider, github, uid = setup
    authorize(client)
    repo = select(client).json()["repositories"][0]
    principal, _ = app.state.auth.profile(provider.users[uid])
    adapter = app.state.connections.adapter(principal.tenant, "repo:member/project")
    with TestClient(app, base_url=ORIGIN) as other:
        sign_in(other, provider)
        authorize(other)
        other_repo = select(other).json()["repositories"][0]
        assert other_repo["id"] != repo["id"]
        assert other.get(f"/v1/github/repositories/{repo['id']}/issues/1").status_code == 404
        assert other.delete(f"/v1/github/repositories/{repo['id']}", headers=HEADERS).status_code == 404
        assert client.delete(f"/v1/github/repositories/{repo['id']}", headers=HEADERS).status_code == 200
        with pytest.raises(GitHubError, match="GITHUB_CONNECTION_REMOVED"):
            adapter.broker.token({})
        new = select(client).json()["repositories"][0]
        assert new["id"] != repo["id"]
        with pytest.raises(GitHubError, match="GITHUB_CONNECTION_REMOVED"):
            app.state.connections.adapter(
                principal.tenant, "repo:member/project", {"connection_id": repo["id"]}
            )
        assert client.delete("/v1/github/connections", headers=HEADERS).status_code == 200
        assert other.get(f"/v1/github/repositories/{other_repo['id']}/issues/1").status_code == 200
    principal, _ = app.state.auth.profile(provider.users[uid])
    assert "repo:member/project" not in principal.resources


def test_refresh_serialization_and_disconnect_during_exchange(setup):
    app, client, provider, github, uid = setup
    authorize(client)
    principal, _ = app.state.auth.profile(provider.users[uid])
    manager = app.state.connections
    with manager.store.transaction() as db:
        row = db.execute("SELECT tokens FROM github_accounts WHERE tenant=?", (principal.tenant,)).fetchone()
        tokens = manager.auth.unseal(row["tokens"])
        tokens["expires"] = 0
        db.execute(
            "UPDATE github_accounts SET tokens=? WHERE tenant=?",
            (manager.auth.seal(tokens), principal.tenant),
        )
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert (
            list(pool.map(lambda _: manager.token(principal.tenant), range(3))) == ["github-user-secret"] * 3
        )
    assert len(github.exchanges) == 2
    query = start(client)
    github.on_exchange = lambda: manager.disconnect(principal)
    assert callback(client, query).headers["location"] == "/?github=failed"
    assert not manager.status(principal)["authorized"]


def test_revocation_identity_change_and_task_repository_pin(setup):
    app, client, provider, github, uid = setup
    authorize(client)
    repo = select(client).json()["repositories"][0]
    principal, _ = app.state.auth.profile(provider.users[uid])
    task = Task(
        provider="github",
        tenant=principal.tenant,
        requester=principal.requester,
        purpose="Read issue",
        resources=["repo:member/project"],
        destinations=["github:member/project"],
        issue_ids=[1],
    )
    app.state.engine.create_task(task, principal)
    with app.state.auth.store.transaction() as db:
        row = db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()
        state = json.loads(row["state"])
        assert state["connection_id"] == repo["id"]
    actor = principal.model_copy(update={"role": "requester"})
    action = app.state.engine.prepare(
        Action(
            task_id=task.task_id,
            operation="read_issue",
            canonical_arguments={"issue_number": 1},
            resource_identifiers=["repo:member/project", "issue:1"],
            destination="github:member/project",
            expected_resource_version="unprepared",
            adapter_version="github-rest-1",
        ),
        actor,
    )
    decision = asyncio.run(app.state.engine.decide(action, actor))
    assert decision.disposition == "allow"
    result = app.state.engine.execute(decision.decision_id, action, actor)
    assert result["state"] == "succeeded", result
    github.removed = True
    assert client.get(f"/v1/github/repositories/{repo['id']}/issues/1").status_code == 503
    github.removed = False
    github.revoked = True
    assert client.get(f"/v1/github/repositories/{repo['id']}/issues/1").status_code == 503
    github.revoked = False
    github.name = "someone/transferred"
    with pytest.raises(GitHubError, match="GITHUB_REPOSITORY_ACCESS_REMOVED"):
        app.state.engine.github_for(task, state).session()
