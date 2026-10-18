import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api import create_app
from agentshield.auth import AuthSettings, SupabaseAuth
from agentshield.demo import DEVELOPER

ORIGIN = "https://console.example"
SETTINGS = AuthSettings("https://project.supabase.co", "public-key", ORIGIN, "s" * 40, "123")
TOKENS = {role: "test-" + role for role in ("developer", "worker", "reviewer", "operator")}


class Provider:
    def __init__(self):
        self.users = {}
        self.codes = set()
        self.refreshes = 0
        self.fail = None
        self.on_user = None

    def user(self, owner=False):
        uid = str(uuid4())
        self.users[uid] = {
            "id": uid,
            "email": "member@example.com",
            "identities": [{"provider": "github", "identity_data": {"sub": "123" if owner else "456"}}],
        }
        return uid

    def __call__(self, request):
        if self.fail:
            return httpx.Response(self.fail)
        if request.url.path.endswith("/token"):
            body = json.loads(request.content)
            if request.url.params["grant_type"] == "pkce":
                uid = body["auth_code"]
                if uid in self.codes:
                    return httpx.Response(400)
                self.codes.add(uid)
                assert len(body["code_verifier"]) >= 43
            else:
                self.refreshes += 1
                uid = body["refresh_token"].removeprefix("refresh-")
            return httpx.Response(
                200,
                json={"access_token": "access-" + uid, "refresh_token": "refresh-" + uid, "expires_in": 3600},
            )
        if request.url.path.endswith("/user"):
            if self.on_user:
                self.on_user()
            uid = request.headers["authorization"].removeprefix("Bearer access-")
            return httpx.Response(200, json=self.users[uid])
        assert request.url.path.endswith("/logout")
        return httpx.Response(204)


@pytest.fixture
def setup(database_location):
    provider = Provider()
    app = create_app(
        database_location, TOKENS.copy(), auth_settings=SETTINGS, auth_transport=httpx.MockTransport(provider)
    )
    with TestClient(app, base_url=ORIGIN) as client:
        yield app, client, provider


def sign_in(client, provider, owner=False):
    uid = provider.user(owner)
    start = client.post("/auth/login", headers={"Origin": ORIGIN}, follow_redirects=False)
    assert start.status_code == 200
    cookie = start.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    authorize = parse_qs(urlsplit(start.json()["url"]).query)
    assert authorize["code_challenge_method"] == ["s256"]
    flow = parse_qs(urlsplit(authorize["redirect_to"][0]).query)
    callback = "/auth/callback?code=" + uid + "&state=" + flow["state"][0]
    result = client.get(callback, follow_redirects=False)
    assert result.status_code == 303 and result.headers["location"] == "/"
    assert SupabaseAuth.cookie in client.cookies
    return uid, callback


def test_login_encrypted_persistent_session_and_logout(setup):
    app, client, provider = setup
    uid, callback = sign_in(client, provider, owner=True)
    profile = client.get("/auth/me").json()
    assert profile["user"]["owner"] and profile["user"]["tenant"] == "acme"
    assert "access" not in profile and "refresh" not in profile
    auth = app.state.auth
    with auth.store.transaction() as db:
        row = db.execute("SELECT * FROM auth_sessions").fetchone()
        assert row["user_id"] == uid
        assert "access-" not in row["tokens"] and "refresh-" not in row["tokens"]
        assert row["id"] != client.cookies.get(auth.cookie)
    # A restart with the same secret/database keeps the session usable.
    restarted = create_app(
        auth.store.path, TOKENS.copy(), auth_settings=SETTINGS, auth_transport=httpx.MockTransport(provider)
    )
    with TestClient(restarted, base_url=ORIGIN) as other:
        other.cookies.update(client.cookies)
        assert other.get("/v1/overview").status_code == 200
    # Callback replay cannot exchange a code again, or overwrite the authenticated session.
    assert client.get(callback, follow_redirects=False).headers["location"].startswith("/?auth_error=")
    old = client.cookies.get(auth.cookie)
    assert client.post("/auth/logout", headers={"Origin": ORIGIN}).status_code == 200
    client.cookies.set(auth.cookie, old)
    assert client.get("/v1/overview").status_code == 401
    assert client.get("/auth/me").json()["user"] is None


def test_csrf_and_oauth_binding(setup):
    app, client, provider = setup
    for origin in ({}, {"Origin": "https://evil.example"}, {"Origin": "null"}):
        assert client.post("/auth/login", headers=origin).status_code == 403
    uid = provider.user()
    start = client.post("/auth/login", headers={"Origin": ORIGIN}, follow_redirects=False)
    assert start.status_code == 200
    response = client.get("/auth/callback?code=" + uid + "&state=wrong", follow_redirects=False)
    assert response.headers["location"].startswith("/?auth_error=")
    assert not provider.codes
    sign_in(client, provider)
    for path in ("/auth/logout", "/v1/demo"):
        assert (
            client.post(path, headers={"Origin": "https://evil.example"}, json={"scenario": "A"}).status_code
            == 403
        )
    assert client.get("/v1/overview", headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert client.get("/v1/overview", headers={"Authorization": "Bearer test-operator"}).status_code == 200


def test_tenant_isolation_and_immutable_owner_identity(setup):
    app, client, provider = setup
    uid, _ = sign_in(client, provider)
    provider.users[uid]["user_metadata"] = {
        "role": "admin",
        "tenant": "acme",
        "sub": "123",
        "provider_id": "123",
    }
    profile = client.get("/auth/me").json()["user"]
    assert profile["tenant"] != "acme" and not profile["owner"]
    # Existing owner fixture remains invisible to this new user.
    owner = client.post(
        "/v1/demo",
        headers={"Authorization": "Bearer test-operator"},
        json={"scenario": "C", "leave_pending": True},
    ).json()
    result = client.post(
        "/v1/demo", headers={"Origin": ORIGIN}, json={"scenario": "C", "leave_pending": True}
    )
    assert result.status_code == 200, result.text
    overview = client.get("/v1/overview").json()
    assert len(overview["tasks"]) == len(overview["approvals"]) == 1
    assert overview["tasks"][0]["contract"]["tenant"] == profile["tenant"]
    assert overview["tasks"][0]["contract"]["task_id"] != owner["task_id"]
    assert all(e["tenant"] == profile["tenant"] for e in client.get("/v1/events").json()["events"])
    assert client.post(f"/v1/tasks/{owner['task_id']}/cancel", headers={"Origin": ORIGIN}).status_code in {
        403,
        404,
    }
    assert len(app.state.engine.overview(DEVELOPER)["tasks"]) == 1
    github = SimpleNamespace(
        settings=SimpleNamespace(repository="owner/private"),
        status=lambda **kw: {"configured": True, "repository": "owner/private"},
    )
    app.state.auth.github = github
    principal, _ = app.state.auth.profile(provider.users[uid])
    assert "repo:owner/private" not in principal.resources
    app.state.engine.github = github
    assert app.state.engine.overview(principal)["github_integration"] == {"configured": False}
    provider.users[uid]["identities"] = [{"provider": "email", "identity_data": {"sub": "123"}}]
    assert client.get("/v1/overview").status_code == 401


def test_refresh_serialized_and_failure_closed(setup):
    app, client, provider = setup
    sign_in(client, provider)
    auth = app.state.auth
    key = hashlib.sha256(client.cookies.get(auth.cookie).encode()).hexdigest()
    with auth.store.transaction() as db:
        row = db.execute("SELECT * FROM auth_sessions WHERE id=?", (key,)).fetchone()
        tokens = auth.unseal(row["tokens"])
        tokens["expires"] = time.time() - 1
        db.execute("UPDATE auth_sessions SET tokens=? WHERE id=?", (auth.seal(tokens), key))
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: client.get("/auth/me").status_code, range(3)))
    assert results == [200, 200, 200] and provider.refreshes == 1
    provider.fail = 503
    assert client.get("/v1/overview").status_code == 503
    provider.fail = None
    assert client.get("/v1/overview").status_code == 200
    provider.fail = 401
    assert client.get("/v1/overview").status_code == 401
    provider.fail = None
    assert client.get("/v1/overview").status_code == 401


def test_expired_tampered_and_concurrent_logout(setup):
    app, client, provider = setup
    sign_in(client, provider)
    auth = app.state.auth
    with auth.store.transaction() as db:
        db.execute("UPDATE auth_sessions SET expires_at=?", (time.time() - 1,))
    assert client.get("/v1/overview").status_code == 401
    sign_in(client, provider)
    with auth.store.transaction() as db:
        db.execute("UPDATE auth_sessions SET tokens=?", ("tampered",))
    assert client.get("/v1/overview").status_code == 401
    sign_in(client, provider)

    def revoke():
        with auth.store.transaction() as db:
            db.execute("DELETE FROM auth_sessions")

    provider.on_user = revoke
    assert client.get("/v1/overview").status_code == 401
    with auth.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM auth_sessions").fetchone()[0] == 0


def test_configuration_fails_closed():
    for url in (
        "http://supabase.co",
        "https://good.example/path",
        "https://a@supabase.co",
        "https://supabase.co?x=y",
    ):
        with pytest.raises(ValueError):
            AuthSettings(url, "key", ORIGIN, "s" * 40)
    with pytest.raises(ValueError):
        AuthSettings(SETTINGS.url, "key", ORIGIN, "short")
    with pytest.raises(ValueError):
        AuthSettings(SETTINGS.url, "key", ORIGIN, "s" * 40, "mutable-login")


def test_live_repository_access_is_owner_only(tmp_path):
    from agentshield.github import GitHubAdapter, GitHubSettings

    provider = Provider()
    github = GitHubAdapter(GitHubSettings("owner/private"))
    app = create_app(
        tmp_path / "auth.sqlite",
        TOKENS.copy(),
        github=github,
        auth_settings=SETTINGS,
        auth_transport=httpx.MockTransport(provider),
    )
    with TestClient(app, base_url=ORIGIN) as client:
        sign_in(client, provider)
        result = client.get("/v1/integrations/github?verify=true")
        assert result.status_code == 200 and not result.json()["configured"]
        assert "owner/private" not in client.get("/v1/overview").text
        draft = client.post(
            "/v1/tasks/draft",
            headers={"Origin": ORIGIN},
            json={
                "provider": "github",
                "request": "Read issue number 1",
                "issue_number": 1,
                "entitlements": ["repo:owner/private"],
            },
        )
        assert draft.status_code == 403
        uid, _ = sign_in(client, provider, owner=True)
        assert client.get("/v1/integrations/github").json()["repository"] == "owner/private"
        principal, _ = app.state.auth.profile(provider.users[uid])
        assert "repo:owner/private" in principal.resources


def test_expired_flow_cookie_and_identity_change(setup):
    app, client, provider = setup
    auth = app.state.auth
    expired = auth.cipher.encrypt_at_time(
        json.dumps({"state": "state", "verifier": "v" * 48}).encode(), int(time.time()) - 601
    ).decode()
    client.cookies.set(auth.flow_cookie, expired)
    result = client.get("/auth/callback?state=state&code=unused", follow_redirects=False)
    assert result.headers["location"].startswith("/?auth_error=") and not provider.codes
    client.cookies.clear()
    uid, _ = sign_in(client, provider)
    provider.users[uid]["id"] = str(uuid4())
    assert client.get("/v1/overview").status_code == 401
