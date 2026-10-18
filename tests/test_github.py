import asyncio
import base64
import json
from dataclasses import replace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agentshield.analyzer import Analyzer
from agentshield.demo import DEVELOPER, REVIEWER, WORKER
from agentshield.engine import Engine, ShieldError
from agentshield.github import GitHubAdapter, GitHubError, GitHubSettings, TokenBroker, bounded_request
from agentshield.models import Action, Resolution, Task

REPO = "demo/sandbox"
DEV, REVIEW, WORK = [
    p.model_copy(update={"resources": ["repo:" + REPO]}) for p in (DEVELOPER, REVIEWER, WORKER)
]


class FakeGitHub:
    def __init__(self):
        self.calls = []
        self.branches = {"main": "base"}
        self.issue = {
            "number": 1,
            "title": "Fix layout",
            "body": "Fix layout",
            "state": "open",
            "updated_at": "v1",
        }
        self.entries = [{"path": "file.css", "type": "blob", "mode": "100644", "sha": "blob"}]
        self.failure = None
        self.truncated = False

    def __call__(self, request):
        assert request.url.host == "api.github.com"
        assert request.headers["authorization"] == "Bearer TEST-ONLY-TOKEN"
        method, path = request.method, request.url.path.removeprefix("/repos/" + REPO)
        body = json.loads(request.content) if request.content else None
        self.calls.append((method, path, body))
        if self.failure and self.failure[0] == (method, path):
            if self.failure[1] == "timeout":
                raise httpx.ReadTimeout("TEST-ONLY-TOKEN", request=request)
            return httpx.Response(self.failure[1], json={"message": "TEST-ONLY-TOKEN"})
        if method == "GET":
            if path == "":
                data = {"id": 123, "full_name": REPO, "default_branch": "main"}
            elif path == "/issues/1":
                data = self.issue
            elif path.startswith("/git/ref/heads/"):
                branch = path.removeprefix("/git/ref/heads/")
                data = {
                    "ref": "refs/heads/" + branch,
                    "object": {"type": "commit", "sha": self.branches[branch]},
                }
            elif path.startswith("/git/commits/"):
                data = {"tree": {"sha": "tree"}}
            elif path.startswith("/git/trees/"):
                data = {"tree": self.entries, "truncated": self.truncated}
            elif path == "/git/blobs/blob":
                data = {"encoding": "base64", "size": 3, "content": base64.b64encode(b"CSS").decode()}
            else:
                raise AssertionError(path)
        elif path == "/git/refs":
            self.branches[body["ref"].removeprefix("refs/heads/")] = body["sha"]
            data = {"object": {"sha": body["sha"]}}
        elif path == "/git/trees":
            assert body["base_tree"] == "tree"
            data = {"sha": "new-tree"}
        elif path == "/git/commits":
            assert body["parents"] == ["base"]
            data = {"sha": "new-commit"}
        elif path.startswith("/git/refs/heads/"):
            assert body["force"] is False
            self.branches[path.removeprefix("/git/refs/heads/")] = body["sha"]
            data = {"object": {"sha": body["sha"]}}
        elif path == "/pulls":
            assert body["draft"] is True and body["base"] == "main"
            data = {"number": 2, "draft": True, "html_url": "https://github.com/demo/sandbox/pull/2"}
        elif path == "/issues/1/comments":
            data = {"id": 3, "html_url": "https://github.com/demo/sandbox/issues/1#issuecomment-3"}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json=data, headers={"x-github-request-id": "test-request"})


class FakeBroker:
    def token(self, permissions):
        return "TEST-ONLY-TOKEN"


@pytest.fixture
def live(tmp_path):
    fake = FakeGitHub()
    adapter = GitHubAdapter(GitHubSettings(REPO, enable_writes=True), httpx.MockTransport(fake), FakeBroker())
    engine = Engine(tmp_path / "live.sqlite", Analyzer("off"), github=adapter)
    task = engine.create_task(
        Task(
            provider="github",
            tenant="acme",
            requester=DEV.subject,
            purpose="Fix layout bug",
            resources=DEV.resources,
            destinations=["github:" + REPO],
            issue_ids=[1],
        ),
        DEV,
    )
    return engine, task, fake


def action(live, op="read_issue", args=None):
    engine, task, _ = live
    args = args or {"issue_number": 1}
    resources = DEV.resources + ([f"issue:{args['issue_number']}"] if "issue_number" in args else [])
    return engine.prepare(
        Action(
            task_id=task.task_id,
            operation=op,
            canonical_arguments=args,
            resource_identifiers=resources,
            destination="github:" + REPO,
            expected_resource_version="unprepared",
            adapter_version="github-rest-1",
        ),
        WORK,
    )


def authorize(live, a):
    engine, _, _ = live
    d = asyncio.run(engine.decide(a, WORK))
    if a.operation not in {"read_issue", "read_file"}:
        assert d.disposition == "require_approval" and "LIVE_WRITE_REVIEW" in d.reason_codes
        d = engine.resolve(
            d.approval_id,
            Resolution(
                approve=True,
                action_digest=d.action_digest,
                justification="Exact action reviewed by test approver",
            ),
            REVIEW,
        )["decision"]
        return d["decision_id"]
    return d.decision_id


def execute(live, op, args):
    a = action(live, op, args)
    result = live[0].execute(authorize(live, a), a, WORK)
    assert result["state"] == "succeeded", result
    return result


def test_real_adapter_flow_and_one_use(live):
    e, t, fake = live
    execute(live, "read_issue", {"issue_number": 1})
    assert execute(live, "read_file", {"path": "file.css"})["result"]["content"] == "CSS"
    execute(live, "create_branch", {"branch": "agent/fix"})
    execute(live, "push_commit", {"branch": "agent/fix", "message": "Fix", "files": {"file.css": "new CSS"}})
    a = action(
        live, "open_draft_pr", {"branch": "agent/fix", "title": "Fix", "body": "Fixes #1", "draft": True}
    )
    grant = authorize(live, a)
    assert e.execute(grant, a, WORK)["result"]["pull_request"]["draft"]
    count = len(fake.calls)
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        e.execute(grant, a, WORK)
    assert len(fake.calls) == count
    execute(live, "comment_issue", {"issue_number": 1, "body": "Fix available in draft PR."})
    assert fake.branches["main"] == "base"
    assert e.store.verify()
    assert "TEST-ONLY-TOKEN" not in json.dumps(e.overview(REVIEW))


def test_remote_staleness_and_mutated_payload(live):
    e, _, fake = live
    a = action(live, "comment_issue", {"issue_number": 1, "body": "Fix ready"})
    grant = authorize(live, a)
    changed = a.model_copy(update={"canonical_arguments": {"issue_number": 1, "body": "different"}})
    with pytest.raises(ShieldError, match="DIGEST_MISMATCH"):
        e.execute(grant, changed, WORK)
    fake.issue["updated_at"] = "changed"
    result = e.execute(grant, a, WORK)
    assert result["state"] == "failed" and result["result"]["error"] == "RESOURCE_VERSION_CHANGED"
    assert all(method == "GET" for method, *_ in fake.calls)


@pytest.mark.parametrize("failure", ["timeout", 500])
def test_uncertain_write_locks_repository_after_restart(live, failure):
    e, t, fake = live
    fake.failure = (("POST", "/git/refs"), failure)
    a = action(live, "create_branch", {"branch": "agent/fix"})
    result = e.execute(authorize(live, a), a, WORK)
    assert result["state"] == "outcome_unknown"
    assert "TEST-ONLY-TOKEN" not in json.dumps(result)
    e.recover()
    b = action(live)
    with pytest.raises(ShieldError, match="GITHUB_BUSY_OR_RECONCILIATION_REQUIRED"):
        e.execute(authorize(live, b), b, WORK)


def test_known_failure_releases_lock(live):
    e, _, fake = live
    fake.failure = (("POST", "/git/refs"), 403)
    a = action(live, "create_branch", {"branch": "agent/fix"})
    assert e.execute(authorize(live, a), a, WORK)["state"] == "failed"
    execute(live, "read_issue", {"issue_number": 1})


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_symlink_submodule_rejected(live, mode):
    e, _, fake = live
    fake.entries[0]["mode"] = mode
    a = action(live, "read_file", {"path": "file.css"})
    result = e.execute(authorize(live, a), a, WORK)
    assert result["result"]["error"] == "GITHUB_UNSUPPORTED_FILE"
    assert not any(path.startswith("/git/blobs/") for _, path, _ in fake.calls)


def test_uninspected_tree_and_concurrent_branch_update(live):
    e, _, fake = live
    execute(live, "create_branch", {"branch": "agent/fix"})
    a = action(live, "push_commit", {"branch": "agent/fix", "message": "Fix", "files": {"file.css": "new"}})
    fake.truncated = True
    assert e.execute(authorize(live, a), a, WORK)["result"]["error"] == "GITHUB_TREE_UNINSPECTED"
    fake.truncated = False
    fake.branches["agent/fix"] = "other"
    b = action(live, "push_commit", a.canonical_arguments)
    assert e.execute(authorize(live, b), b, WORK)["result"]["error"] == "RESOURCE_VERSION_CHANGED"
    assert not any(path == "/git/commits" for _, path, _ in fake.calls)


@pytest.mark.parametrize(
    "args",
    [
        {"branch": "main", "files": {"file.css": "x"}, "message": "fix"},
        {"branch": "agent/fix", "files": {".github/workflows/test.yml": "x"}, "message": "fix"},
        {"branch": "agent/fix", "files": {".env": "x"}, "message": "fix"},
        {"branch": "agent/fix", "files": {"src": "x", "src/file.css": "x"}, "message": "fix"},
    ],
)
def test_forbidden_writes_never_reach_provider(live, args):
    before = len(live[2].calls)
    with pytest.raises(ShieldError):
        action(live, "push_commit", args)
    assert len(live[2].calls) == before


def test_scope_cancel_and_write_switch(live):
    e, t, fake = live
    a = action(live, "create_branch", {"branch": "agent/fix"})
    bad = a.model_copy(update={"resource_identifiers": ["repo:other/repo"]})
    assert asyncio.run(e.decide(bad, WORK)).disposition == "deny"
    a = action(live, "create_branch", {"branch": "agent/fix"})
    grant = authorize(live, a)
    e.github.settings = replace(e.github.settings, enable_writes=False)
    assert e.execute(grant, a, WORK)["result"]["error"] == "GITHUB_WRITES_DISABLED"
    b = action(live)
    grant = authorize(live, b)
    e.cancel(t.task_id, DEV)
    before = len(fake.calls)
    with pytest.raises(ShieldError, match="TASK_INACTIVE"):
        e.execute(grant, b, WORK)
    assert len(fake.calls) == before


def test_explicit_development_opt_in(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_AUTH_MODE", "gh")
    monkeypatch.delenv("AGENTSHIELD_ALLOW_GH_DEV_AUTH", raising=False)
    with pytest.raises(ValueError, match="requires"):
        GitHubSettings.from_env()


def test_app_token_is_signed_and_repo_scoped(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "key.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    def provider(request):
        payload = jwt.decode(request.headers["authorization"][7:], key.public_key(), algorithms=["RS256"])
        assert payload["iss"] == "321" and payload["exp"] - payload["iat"] == 600
        assert json.loads(request.content) == {
            "repositories": ["sandbox"],
            "permissions": {"contents": "read"},
        }
        return httpx.Response(201, json={"token": "TEST", "repositories": [{"full_name": REPO}]})

    settings = GitHubSettings(REPO, app_id="321", installation_id="9", private_key_path=str(path))
    assert TokenBroker(settings, httpx.MockTransport(provider)).token({"contents": "read"}) == "TEST"
    mismatch = httpx.MockTransport(
        lambda r: httpx.Response(201, json={"token": "TEST", "repositories": [{"full_name": "other/repo"}]})
    )
    with pytest.raises(GitHubError, match="GITHUB_TOKEN_SCOPE_MISMATCH"):
        TokenBroker(settings, mismatch).token({"contents": "read"})


@pytest.mark.parametrize("status", [301, 302, 429])
def test_no_redirects_or_retries(status):
    requests = []

    def provider(request):
        requests.append(request)
        return httpx.Response(
            status, headers={"location": "https://evil.example"}, json={"message": "PRIVATE"}
        )

    with httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(provider)) as client:
        with pytest.raises(GitHubError) as error:
            bounded_request(client, "GET", "/repos/demo/sandbox", token="SECRET")
    assert len(requests) == 1 and "PRIVATE" not in str(error.value)


def test_cancel_between_git_object_writes_retains_lock(live):
    e, t, fake = live
    execute(live, "create_branch", {"branch": "agent/fix"})
    original = fake.__call__

    def cancel_after_tree(request):
        response = original(request)
        if request.method == "POST" and request.url.path.endswith("/git/trees"):
            e.cancel(t.task_id, DEV)
        return response

    e.github.transport = httpx.MockTransport(cancel_after_tree)
    a = action(live, "push_commit", {"branch": "agent/fix", "message": "Fix", "files": {"file.css": "new"}})
    result = e.execute(authorize(live, a), a, WORK)
    assert result["state"] == "outcome_unknown"
    assert result["result"]["error"] == "TASK_STOPPED_BEFORE_SUBMISSION"
    assert not any(method == "PATCH" or path == "/git/commits" for method, path, _ in fake.calls)
    with e.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM github_inflight").fetchone()[0] == 1


@pytest.mark.parametrize(
    "body,code", [(b"x" * (256 * 1024 + 1), "GITHUB_RESPONSE_TOO_LARGE"), (b"[]", "GITHUB_INVALID_RESPONSE")]
)
def test_bounded_malformed_responses(body, code):
    with httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body)),
    ) as client:
        with pytest.raises(GitHubError) as error:
            bounded_request(client, "POST", "/repos/demo/sandbox/git/refs", token="TEST")
        assert error.value.code == code and error.value.unknown


def test_api_preparation_and_status_roles(live, tmp_path):
    from fastapi.testclient import TestClient

    from agentshield.api import create_app

    tokens = {"developer": "dev", "worker": "worker", "reviewer": "review", "operator": "operator"}
    app = create_app(
        db_path=tmp_path / "api.sqlite", tokens=tokens, analyzer=Analyzer("off"), github=live[0].github
    )
    with TestClient(app) as client:
        assert client.get("/v1/integrations/github").status_code == 401
        assert (
            client.get("/v1/integrations/github", headers={"Authorization": "Bearer worker"}).status_code
            == 403
        )
        status = client.get("/v1/integrations/github?verify=true", headers={"Authorization": "Bearer review"})
        assert status.json()["connection"] == "verified"
        contract = live[1].model_dump(mode="json")
        response = client.post("/v1/tasks", json=contract, headers={"Authorization": "Bearer dev"})
        assert response.status_code == 200
        a = action(live).model_dump(mode="json")
        a["expected_resource_version"] = "unprepared"
        prepared = client.post("/v1/actions/prepare", json=a, headers={"Authorization": "Bearer worker"})
        assert prepared.status_code == 200 and prepared.json()["expected_resource_version"].startswith(
            "github:sha256:"
        )
        assert client.get("/health").json()["github_configured"]


def test_sdk_can_find_lost_execution_response_by_known_grant(live):
    from agentshield.api import create_app
    from agentshield.sdk import AgentShieldClient

    e, _, _ = live
    a = action(live)
    grant = authorize(live, a)
    expected = e.execute(grant, a, WORK)
    app = create_app(
        db_path=e.store.path,
        tokens={"developer": "dev", "worker": "worker", "reviewer": "review", "operator": "operator"},
        github=e.github,
    )

    async def check():
        async with AgentShieldClient("http://test", "worker", transport=httpx.ASGITransport(app=app)) as sdk:
            assert await sdk.execution_for_authorization(grant) == expected

    asyncio.run(check())
    unrelated = WORK.model_copy(update={"tenant": "unrelated"})
    with pytest.raises(ShieldError, match="NOT_FOUND"):
        e.execution_for_authorization(grant, unrelated)
