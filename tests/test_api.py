from fastapi.testclient import TestClient

from agentshield.api import create_app
from agentshield.demo import DEVELOPER, task_contract

TOKENS = {
    "developer": "test-developer",
    "worker": "test-worker",
    "reviewer": "test-reviewer",
    "operator": "test-operator",
}


def test_api_workflow_and_roles(tmp_path):
    app = create_app(tmp_path / "api.sqlite", TOKENS.copy())
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/v1/overview").status_code == 401
        headers = {"Authorization": "Bearer test-operator"}
        assert client.get("/", headers=headers).status_code == 200
        result = client.post("/v1/demo", headers=headers, json={"scenario": "C", "leave_pending": True})
        assert result.status_code == 200, result.text
        overview = client.get("/v1/overview", headers=headers).json()
        assert len(overview["tasks"]) == 1
        assert overview["approvals"][0]["status"] == "pending"
        assert client.get("/v1/overview", headers={"Authorization": "Bearer test-worker"}).status_code == 403
        assert client.get("/v1/events/export", headers=headers).status_code == 200
        assert client.post("/v1/demo", headers=headers, json={"scenario": "Z"}).status_code == 422
        assert client.post("/v1/tasks", headers=headers, content="x" * 100001).status_code == 413
        assert client.get("/v1/events?limit=1001", headers=headers).status_code == 422


def test_draft_is_proposal_only_and_bounded(tmp_path):
    app = create_app(tmp_path / "api.sqlite", TOKENS.copy())
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer test-developer"}
        request = {
            "request": "Fix issue 412 in web-ui",
            "entitlements": ["repo:acme/web-ui", "repo:acme/secret"],
        }
        draft = client.post("/v1/tasks/draft", headers=headers, json=request).json()
        assert draft["draft_source"] == "template"
        assert draft["requires_confirmation"] is True
        assert draft["contract"]["resources"] == ["repo:acme/web-ui"]
        assert app.state.engine.overview(DEVELOPER)["tasks"] == []
        result = client.post("/v1/tasks", headers=headers, json=draft["contract"])
        assert result.status_code == 200
        assert client.post("/v1/tasks", headers=headers, json=draft["contract"]).status_code == 200


def test_task_cannot_escalate_entitlements(tmp_path):
    app = create_app(tmp_path / "api.sqlite", TOKENS.copy())
    with TestClient(app) as client:
        task = task_contract().model_dump(mode="json")
        task["resources"] = ["repo:acme/secret"]
        response = client.post("/v1/tasks", headers={"Authorization": "Bearer test-developer"}, json=task)
        assert response.status_code == 403
