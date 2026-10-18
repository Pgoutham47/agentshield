"""Small asynchronous SDK. It holds only gateway credentials and never invokes a provider."""

import httpx

from .models import Action, Decision, DraftRequest, Resolution, Task


class AgentShieldClient:
    def __init__(self, base_url, token, *, transport=None, timeout=180):
        self.http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.http.aclose()

    async def _post(self, path, body):
        response = await self.http.post(path, json=body)
        response.raise_for_status()
        return response.json()

    async def draft_task(self, request: DraftRequest):
        return await self._post("/v1/tasks/draft", request.model_dump(mode="json"))

    async def create_task(self, task: Task):
        return Task.model_validate(await self._post("/v1/tasks", task.model_dump(mode="json")))

    async def prepare(self, action: Action):
        return Action.model_validate(await self._post("/v1/actions/prepare", action.model_dump(mode="json")))

    async def decide(self, action: Action):
        return Decision.model_validate(await self._post("/v1/decisions", action.model_dump(mode="json")))

    async def execute(self, decision: Decision, action: Action):
        # Never retry a write automatically; query the execution outcome instead.
        if decision.disposition != "allow":
            raise ValueError("An allow authorization is required")
        return await self._post(
            "/v1/executions",
            {"decision_id": decision.decision_id, "envelope": action.model_dump(mode="json")},
        )

    async def execution(self, execution_id):
        response = await self.http.get(f"/v1/executions/{execution_id}")
        response.raise_for_status()
        return response.json()

    async def execution_for_authorization(self, decision_id):
        """After a client timeout, look up the known grant; never resubmit automatically."""
        response = await self.http.get(f"/v1/authorizations/{decision_id}/execution")
        response.raise_for_status()
        return response.json()

    async def resolve(self, approval_id, resolution: Resolution):
        return await self._post(f"/v1/approvals/{approval_id}/resolve", resolution.model_dump(mode="json"))

    async def cancel(self, task_id):
        return await self._post(f"/v1/tasks/{task_id}/cancel", {})
