"""Opt-in hosted sandbox verification. Uses gateway tokens, never provider credentials.

Creates a branch, commit and draft PR; no merge or issue comment is published.
"""

import argparse
import asyncio
import json
from pathlib import Path
from uuid import uuid4

import httpx

from agentshield.github_demo import FIX_CSS, FIX_TEST
from agentshield.models import Action, Decision, Resolution, Task, digest
from agentshield.sdk import AgentShieldClient


async def verify(args):
    if not args.approve_sandbox_writes:
        raise ValueError("Explicit --approve-sandbox-writes is required")
    if not args.url.startswith("https://"):
        raise ValueError("Hosted verification requires HTTPS")
    tokens = json.loads(Path(args.tokens).read_text())
    report = {"url": args.url, "analysis": "fixture", "review": "scripted sandbox reviewer", "trace": []}
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)

    def save():
        target.write_text(json.dumps(report, indent=2))

    async with (
        AgentShieldClient(args.url, tokens["developer"]) as developer,
        AgentShieldClient(args.url, tokens["worker"]) as worker,
        AgentShieldClient(args.url, tokens["reviewer"]) as reviewer,
    ):
        response = await reviewer.http.get("/v1/integrations/github?verify=true")
        response.raise_for_status()
        integration = response.json()
        repo = integration.get("repository", "")
        if not (
            repo.endswith("/agentshield-github-sandbox")
            and integration.get("writes_enabled")
            and integration.get("auth_mode") == "app"
            and integration.get("connection") == "verified"
        ):
            raise ValueError("Verified GitHub App with enabled writes on the sandbox is required")
        report["integration"] = integration
        task = await developer.create_task(
            Task(
                provider="github",
                tenant="acme",
                requester="dev@acme.example",
                purpose="Verify the hosted gateway while fixing button overflow in sandbox issue 1",
                resources=["repo:" + repo],
                destinations=["github:" + repo],
                issue_ids=[1],
            )
        )
        report["task_id"] = task.task_id
        save()

        async def propose(operation, arguments, approve=True, resource=None):
            resources = [resource or "repo:" + repo]
            if "issue_number" in arguments:
                resources.append("issue:" + str(arguments["issue_number"]))
            action = Action(
                task_id=task.task_id,
                operation=operation,
                canonical_arguments=arguments,
                resource_identifiers=resources,
                destination="github:" + repo,
                expected_resource_version="unprepared",
                adapter_version="github-rest-1",
                source_references=["issue:1#body"],
            )
            if resource is None:
                action = await worker.prepare(action)
            decision = await worker.decide(action)
            item = {"operation": operation, "decision": decision.model_dump(mode="json")}
            report["trace"].append(item)
            save()
            if decision.disposition == "require_approval":
                review = await reviewer.resolve(
                    decision.approval_id,
                    Resolution(
                        approve=approve,
                        action_digest=decision.action_digest,
                        justification="Scripted review for the user-authorized synthetic sandbox verification."
                        if approve
                        else "Reject unrelated internal configuration publication.",
                    ),
                )
                item["review"] = review["status"]
                if approve:
                    decision = Decision.model_validate(review["decision"])
            if decision.disposition == "allow":
                item["execution"] = await worker.execute(decision, action)
                save()
                if item["execution"]["state"] != "succeeded":
                    raise RuntimeError("Execution did not succeed; inspect the saved trace. Do not retry.")
                if operation == "read_issue":
                    try:
                        await worker.execute(decision, action)
                    except httpx.HTTPStatusError as error:
                        report["replay_rejected"] = error.response.json().get("error")
                        if report["replay_rejected"] != "AUTHORIZATION_NOT_USABLE":
                            raise RuntimeError("Replay failed for an unexpected reason") from None
                    else:
                        raise RuntimeError("Consumed grant unexpectedly accepted")
            if not approve and item.get("review") != "rejected":
                raise RuntimeError("Expected internal comment review and rejection")
            if resource and decision.disposition != "deny":
                raise RuntimeError("Expected cross-repository denial")
            save()
            print(
                operation + ": " + item["decision"]["disposition"] + " " + item.get("review", ""), flush=True
            )
            return item.get("execution", {}).get("result", {})

        await propose("read_issue", {"issue_number": 1})
        await propose("read_file", {"path": "src/button.css"})
        internal = await propose("read_file", {"path": "config/internal.yaml"})
        await propose("comment_issue", {"issue_number": 1, "body": internal["content"]}, approve=False)
        await propose("read_file", {"path": "README.md"}, resource="repo:outside/unauthorized")
        branch = "agent/hosted-verification-" + uuid4().hex[:8]
        await propose("create_branch", {"branch": branch})
        await propose(
            "push_commit",
            {
                "branch": branch,
                "files": {"src/button.css": FIX_CSS, "tests/button.test.mjs": FIX_TEST},
                "message": "Fix sandbox button wrapping through the hosted AgentShield gateway",
            },
        )
        result = await propose(
            "open_draft_pr",
            {
                "branch": branch,
                "draft": True,
                "title": "Verify hosted AgentShield with the sandbox button fix",
                "body": "Allows the synthetic sample button label to wrap inside narrow containers and adds regression checks. "
                "This draft verifies the Render-hosted AgentShield API, Supabase persistence, and scoped GitHub App. "
                "Writes used an explicitly enabled scripted reviewer; contextual analysis used fixtures. "
                "The internal-configuration comment was rejected, and an unrelated-repository read was denied. "
                "This is integration evidence, not a live-model security benchmark. No merge is performed.",
            },
        )
        report["pull_request"] = result["pull_request"]
        save()
        response = await reviewer.http.get("/v1/events/export")
        response.raise_for_status()
        target.with_suffix(".audit.jsonl").write_text(response.text)
        previous = "genesis"
        events = [json.loads(line) for line in response.text.splitlines()]
        for sequence, event in enumerate(events, 1):
            stored_hash = event.pop("hash")
            if (
                event["sequence"] != sequence
                or event["previous_hash"] != previous
                or digest(event) != stored_hash
            ):
                raise RuntimeError("Audit chain verification failed")
            previous = stored_hash
        report["audit_valid"] = True
        report["audit_events"] = len(events)
        save()
        print(
            json.dumps({"task_id": task.task_id, "pull_request": report["pull_request"], "audit_valid": True})
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument(
        "--tokens", required=True, help="Protected JSON file with developer, worker, reviewer tokens"
    )
    parser.add_argument("--approve-sandbox-writes", action="store_true")
    parser.add_argument("--output", default="output/hosted-verification.json")
    args = parser.parse_args()
    asyncio.run(verify(args))
