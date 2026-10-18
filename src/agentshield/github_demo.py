"""Explicitly opted-in live sandbox demonstration. Scripted proposals, not a live agent."""

import json
from pathlib import Path
from uuid import uuid4

from .analyzer import Analyzer
from .demo import DEVELOPER, REVIEWER, WORKER
from .engine import Engine
from .github import ADAPTER_VERSION, GitHubAdapter, GitHubSettings
from .models import Action, Resolution, Task

FIX_CSS = """body { font-family: system-ui, sans-serif; margin: 2rem; }
main { max-width: 24rem; }
.button {
  font: inherit;
  padding: 0.75rem 1rem;
  box-sizing: border-box;
  max-width: 100%;
  min-width: 0;
  white-space: normal;
  overflow-wrap: anywhere;
}
"""
FIX_TEST = """import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('sample has an accessible native button and mobile viewport', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /<button[^>]*type="button"/);
  assert.match(html, /name="viewport"/);
});

test('button styles permit wrapping within its container', () => {
  const css = readFileSync(new URL('../src/button.css', import.meta.url), 'utf8');
  for (const rule of ['white-space: normal', 'overflow-wrap: anywhere', 'max-width: 100%', 'box-sizing: border-box']) {
    assert.ok(css.includes(rule), `Missing layout rule: ${rule}`);
  }
  assert.ok(!css.includes('white-space: nowrap'));
});
"""


async def run_github_demo(db, issue_number, output, approve_sandbox_writes=False):
    settings = GitHubSettings.from_env()
    if not settings or not settings.repository.endswith("/agentshield-github-sandbox"):
        raise ValueError("This demonstration requires a disposable agentshield-github-sandbox repository.")
    if not approve_sandbox_writes or not settings.enable_writes:
        raise ValueError("Explicit --approve-sandbox-writes and GITHUB_ENABLE_WRITES=true are required.")
    repo = settings.repository
    dev, reviewer, worker = [
        p.model_copy(update={"resources": ["repo:" + repo]}) for p in (DEVELOPER, REVIEWER, WORKER)
    ]
    engine = Engine(db, Analyzer("fixture"), GitHubAdapter(settings))
    task = engine.create_task(
        Task(
            provider="github",
            tenant="acme",
            requester=dev.subject,
            purpose=f"Fix button label overflow on narrow screens in issue {issue_number}",
            resources=dev.resources,
            destinations=["github:" + repo],
            issue_ids=[issue_number],
        ),
        dev,
    )
    report = {
        "repository": repo,
        "task_id": task.task_id,
        "provider": "github",
        "analysis": "fixture",
        "approval_mode": "scripted sandbox reviewer, explicitly enabled by operator; not a human-review efficacy test",
        "trace": [],
    }
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)

    def save():
        target.write_text(json.dumps(report, indent=2))
        engine.store.export("acme", str(target.with_suffix(".audit.jsonl")))

    async def propose(op, args, approve=True, resource=None):
        resources = [resource or "repo:" + repo]
        if "issue_number" in args:
            resources.append(f"issue:{args['issue_number']}")
        a = Action(
            task_id=task.task_id,
            operation=op,
            canonical_arguments=args,
            resource_identifiers=resources,
            destination="github:" + repo,
            expected_resource_version="unprepared",
            adapter_version=ADAPTER_VERSION,
            source_references=[f"issue:{issue_number}#body"],
        )
        if not resource:
            a = engine.prepare(a, worker)
        d = await engine.decide(a, worker)
        item = {"operation": op, "decision": d.model_dump(mode="json")}
        report["trace"].append(item)
        save()
        grant = d.decision_id
        if d.disposition == "require_approval":
            result = engine.resolve(
                d.approval_id,
                Resolution(
                    approve=approve,
                    action_digest=d.action_digest,
                    justification="Scripted reviewer: approved exact synthetic fix for user-authorized sandbox test."
                    if approve
                    else "Reject publishing internal configuration; unrelated to the layout fix.",
                ),
                reviewer,
            )
            item["review"] = result["status"]
            if approve:
                grant = result["decision"]["decision_id"]
        if d.disposition == "allow" or (d.disposition == "require_approval" and approve):
            item["execution"] = engine.execute(grant, a, worker)
            save()
            if item["execution"]["state"] != "succeeded":
                raise RuntimeError(json.dumps(item["execution"]))
        print(
            f"{op}: {d.disposition}" + (f" → {item['execution']['state']}" if "execution" in item else ""),
            flush=True,
        )
        save()
        return item.get("execution", {}).get("result", {})

    await propose("read_issue", {"issue_number": issue_number})
    await propose("read_file", {"path": "src/button.css"})
    internal = await propose("read_file", {"path": "config/internal.yaml"})
    await propose("comment_issue", {"issue_number": issue_number, "body": internal["content"]}, approve=False)
    await propose("read_file", {"path": "README.md"}, resource="repo:outside/unauthorized")
    branch = "agent/fix-issue-" + str(issue_number) + "-" + uuid4().hex[:8]
    await propose("create_branch", {"branch": branch})
    await propose(
        "push_commit",
        {
            "branch": branch,
            "files": {"src/button.css": FIX_CSS, "tests/button.test.mjs": FIX_TEST},
            "message": "Fix narrow-screen button wrapping and add regression checks",
        },
    )
    pr = await propose(
        "open_draft_pr",
        {
            "branch": branch,
            "title": "Fix button label overflow on narrow screens",
            "draft": True,
            "body": f"Allows long button labels to wrap within the available width, including unbroken words, and adds style regression checks. Fixes #{issue_number}.\n\nValidation: Node built-in tests pass. This is a synthetic AgentShield integration demonstration; writes used an explicitly enabled scripted sandbox reviewer. The proposed internal-configuration comment was rejected and was not published.\n\nThis PR remains a draft and is not merged.",
        },
    )
    report["pull_request"] = pr["pull_request"]
    save()
    print(pr["pull_request"]["url"], flush=True)
    await propose(
        "comment_issue",
        {
            "issue_number": issue_number,
            "body": f"Synthetic integration verification completed. The layout fix is available in draft PR #{pr['pull_request']['number']}. The unrelated configuration-publication request was rejected. No merge was performed.",
        },
    )
    report["audit_valid"] = engine.store.verify()
    save()
    return report
