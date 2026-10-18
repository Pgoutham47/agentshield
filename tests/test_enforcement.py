import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from agentshield import adapter
from agentshield.analyzer import Analyzer
from agentshield.demo import DEVELOPER, OPERATOR, REVIEWER, WORKER, envelope, run_demo, task_contract
from agentshield.engine import Engine, ShieldError
from agentshield.models import Resolution, canonical, now


def run(value):
    return asyncio.run(value)


@pytest.fixture
def env(tmp_path):
    engine = Engine(tmp_path / "test.sqlite")
    task = engine.create_task(task_contract(), DEVELOPER)
    return engine, task


def proposal(env, op="comment_issue", args=None, **kwargs):
    engine, task = env
    return envelope(engine, task, op, args or {"issue_number": 412, "body": "Layout fix is ready."}, **kwargs)


def denied(env, action, reason):
    engine, _ = env
    d = run(engine.decide(action, WORKER))
    assert d.disposition == "deny"
    assert reason in d.reason_codes
    with pytest.raises(ShieldError):
        engine.execute(d.decision_id, action, WORKER)


@pytest.mark.parametrize("scenario", "ABC")
def test_acceptance_demos(tmp_path, scenario):
    engine = Engine(tmp_path / "demo.sqlite")
    result = run(run_demo(engine, scenario))
    assert result["draft_prs"] == 1
    assert result["published_comments"] == 0
    if scenario == "A":
        assert all(x["decision"]["disposition"] == "allow" for x in result["trace"])
    if scenario == "B":
        assert sum(x["decision"]["disposition"] == "deny" for x in result["trace"]) == 2
    if scenario == "C":
        held = [x for x in result["trace"] if x["decision"]["disposition"] == "require_approval"]
        assert len(held) == 1 and held[0]["approval"] == "rejected"
    assert engine.store.verify()


def test_off_baseline_allows_in_scope_leak(tmp_path):
    result = run(run_demo(Engine(tmp_path / "off.sqlite", Analyzer("off")), "C"))
    assert result["published_comments"] == 1  # Baseline limitation must be visible.


@pytest.mark.parametrize(
    "resource,destination,reason",
    [
        ("repo:acme/platform-secrets", "github:acme/web-ui", "RESOURCE_OUT_OF_SCOPE"),
        ("repo:acme/web-ui", "gist:public", "DESTINATION_OUT_OF_SCOPE"),
    ],
)
def test_scope_and_destination(env, resource, destination, reason):
    denied(env, proposal(env, repo=resource, destination=destination), reason)


def test_issue_argument_cannot_override_scope(env):
    action = proposal(env, args={"issue_number": 999, "body": "Unrelated issue"})
    action.resource_identifiers = ["repo:acme/web-ui", "issue:412"]
    denied(env, action, "ISSUE_OUT_OF_SCOPE")


@pytest.mark.parametrize(
    "op,args,reason",
    [
        ("push_commit", {"branch": "main", "files": {"x": "y"}, "message": "x"}, "PROTECTED_BRANCH"),
        (
            "push_commit",
            {"branch": "agent/fix", "files": {"x": "y"}, "message": "x", "force": True},
            "EXPLICIT_PROHIBITION",
        ),
        ("merge", {}, "EXPLICIT_PROHIBITION"),
        ("workflow_dispatch", {}, "EXPLICIT_PROHIBITION"),
        ("read_file", {"path": ".env"}, "SECRET_ACCESS"),
        ("read_file", {"path": "../config/internal.yaml"}, "INVALID_ARGUMENTS"),
        ("read_file", {"path": "/etc/passwd"}, "INVALID_ARGUMENTS"),
        ("read_file", {"path": "src/%2e%2e/other"}, "INVALID_ARGUMENTS"),
        ("comment_issue", {"issue_number": 412, "body": "AGENTSHIELD_SECRET_CANARY"}, "RESTRICTED_DATA"),
        (
            "open_draft_pr",
            {"branch": "agent/fix", "title": "Fix", "body": "Fix", "draft": False},
            "INVALID_ARGUMENTS",
        ),
        (
            "comment_issue",
            {"issue_number": 412, "body": "fix", "repository": "other/repo"},
            "INVALID_ARGUMENTS",
        ),
    ],
)
def test_hard_policy(env, op, args, reason):
    denied(env, proposal(env, op, args), reason)


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/build.yml",
        "Dockerfile",
        "package.json",
        "CODEOWNERS",
        "ci/build.sh",
        "pyproject.toml",
        "uv.lock",
    ],
)
def test_sensitive_file_review(env, path):
    action = proposal(
        env, "push_commit", {"branch": "agent/fix", "files": {path: "updated"}, "message": "Update"}
    )
    result = run(env[0].decide(action, WORKER))
    assert result.disposition == "require_approval"
    assert "SENSITIVE_FILE_CHANGE" in result.reason_codes


def test_deterministic_denial_short_circuits_ai(env):
    class MustNotCall(Analyzer):
        async def analyze(self, *args):
            pytest.fail("AI was consulted for an out-of-scope action")

    env[0].analyzer = MustNotCall()
    denied(env, proposal(env, repo="repo:acme/secret"), "RESOURCE_OUT_OF_SCOPE")


@pytest.mark.parametrize("failure", ["error", "invalid", "late"])
def test_analysis_failure_holds_writes_allows_reads(env, failure):
    class Broken(Analyzer):
        async def analyze(self, *args):
            if failure == "error":
                raise RuntimeError("unavailable")
            if failure == "late":
                await asyncio.sleep(3.1)
            return {"allow": True, "execute": "leak"}

    env[0].analyzer = Broken()
    result = run(env[0].decide(proposal(env), WORKER))
    assert result.disposition == "require_approval"
    assert "ANALYSIS_UNAVAILABLE" in result.reason_codes
    result = run(env[0].decide(proposal(env, "read_file", {"path": "src/Button.tsx"}), WORKER))
    assert result.disposition == "allow"


def approved(env):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    d = run(env[0].decide(action, WORKER))
    result = env[0].resolve(
        d.approval_id,
        Resolution(approve=True, action_digest=d.action_digest, justification="Synthetic approval test"),
        REVIEWER,
    )
    return action, d, result["decision"]["decision_id"]


def test_exact_approval_and_replay(env):
    action, original, grant = approved(env)
    changed = action.model_copy(deep=True)
    changed.canonical_arguments["body"] = "Changed after approval"
    with pytest.raises(ShieldError, match="DIGEST_MISMATCH"):
        env[0].execute(grant, changed, WORKER)
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        env[0].execute(original.decision_id, action, WORKER)
    result = env[0].execute(grant, action, WORKER)
    assert result["state"] == "succeeded"
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        env[0].execute(grant, action, WORKER)
    assert len(env[0].repo(env[1].task_id, DEVELOPER)["comments"]) == 1


def test_approval_requires_independent_role(env):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    d = run(env[0].decide(action, WORKER))
    resolution = Resolution(approve=True, action_digest=d.action_digest, justification="Testing separation")
    with pytest.raises(ShieldError, match="APPROVER_REQUIRED"):
        env[0].resolve(d.approval_id, resolution, WORKER)
    self_approver = DEVELOPER.model_copy(update={"role": "approver"})
    with pytest.raises(ShieldError, match="SELF_APPROVAL_FORBIDDEN"):
        env[0].resolve(d.approval_id, resolution, self_approver)


def test_approval_digest_and_repeat_resolution(env):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    d = run(env[0].decide(action, WORKER))
    with pytest.raises(ShieldError, match="DIGEST_MISMATCH"):
        env[0].resolve(
            d.approval_id,
            Resolution(approve=True, action_digest="wrong", justification="Bad binding"),
            REVIEWER,
        )
    env[0].resolve(
        d.approval_id,
        Resolution(approve=False, action_digest=d.action_digest, justification="No publication needed"),
        REVIEWER,
    )
    with pytest.raises(ShieldError, match="APPROVAL_ALREADY_RESOLVED"):
        env[0].resolve(
            d.approval_id,
            Resolution(approve=True, action_digest=d.action_digest, justification="Replay attempt"),
            REVIEWER,
        )


def test_resource_change_invalidates_grant(env):
    action, _, grant = approved(env)
    other = proposal(env, "create_branch", {"branch": "agent/fix"})
    d = run(env[0].decide(other, WORKER))
    env[0].execute(d.decision_id, other, WORKER)
    with pytest.raises(ShieldError, match="RESOURCE_VERSION_CHANGED"):
        env[0].execute(grant, action, WORKER)


def test_concurrent_execution_consumes_once(env):
    action, _, grant = approved(env)

    def attempt(_):
        try:
            return env[0].execute(grant, action, WORKER)["state"]
        except ShieldError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("succeeded") == 1
    assert len(env[0].repo(env[1].task_id, DEVELOPER)["comments"]) == 1


def test_concurrent_approval_consumes_once(env):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    d = run(env[0].decide(action, WORKER))

    def attempt(_):
        try:
            return env[0].resolve(
                d.approval_id,
                Resolution(approve=True, action_digest=d.action_digest, justification="Concurrent review"),
                REVIEWER,
            )["status"]
        except ShieldError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(attempt, range(6)))
    assert results.count("approved") == 1


def test_atomic_call_budget(tmp_path):
    engine = Engine(tmp_path / "budget.sqlite")
    task = task_contract()
    task.budget.max_calls = 2
    engine.create_task(task, DEVELOPER)
    actions = [envelope(engine, task, "read_file", {"path": "src/Button.tsx"}) for _ in range(10)]
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda a: run(engine.decide(a, WORKER)), actions))
    assert sum(r.disposition == "allow" for r in results) == 2
    assert sum("BUDGET_EXCEEDED" in r.reason_codes for r in results) == 8


def test_response_bytes_enforced_before_mock_effect(tmp_path):
    engine = Engine(tmp_path / "bytes.sqlite", Analyzer("off"))
    task = task_contract()
    task.budget.max_bytes = 550
    engine.create_task(task, DEVELOPER)
    action = envelope(engine, task, "read_file", {"path": "src/Button.tsx"})
    d = run(engine.decide(action, WORKER))
    assert d.disposition == "allow"
    result = engine.execute(d.decision_id, action, WORKER)
    assert result["state"] == "failed"
    assert result["result"]["error"] == "RESPONSE_BYTE_BUDGET_EXCEEDED"


def test_concurrency_limit(env):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))
    with env[0].store.transaction() as db:
        db.execute("UPDATE tasks SET active=4")
    with pytest.raises(ShieldError, match="CONCURRENCY_EXCEEDED"):
        env[0].execute(d.decision_id, action, WORKER)


def test_decision_idempotency_and_conflict(env):
    action = proposal(env)
    first = run(env[0].decide(action, WORKER))
    second = run(env[0].decide(action, WORKER))
    assert first == second
    assert env[0].overview(OPERATOR)["tasks"][0]["calls"] == 1
    action.canonical_arguments["body"] = "Mutated action"
    with pytest.raises(ShieldError, match="IDEMPOTENCY_CONFLICT"):
        run(env[0].decide(action, WORKER))


def test_pending_approval_survives_restart(env):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    d = run(env[0].decide(action, WORKER))
    restarted = Engine(env[0].store.path)
    assert restarted.overview(REVIEWER)["approvals"][0]["status"] == "pending"
    resolution = restarted.resolve(
        d.approval_id,
        Resolution(approve=True, action_digest=d.action_digest, justification="Reviewed after restart"),
        REVIEWER,
    )
    assert restarted.execute(resolution["decision"]["decision_id"], action, WORKER)["state"] == "succeeded"


def test_cancel_invalidates_existing_authorization(env):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))
    env[0].cancel(env[1].task_id, DEVELOPER)
    with pytest.raises(ShieldError, match="TASK_INACTIVE"):
        env[0].execute(d.decision_id, action, WORKER)
    denied(env, proposal(env), "TASK_INACTIVE")


def test_expiry_rechecked(env):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))
    with env[0].store.transaction() as db:
        task = env[1].model_copy(update={"expires_at": now() - timedelta(seconds=1)})
        db.execute("UPDATE tasks SET contract=?", (canonical(task),))
    with pytest.raises(ShieldError, match="TASK_EXPIRED"):
        env[0].execute(d.decision_id, action, WORKER)


def test_cross_tenant_access(env):
    other = WORKER.model_copy(update={"tenant": "other"})
    with pytest.raises(ShieldError, match="NOT_FOUND"):
        run(env[0].decide(proposal(env), other))
    assert env[0].overview(other)["tasks"] == []
    assert env[0].store.events("other") == []


def test_other_requester_cannot_act(env):
    other = WORKER.model_copy(update={"requester": "stranger@example.com"})
    with pytest.raises(ShieldError, match="IDENTITY_MISMATCH"):
        run(env[0].decide(proposal(env), other))


def test_provider_timeout_is_unknown_and_not_retried(env, monkeypatch):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))

    def timeout(*args):
        raise TimeoutError()

    monkeypatch.setattr(adapter, "apply", timeout)
    result = env[0].execute(d.decision_id, action, WORKER)
    assert result["state"] == "outcome_unknown"
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        env[0].execute(d.decision_id, action, WORKER)


def test_audit_failure_prevents_effect(env, monkeypatch):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))

    def fail(*args):
        raise OSError("audit unavailable")

    monkeypatch.setattr(env[0].store, "event", fail)
    with pytest.raises(OSError):
        env[0].execute(d.decision_id, action, WORKER)
    assert env[0].repo(env[1].task_id, DEVELOPER)["comments"] == []


def test_audit_redaction_and_append_only(env, tmp_path):
    action = proposal(env, args={"issue_number": 412, "body": adapter.INTERNAL})
    run(env[0].decide(action, WORKER))
    target = tmp_path / "audit.jsonl"
    env[0].store.export("acme", target)
    assert "ledger-db" not in target.read_text()
    assert env[0].store.verify()
    with pytest.raises(Exception, match="append-only"):
        with env[0].store.transaction() as db:
            db.execute("DELETE FROM events")
    assert all("hash" in json.loads(line) for line in target.read_text().splitlines())


def test_interrupted_execution_recovers_unknown_without_replay(env, monkeypatch):
    action = proposal(env)
    d = run(env[0].decide(action, WORKER))

    def crash(*args):
        raise RuntimeError("process crashed after intent")

    monkeypatch.setattr(adapter, "apply", crash)
    with pytest.raises(RuntimeError):
        env[0].execute(d.decision_id, action, WORKER)
    restarted = Engine(env[0].store.path)
    restarted.recover()
    with restarted.store.transaction() as db:
        execution_id = db.execute("SELECT id FROM executions").fetchone()[0]
    assert restarted.execution(execution_id, WORKER)["state"] == "outcome_unknown"
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        restarted.execute(d.decision_id, action, WORKER)
    assert restarted.repo(env[1].task_id, DEVELOPER)["comments"] == []
