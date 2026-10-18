import asyncio
import json
from datetime import timedelta

from . import adapter, policy
from .analyzer import Analyzer
from .github import GitHubError, resource_version
from .live import LiveExecution
from .models import OPERATIONS, POLICY, WRITES, Decision, Signals, Task, canonical, digest, now, uid
from .store import Store


class ShieldError(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


class Engine(LiveExecution):
    def __init__(self, path, analyzer=None, github=None):
        self.github = github
        self.store = Store(path)
        self.analyzer = analyzer or Analyzer()

    @staticmethod
    def _task(db, task_id, principal, act=False):
        row = db.execute(
            "SELECT * FROM tasks WHERE id=? AND tenant=?", (task_id, principal.tenant)
        ).fetchone()
        if not row:
            raise ShieldError("NOT_FOUND", 404)
        task = Task.model_validate_json(row["contract"])
        if not set(task.resources).issubset(principal.resources):
            raise ShieldError("RESOURCE_FORBIDDEN", 403)
        if act and (
            principal.role not in {"requester", "worker"}
            or principal.requester != task.requester
            or (principal.role == "worker" and principal.subject != task.agent)
        ):
            raise ShieldError("IDENTITY_MISMATCH", 403)
        return row, task

    def create_task(self, task, principal, issue=adapter.ISSUE):
        if (
            principal.role not in {"requester", "admin"}
            or task.tenant != principal.tenant
            or task.requester != principal.requester
        ):
            raise ShieldError("IDENTITY_MISMATCH", 403)
        if not set(task.resources).issubset(principal.resources):
            raise ShieldError("ENTITLEMENTS_EXCEEDED", 403)
        if task.policy_version != POLICY or not set(task.operations).issubset(OPERATIONS + ["create_gist"]):
            raise ShieldError("INVALID_CONTRACT", 400)
        if any(
            d not in [r.replace("repo:", "github:", 1) for r in task.resources] for d in task.destinations
        ):
            raise ShieldError("INVALID_DESTINATIONS", 400)
        # Prototype adapter has one explicit fixture repository and issue.
        if task.provider == "mock" and (task.resources != ["repo:acme/web-ui"] or task.issue_ids != [412]):
            raise ShieldError("MOCK_RESOURCE_UNSUPPORTED", 400)
        if task.provider == "github":
            if not self.github:
                raise ShieldError("GITHUB_NOT_CONFIGURED", 503)
            if "read_issue" not in task.operations:
                raise ShieldError("GITHUB_TASK_REQUIRES_ISSUE_READ", 400)
        with self.store.transaction() as db:
            existing = db.execute(
                "SELECT contract FROM tasks WHERE tenant=? AND idem=?", (task.tenant, task.idempotency_key)
            ).fetchone()
            if existing:
                if digest(json.loads(existing[0])) != digest(task):
                    raise ShieldError("IDEMPOTENCY_CONFLICT")
                return task
        if task.expires_at <= now() or task.expires_at > now() + timedelta(hours=1):
            raise ShieldError("INVALID_TASK_EXPIRY", 400)
        try:
            repo_state = (
                self.github.initialize(task) if task.provider == "github" else adapter.fresh_repo(issue)
            )
        except GitHubError as error:
            raise ShieldError(error.code, 503) from None
        with self.store.transaction() as db:
            existing = db.execute(
                "SELECT contract FROM tasks WHERE tenant=? AND idem=?", (task.tenant, task.idempotency_key)
            ).fetchone()
            if existing:
                if digest(json.loads(existing[0])) != digest(task):
                    raise ShieldError("IDEMPOTENCY_CONFLICT")
                return task
            if task.expires_at <= now() or task.expires_at > now() + timedelta(hours=1):
                raise ShieldError("INVALID_TASK_EXPIRY", 400)
            if db.execute("SELECT 1 FROM tasks WHERE id=?", (task.task_id,)).fetchone():
                raise ShieldError("TASK_ID_CONFLICT")
            db.execute(
                "INSERT INTO tasks(id,tenant,idem,contract) VALUES(?,?,?,?)",
                (task.task_id, task.tenant, task.idempotency_key, canonical(task)),
            )
            db.execute("INSERT INTO repos VALUES(?,?)", (task.task_id, canonical(repo_state)))
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "task_created",
                {"policy_version": POLICY, "contract_digest": digest(task)},
            )
        return task

    async def draft(self, request, principal):
        if principal.role not in {"requester", "admin"}:
            raise ShieldError("ROLE_FORBIDDEN", 403)
        resources = sorted(set(request.entitlements) & set(principal.resources))
        if not resources:
            raise ShieldError("NO_ENTITLEMENTS", 403)
        try:
            selected, source = await self.analyzer.draft(request.request, resources)
        except Exception:
            raise ShieldError("DRAFT_ANALYSIS_UNAVAILABLE", 503) from None
        task = Task(
            provider=request.provider,
            tenant=principal.tenant,
            requester=principal.requester,
            purpose=request.request,
            resources=selected,
            destinations=[r.replace("repo:", "github:", 1) for r in selected],
            issue_ids=[request.issue_number],
        )
        return {
            "contract": task.model_dump(mode="json"),
            "draft_source": source,
            "requires_confirmation": True,
        }

    def repo(self, task_id, principal):
        with self.store.transaction() as db:
            self._task(db, task_id, principal)
            return json.loads(db.execute("SELECT state FROM repos WHERE task_id=?", (task_id,)).fetchone()[0])

    @staticmethod
    def _existing(db, action):
        row = db.execute(
            "SELECT * FROM decisions WHERE task_id=? AND (action_id=? OR idem=?)",
            (action.task_id, action.action_id, action.idempotency_key),
        ).fetchone()
        if row and digest(json.loads(row["action"])) != digest(action):
            raise ShieldError("IDEMPOTENCY_CONFLICT")
        return Decision.model_validate_json(row["response"]) if row else None

    async def decide(self, action, principal):
        # Read first; never hold a SQLite transaction across a model/network await.
        with self.store.transaction() as db:
            row, task = self._task(db, action.task_id, principal, act=True)
            existing = self._existing(db, action)
            if existing:
                return existing
            denial = policy.deterministic(task, action, row["status"])
            amount = len(canonical(action).encode())
            if not denial and (
                row["calls"] >= task.budget.max_calls or row["bytes"] + amount > task.budget.max_bytes
            ):
                denial = "BUDGET_EXCEEDED"
            repo = json.loads(
                db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
            )
            recent = [
                json.loads(r[0])
                for r in db.execute(
                    "SELECT action FROM decisions WHERE task_id=? ORDER BY rowid DESC LIMIT 5",
                    (task.task_id,),
                )
            ][::-1]
        signals, unavailable = None, False
        if not denial and self.analyzer.mode != "off":
            try:
                async with asyncio.timeout(3):
                    raw = await self.analyzer.analyze(task, action, recent, repo["issue"]["body"])
                    signals = Signals.model_validate(raw)
            except Exception:
                unavailable = True
        with self.store.transaction() as db:
            row, task = self._task(db, action.task_id, principal, act=True)
            existing = self._existing(db, action)
            if existing:
                return existing
            denial = policy.deterministic(task, action, row["status"])
            if not denial and (
                row["calls"] >= task.budget.max_calls or row["bytes"] + amount > task.budget.max_bytes
            ):
                denial = "BUDGET_EXCEEDED"
            reasons = [denial] if denial else []
            disposition = "deny" if denial else "allow"
            if not denial:
                db.execute("UPDATE tasks SET calls=calls+1,bytes=bytes+? WHERE id=?", (amount, task.task_id))
                review = policy.review_required(action)
                if review:
                    reasons.append(review)
                if action.operation in WRITES:
                    if task.provider == "github":
                        reasons.append("LIVE_WRITE_REVIEW")
                    if unavailable:
                        reasons.append("ANALYSIS_UNAVAILABLE")
                    if signals:
                        if signals.exposure.score >= 0.7:
                            reasons.append("AI_EXPOSURE_INTERNAL")
                        if signals.injection.score >= 0.7:
                            reasons.append("AI_INJECTION")
                        if signals.intent_alignment.score <= 0.3:
                            reasons.append("AI_INTENT_MISMATCH")
                        if signals.flow.score >= 0.7:
                            reasons.append("AI_FLOW_RISK")
                if reasons:
                    disposition = "require_approval"
            reasons = reasons or ["ALLOWED"]
            result = Decision(
                disposition=disposition,
                reason_codes=reasons,
                applicable_rule_ids=[f"{POLICY}/{r.lower()}" for r in reasons],
                detector_versions=self.analyzer.versions,
                signals=signals if not denial else None,
                explanation=policy.EXPLANATIONS.get(
                    reasons[0], reasons[0].replace("_", " ").capitalize() + "."
                ),
                suggested_next_step="Continue the authorized fix."
                if disposition == "allow"
                else "Continue safe work, revise this action, or ask an authorized reviewer.",
                action_digest=digest(action),
                expires_at=min(task.expires_at, now() + timedelta(minutes=15)),
                approval_id=uid("ap") if disposition == "require_approval" else None,
            )
            state = {"allow": "authorized", "deny": "denied", "require_approval": "awaiting_approval"}[
                disposition
            ]
            db.execute(
                "INSERT INTO decisions VALUES(?,?,?,?,?,?,?)",
                (
                    result.decision_id,
                    task.task_id,
                    action.action_id,
                    action.idempotency_key,
                    canonical(action),
                    canonical(result),
                    state,
                ),
            )
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "action_proposed",
                {
                    "action_id": action.action_id,
                    "operation": action.operation,
                    "action_digest": digest(action),
                },
            )
            # Audit metadata deliberately excludes payloads and model-generated rationales.
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "decision",
                {
                    "decision_id": result.decision_id,
                    "disposition": disposition,
                    "reason_codes": reasons,
                    "policy_version": POLICY,
                    "detector_versions": self.analyzer.versions,
                    "action_digest": digest(action),
                },
            )
            if result.approval_id:
                db.execute(
                    "INSERT INTO approvals VALUES(?,?,?,?,NULL)",
                    (result.approval_id, result.decision_id, task.task_id, "pending"),
                )
                self.store.event(
                    db,
                    task.tenant,
                    task.task_id,
                    "approval_requested",
                    {"approval_id": result.approval_id, "action_digest": digest(action)},
                )
            return result

    def resolve(self, approval_id, resolution, principal):
        from .models import Action

        if principal.role not in {"approver", "admin"}:
            raise ShieldError("APPROVER_REQUIRED", 403)
        with self.store.transaction() as db:
            ap = db.execute(
                "SELECT a.* FROM approvals a JOIN tasks t ON a.task_id=t.id WHERE a.id=? AND t.tenant=?",
                (approval_id, principal.tenant),
            ).fetchone()
            if not ap:
                raise ShieldError("NOT_FOUND", 404)
            row, task = self._task(db, ap["task_id"], principal)
            if principal.subject == task.requester:
                raise ShieldError("SELF_APPROVAL_FORBIDDEN", 403)
            if ap["status"] != "pending":
                raise ShieldError("APPROVAL_ALREADY_RESOLVED")
            item = db.execute("SELECT * FROM decisions WHERE id=?", (ap["decision_id"],)).fetchone()
            original = Decision.model_validate_json(item["response"])
            action = Action.model_validate_json(item["action"])
            if resolution.action_digest != original.action_digest:
                raise ShieldError("DIGEST_MISMATCH")
            if original.expires_at <= now():
                raise ShieldError("APPROVAL_EXPIRED")
            if resolution.approve:
                denial = policy.deterministic(task, action, row["status"])
                if denial:
                    raise ShieldError(denial, 403)
                repo = json.loads(
                    db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
                )
                if (
                    resource_version(repo, action) if task.provider == "github" else adapter.version(repo)
                ) != action.expected_resource_version:
                    raise ShieldError("RESOURCE_VERSION_CHANGED")
            response = {"status": "approved" if resolution.approve else "rejected"}
            if resolution.approve:
                grant = original.model_copy(
                    update={
                        "decision_id": uid("d"),
                        "disposition": "allow",
                        "parent_decision_id": original.decision_id,
                        "approval_id": approval_id,
                        "reason_codes": ["EXACT_ACTION_APPROVED"],
                        "explanation": "An authorized reviewer approved this exact action.",
                    }
                )
                db.execute(
                    "INSERT INTO grants VALUES(?,?,?,?,?)",
                    (grant.decision_id, task.task_id, canonical(action), canonical(grant), "authorized"),
                )
                response["decision"] = grant.model_dump(mode="json")
            db.execute(
                "UPDATE approvals SET status=?,resolution=? WHERE id=?",
                (response["status"], canonical(response), approval_id),
            )
            db.execute("UPDATE decisions SET state=? WHERE id=?", (response["status"], original.decision_id))
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "approval_resolved",
                {
                    "approval_id": approval_id,
                    "status": response["status"],
                    "actor": principal.subject,
                    "action_digest": original.action_digest,
                    "justification_digest": digest(resolution.justification),
                },
            )
            return response

    def execute(self, decision_id, action, principal):
        with self.store.transaction() as db:
            _, bound_task = self._task(db, action.task_id, principal, act=True)
        if bound_task.provider == "github":
            return self._execute_github(decision_id, action, principal)
        with self.store.transaction() as db:
            row, task = self._task(db, action.task_id, principal, act=True)
            table = "decisions"
            record = db.execute(
                "SELECT * FROM decisions WHERE id=? AND task_id=?", (decision_id, task.task_id)
            ).fetchone()
            if not record:
                table = "grants"
                record = db.execute(
                    "SELECT * FROM grants WHERE id=? AND task_id=?", (decision_id, task.task_id)
                ).fetchone()
            if not record:
                raise ShieldError("NOT_FOUND", 404)
            decision = Decision.model_validate_json(record["response"])
            if digest(action) != decision.action_digest:
                raise ShieldError("DIGEST_MISMATCH")
            if decision.disposition != "allow" or record["state"] != "authorized":
                raise ShieldError("AUTHORIZATION_NOT_USABLE")
            if decision.expires_at <= now():
                raise ShieldError("AUTHORIZATION_EXPIRED")
            denial = policy.deterministic(task, action, row["status"])
            if denial:
                raise ShieldError(denial, 403)
            repo = json.loads(
                db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
            )
            if action.expected_resource_version != adapter.version(repo):
                raise ShieldError("RESOURCE_VERSION_CHANGED")
            if row["active"] >= task.budget.max_concurrency:
                raise ShieldError("CONCURRENCY_EXCEEDED", 429)
            execution_id = uid("ex")
            db.execute(f"UPDATE {table} SET state='consumed' WHERE id=?", (decision_id,))
            db.execute("UPDATE tasks SET active=active+1 WHERE id=?", (task.task_id,))
            db.execute(
                "INSERT INTO executions VALUES(?,?,?,?,NULL)",
                (execution_id, decision_id, task.task_id, "executing"),
            )
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "execution_started",
                {"execution_id": execution_id, "decision_id": decision_id, "operation": action.operation},
            )
        # Execution intent is durable before side effects. A crash cannot replay this grant.
        with self.store.transaction() as db:
            row, task = self._task(db, action.task_id, principal, act=True)
            repo = json.loads(
                db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
            )
            state, result = "succeeded", None
            try:
                denial = policy.deterministic(task, action, row["status"])
                if denial:
                    raise ValueError(denial)
                if decision.expires_at <= now():
                    raise ValueError("AUTHORIZATION_EXPIRED")
                if action.expected_resource_version != adapter.version(repo):
                    raise ValueError("RESOURCE_VERSION_CHANGED")
                updated, result = adapter.apply(repo, action)
                result_bytes = len(canonical(result).encode())
                if row["bytes"] + result_bytes > task.budget.max_bytes:
                    raise ValueError("RESPONSE_BYTE_BUDGET_EXCEEDED")
                db.execute("UPDATE repos SET state=? WHERE task_id=?", (canonical(updated), task.task_id))
                db.execute("UPDATE tasks SET bytes=bytes+? WHERE id=?", (result_bytes, task.task_id))
            except TimeoutError:
                state, result = (
                    "outcome_unknown",
                    {"error": "Provider outcome requires reconciliation; do not retry."},
                )
            except ValueError as exc:
                state, result = "failed", {"error": str(exc)}
            response = {
                "execution_id": execution_id,
                "state": state,
                "result": result,
                "provider_request_id": "mock:" + execution_id,
                "adapter_version": "mock-github-1",
            }
            db.execute(
                "UPDATE executions SET state=?,result=? WHERE id=?",
                (state, canonical(response), execution_id),
            )
            db.execute("UPDATE tasks SET active=active-1 WHERE id=?", (task.task_id,))
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "execution_result",
                {
                    "execution_id": execution_id,
                    "state": state,
                    "provider_request_id": response["provider_request_id"],
                },
            )
            return response

    def execution_for_authorization(self, decision_id, principal):
        """Recover a response lost in transit using the caller's already-known grant ID."""
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT e.id,e.task_id FROM executions e JOIN tasks t ON t.id=e.task_id "
                "WHERE e.decision_id=? AND t.tenant=?",
                (decision_id, principal.tenant),
            ).fetchone()
            if not row:
                raise ShieldError("NOT_FOUND", 404)
            self._task(db, row["task_id"], principal)
            execution_id = row["id"]
        return self.execution(execution_id, principal)

    def execution(self, execution_id, principal):
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT e.* FROM executions e JOIN tasks t ON t.id=e.task_id WHERE e.id=? AND t.tenant=?",
                (execution_id, principal.tenant),
            ).fetchone()
            if not row:
                raise ShieldError("NOT_FOUND", 404)
            self._task(db, row["task_id"], principal)
            return (
                json.loads(row["result"])
                if row["result"]
                else {"execution_id": execution_id, "state": row["state"]}
            )

    def recover(self):
        """Call only during exclusive process startup, never while another executor is live."""
        with self.store.transaction() as db:
            for row in db.execute(
                "SELECT e.*,t.tenant FROM executions e JOIN tasks t ON t.id=e.task_id WHERE e.state='executing'"
            ).fetchall():
                db.execute("UPDATE executions SET state='outcome_unknown' WHERE id=?", (row["id"],))
                db.execute("UPDATE tasks SET active=MAX(0,active-1) WHERE id=?", (row["task_id"],))
                self.store.event(
                    db,
                    row["tenant"],
                    row["task_id"],
                    "execution_result",
                    {"execution_id": row["id"], "state": "outcome_unknown", "reason": "process_recovery"},
                )

    def cancel(self, task_id, principal):
        if principal.role not in {"requester", "admin", "approver"}:
            raise ShieldError("ROLE_FORBIDDEN", 403)
        with self.store.transaction() as db:
            row, task = self._task(db, task_id, principal)
            if principal.role == "requester" and principal.requester != task.requester:
                raise ShieldError("IDENTITY_MISMATCH", 403)
            db.execute("UPDATE tasks SET status='canceled' WHERE id=?", (task_id,))
            db.execute(
                "UPDATE approvals SET status='canceled' WHERE task_id=? AND status='pending'", (task_id,)
            )
            self.store.event(
                db,
                task.tenant,
                task_id,
                "task_canceled",
                {"actor": principal.subject, "in_flight": row["active"]},
            )
            return {"status": "canceled", "new_actions": "blocked", "in_flight": row["active"]}

    def overview(self, principal):
        with self.store.transaction() as db:
            tasks = []
            for row in db.execute(
                "SELECT * FROM tasks WHERE tenant=? ORDER BY rowid DESC LIMIT 100", (principal.tenant,)
            ):
                task = json.loads(row["contract"])
                if not set(task["resources"]).issubset(principal.resources):
                    continue
                repo = json.loads(
                    db.execute("SELECT state FROM repos WHERE task_id=?", (row["id"],)).fetchone()[0]
                )
                actions = []
                for d in db.execute("SELECT * FROM decisions WHERE task_id=? ORDER BY rowid", (row["id"],)):
                    response, action = json.loads(d["response"]), json.loads(d["action"])
                    execution = db.execute(
                        "SELECT e.result FROM executions e LEFT JOIN grants g ON g.id=e.decision_id "
                        "WHERE e.decision_id=? OR json_extract(g.response,'$.parent_decision_id')=? "
                        "ORDER BY e.rowid DESC LIMIT 1",
                        (d["id"], d["id"]),
                    ).fetchone()
                    actions.append(
                        {
                            "action": action,
                            "decision": response,
                            "state": d["state"],
                            "execution": json.loads(execution[0]) if execution and execution[0] else None,
                        }
                    )
                tasks.append(
                    {
                        "contract": task,
                        "status": row["status"],
                        "calls": row["calls"],
                        "bytes": row["bytes"],
                        "actions": actions,
                        "pull_requests": len(repo["prs"]),
                        "comments": len(repo["comments"]),
                        "provider": repo.get("provider", "mock"),
                        "pull_request_links": [p.get("url") for p in repo["prs"] if p.get("url")],
                    }
                )
            approvals = [
                dict(r)
                for r in db.execute(
                    "SELECT a.* FROM approvals a JOIN tasks t ON t.id=a.task_id WHERE t.tenant=? ORDER BY a.rowid DESC",
                    (principal.tenant,),
                )
                if any(t["contract"]["task_id"] == r["task_id"] for t in tasks)
            ]
        return {
            "tasks": tasks,
            "approvals": approvals,
            "analysis": self.analyzer.versions,
            "github_integration": self.github.status() if self.github else {"configured": False},
            "coverage": {
                "github": "configured; mediated API only" if self.github else "mock only",
                "sandbox": "not implemented",
                "egress": "not implemented",
                "credential_broker": "in-process; not isolated" if self.github else "not configured",
                "live_ai_evaluated": False,
            },
        }
