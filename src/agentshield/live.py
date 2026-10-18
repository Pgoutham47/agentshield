"""Durable execution boundary for real GitHub calls; never hold SQLite over network I/O."""

import json

from . import policy
from .github import MAX_WIRE_BYTES, GitHubError, resource_version
from .models import Decision, canonical, digest, now, uid


class LiveExecution:
    def prepare(self, action, principal):
        from .engine import ShieldError

        with self.store.transaction() as db:
            row, task = self._task(db, action.task_id, principal, act=True)
            denial = policy.deterministic(task, action, row["status"])
            if denial:
                raise ShieldError(denial, 403)
            repo = json.loads(
                db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
            )
            if task.provider != "github" or not self.github:
                raise ShieldError("GITHUB_TASK_REQUIRED", 400)
            try:
                version = resource_version(repo, action)
            except GitHubError as error:
                raise ShieldError(error.code, 409) from None
            prepared = action.model_copy(update={"expected_resource_version": version})
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "action_prepared",
                {"action_id": action.action_id, "action_digest": digest(prepared)},
            )
            return prepared

    def _execute_github(self, decision_id, action, principal):
        from .engine import ShieldError

        if not self.github:
            raise ShieldError("GITHUB_NOT_CONFIGURED", 503)
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
            if row["active"] >= task.budget.max_concurrency:
                raise ShieldError("CONCURRENCY_EXCEEDED", 429)
            if row["bytes"] + MAX_WIRE_BYTES > task.budget.max_bytes:
                raise ShieldError("RESPONSE_BYTE_BUDGET_EXCEEDED", 429)
            repo = json.loads(
                db.execute("SELECT state FROM repos WHERE task_id=?", (task.task_id,)).fetchone()[0]
            )
            try:
                if resource_version(repo, action) != action.expected_resource_version:
                    raise ShieldError("RESOURCE_VERSION_CHANGED")
            except GitHubError as error:
                raise ShieldError(error.code) from None
            if db.execute(
                "SELECT 1 FROM github_inflight WHERE repository=?", (repo["repository"].lower(),)
            ).fetchone():
                raise ShieldError("GITHUB_BUSY_OR_RECONCILIATION_REQUIRED")
            execution_id = uid("ex")
            db.execute(f"UPDATE {table} SET state='consumed' WHERE id=?", (decision_id,))
            db.execute(
                "UPDATE tasks SET active=active+1,bytes=bytes+? WHERE id=?", (MAX_WIRE_BYTES, task.task_id)
            )
            db.execute(
                "INSERT INTO executions VALUES(?,?,?,?,NULL)",
                (execution_id, decision_id, task.task_id, "executing"),
            )
            db.execute("INSERT INTO github_inflight VALUES(?,?)", (repo["repository"].lower(), execution_id))
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "execution_started",
                {
                    "execution_id": execution_id,
                    "decision_id": decision_id,
                    "operation": action.operation,
                    "provider": "github",
                },
            )

        def guard():
            with self.store.transaction() as db:
                row, current = self._task(db, task.task_id, principal, act=True)
                denial = policy.deterministic(current, action, row["status"])
                if denial or decision.expires_at <= now():
                    raise ShieldError(denial or "AUTHORIZATION_EXPIRED", 403)
                if not self.github.settings.enable_writes:
                    raise ShieldError("GITHUB_WRITES_DISABLED", 403)

        state, result, ids = "succeeded", None, []
        updated = repo
        try:
            updated, result, ids, _ = self.github.execute(repo, action, guard)
        except GitHubError as error:
            state = "outcome_unknown" if error.unknown else "failed"
            result = {"error": error.code, "retry_safe": False}
            ids = [error.request_id] if error.request_id else []
        except Exception:
            # Once execution intent exists, unexpected adapter failure is conservatively unknown.
            state, result = "outcome_unknown", {"error": "GITHUB_UNEXPECTED_FAILURE", "retry_safe": False}
        response = {
            "execution_id": execution_id,
            "state": state,
            "result": result,
            "provider_request_id": ids[-1] if ids else None,
            "provider_request_ids": ids,
            "adapter_version": self.github.version,
        }
        # If durable finalization fails, retain the consumed grant and repository lock for recovery.
        with self.store.transaction() as db:
            if state == "succeeded":
                db.execute("UPDATE repos SET state=? WHERE task_id=?", (canonical(updated), task.task_id))
            db.execute(
                "UPDATE executions SET state=?,result=? WHERE id=?",
                (state, canonical(response), execution_id),
            )
            db.execute("UPDATE tasks SET active=active-1 WHERE id=?", (task.task_id,))
            if state != "outcome_unknown":
                db.execute("DELETE FROM github_inflight WHERE execution_id=?", (execution_id,))
            self.store.event(
                db,
                task.tenant,
                task.task_id,
                "execution_result",
                {
                    "execution_id": execution_id,
                    "state": state,
                    "provider_request_ids": ids,
                    "provider": "github",
                },
            )
        return response
