import asyncio
import json
import os
import subprocess
import sys

import psycopg
import pytest
from fastapi.testclient import TestClient

from agentshield.api import create_app
from agentshield.demo import DEVELOPER, REVIEWER, WORKER, envelope, run_demo, task_contract
from agentshield.engine import Engine, ShieldError
from agentshield.migrate import import_sqlite
from agentshield.postgres import PostgresStore, StorageError, validate_url


def test_postgres_rollback_preserves_audit_sequence(postgres_location):
    store = PostgresStore(postgres_location)
    with pytest.raises(RuntimeError):
        with store.transaction() as db:
            store.event(db, "acme", "t", "rolled_back", {})
            raise RuntimeError("abort")
    with store.transaction() as db:
        store.event(db, "acme", "t", "committed", {})
    assert store.events("acme")[0]["sequence"] == 1
    assert store.verify()
    with pytest.raises(StorageError):
        with store.transaction() as db:
            db.execute("TRUNCATE events")
    assert store.verify()


def test_private_schema_rls_and_no_public_privileges(postgres_location):
    store = PostgresStore(postgres_location)
    with store.transaction() as db:
        tables = db.execute(
            "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=? AND c.relkind=?",
            (store.schema, "r"),
        ).fetchall()
        assert tables and all(r[0] for r in tables)
        grants = db.execute(
            "SELECT count(*) FROM information_schema.table_privileges WHERE table_schema=? AND grantee IN ('PUBLIC','anon','authenticated')",
            (store.schema,),
        ).fetchone()[0]
        assert grants == 0


def test_import_preserves_history_pending_approval_and_one_use(postgres_location, tmp_path):
    source = tmp_path / "source.sqlite"
    engine = Engine(source)
    report = asyncio.run(run_demo(engine, "C", reject=False))
    before = engine.overview(REVIEWER)
    result = import_sqlite(source, postgres_location, source_stopped=True)
    target = Engine(postgres_location)
    assert result["audit_valid"] and target.store.verify()
    assert target.overview(REVIEWER)["tasks"][0]["contract"] == before["tasks"][0]["contract"]
    assert target.overview(REVIEWER)["approvals"][0]["status"] == "pending"
    assert target.store.events("acme") == engine.store.events("acme")
    a = report["trace"][0]
    from agentshield.models import Action

    with source.open("rb") as f:
        original = f.read()
    with pytest.raises(ValueError, match="empty"):
        import_sqlite(source, postgres_location, source_stopped=True)
    assert source.read_bytes() == original
    with engine.store.transaction() as db:
        raw = db.execute(
            "SELECT action FROM decisions WHERE id=?", (a["decision"]["decision_id"],)
        ).fetchone()[0]
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        target.execute(a["decision"]["decision_id"], Action.model_validate_json(raw), WORKER)
    asyncio.run(run_demo(target, "A"))
    assert target.store.verify()


def test_import_requires_stopped_source(postgres_location, tmp_path):
    with pytest.raises(ValueError, match="source-stopped"):
        import_sqlite(tmp_path / "missing", postgres_location)


def test_other_process_execution_is_not_recovered_until_owner_dies(postgres_location):
    engine = Engine(postgres_location)
    task = engine.create_task(task_contract(), DEVELOPER)
    action = envelope(engine, task, "read_issue", {"issue_number": 412})
    decision = asyncio.run(engine.decide(action, WORKER))
    env = os.environ.copy()
    env["TEST_PAYLOAD"] = json.dumps([postgres_location, decision.decision_id, task.task_id])
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import json, os, sys
from agentshield.postgres import PostgresStore
url, grant, task = json.loads(os.environ['TEST_PAYLOAD'])
s = PostgresStore(url)
with s.execution_lock(grant):
    with s.transaction() as db:
        db.execute("UPDATE decisions SET state='consumed' WHERE id=?", (grant,))
        db.execute("UPDATE tasks SET active=active+1 WHERE id=?", (task,))
        db.execute("INSERT INTO executions(id,decision_id,task_id,state,result) VALUES(?,?,?,'executing',NULL)", ('ex_process',grant,task))
    print('READY', flush=True)
    sys.stdin.readline()
""",
        ],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "READY"
        engine.recover()
        assert engine.execution("ex_process", WORKER)["state"] == "executing"
    finally:
        child.kill()
        child.wait(timeout=10)
    engine.recover()
    assert engine.execution("ex_process", WORKER)["state"] == "outcome_unknown"
    with pytest.raises(ShieldError, match="AUTHORIZATION_NOT_USABLE"):
        engine.execute(decision.decision_id, action, WORKER)
    assert engine.store.verify()


def test_lost_execution_session_fails_closed(postgres_location):
    store = PostgresStore(postgres_location)
    with store.execution_lock("test-grant"):
        connection = store._execution.get()
        pid = connection.execute("SELECT pg_backend_pid()").fetchone()[0]
        with psycopg.connect(postgres_location, autocommit=True) as control:
            control.execute("SELECT pg_terminate_backend(%s)", (pid,))
        with pytest.raises(StorageError):
            with store.transaction():
                pytest.fail("Must not enter a transaction after losing execution ownership")


def test_hosted_api_with_postgres_survives_restart(postgres_location, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_ENV", "hosted")
    monkeypatch.setenv("AGENTSHIELD_DATA_DIR", str(tmp_path))
    # Local test server has no TLS; use explicit db_path while hosted token checks remain enabled.
    for role in ("DEVELOPER", "WORKER", "REVIEWER", "OPERATOR"):
        monkeypatch.setenv("AGENTSHIELD_" + role + "_TOKEN", role + "x" * 40)
    headers = {"Authorization": "Bearer OPERATOR" + "x" * 40}
    with TestClient(create_app(db_path=postgres_location)) as client:
        assert client.get("/health").json()["storage"] == "postgresql"
        assert client.get("/v1/overview").status_code == 401
        task = client.post("/v1/demo", headers=headers, json={"scenario": "A"}).json()["task_id"]
    with TestClient(create_app(db_path=postgres_location)) as client:
        tasks = client.get("/v1/overview", headers=headers).json()["tasks"]
        assert any(t["contract"]["task_id"] == task for t in tasks)
        assert client.get("/v1/events/export", headers=headers).status_code == 200
    assert not (tmp_path / "local-tokens.json").exists()


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "postgresql://user:SECRET@host:6543/postgres?sslmode=require",
        "postgresql://user:SECRET@host/postgres",
    ],
)
def test_invalid_hosted_connection_does_not_expose_secret(url):
    with pytest.raises(ValueError) as error:
        validate_url(url, require_tls=True)
    assert "SECRET" not in str(error.value)


def test_connection_error_is_redacted():
    with pytest.raises(StorageError) as error:
        PostgresStore("postgresql://user:SECRET@127.0.0.1:1/postgres")
    assert str(error.value) == "DATABASE_UNAVAILABLE"
