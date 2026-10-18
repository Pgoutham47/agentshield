"""SQLite is the prototype's transactional source of truth, including the audit outbox."""

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from pathlib import Path

from .models import canonical, digest, now, uid


class Store:
    backend = "sqlite"

    def execution_lock(self, decision_id):
        return nullcontext()

    def recoverable(self, db, decision_id):
        return True

    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS tasks (
              id TEXT PRIMARY KEY, tenant TEXT NOT NULL, idem TEXT NOT NULL,
              contract TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
              calls INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
              active INTEGER NOT NULL DEFAULT 0, UNIQUE(tenant, idem));
            CREATE TABLE IF NOT EXISTS decisions (
              id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
              action_id TEXT NOT NULL, idem TEXT NOT NULL, action TEXT NOT NULL,
              response TEXT NOT NULL, state TEXT NOT NULL, UNIQUE(task_id, action_id), UNIQUE(task_id, idem));
            CREATE TABLE IF NOT EXISTS grants (
              id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
              action TEXT NOT NULL, response TEXT NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approvals (
              id TEXT PRIMARY KEY, decision_id TEXT NOT NULL REFERENCES decisions(id),
              task_id TEXT NOT NULL, status TEXT NOT NULL, resolution TEXT);
            CREATE TABLE IF NOT EXISTS executions (
              id TEXT PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL,
              task_id TEXT NOT NULL, state TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS repos (
              task_id TEXT PRIMARY KEY REFERENCES tasks(id), state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS github_inflight (
              repository TEXT PRIMARY KEY, execution_id TEXT NOT NULL REFERENCES executions(id));
            CREATE TABLE IF NOT EXISTS events (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
              BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
              BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
            """)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def event(db, tenant, task_id, kind, metadata):
        last = db.execute("SELECT seq,event FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        event = {
            "event_id": uid("ev"),
            "sequence": last["seq"] + 1 if last else 1,
            "tenant": tenant,
            "task_id": task_id,
            "event_type": kind,
            "timestamp": now().isoformat(),
            "metadata": metadata,
            "previous_hash": json.loads(last["event"])["hash"] if last else "genesis",
        }
        event["hash"] = digest(event)
        db.execute("INSERT INTO events(seq,event) VALUES (?,?)", (event["sequence"], canonical(event)))

    def events(self, tenant, after=0, limit=1000):
        with self.transaction() as db:
            rows = db.execute(
                "SELECT event FROM events WHERE seq>? AND json_extract(event,'$.tenant')=? ORDER BY seq LIMIT ?",
                (after, tenant, limit),
            )
            return [json.loads(r[0]) for r in rows]

    def export(self, tenant, path):
        """Export a consistent JSONL snapshot; the database outbox is never truncated."""
        with self.transaction() as db:
            rows = db.execute(
                "SELECT event FROM events WHERE json_extract(event,'$.tenant')=? ORDER BY seq", (tenant,)
            )
            data = "".join(row[0] + "\n" for row in rows)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(data)

    def verify(self):
        with self.transaction() as db:
            previous = "genesis"
            for sequence, row in enumerate(db.execute("SELECT event FROM events ORDER BY seq"), 1):
                event = json.loads(row[0])
                stored_hash = event.pop("hash")
                if (
                    event["sequence"] != sequence
                    or event["previous_hash"] != previous
                    or digest(event) != stored_hash
                ):
                    return False
                previous = stored_hash
        return True


def open_store(location):
    if str(location).startswith(("postgres://", "postgresql://")):
        from .postgres import PostgresStore

        return PostgresStore(location)
    return Store(location)
