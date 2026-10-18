"""Offline, atomic SQLite-to-PostgreSQL import; preserves exact audit hashes and consumed grants."""

import json
import sqlite3
from pathlib import Path

from .models import digest
from .postgres import PostgresStore

TABLES = ("tasks", "decisions", "grants", "approvals", "executions", "repos", "github_inflight", "events")
ORDERED = {"tasks", "decisions", "approvals", "executions"}


def import_sqlite(source, destination, *, source_stopped=False):
    if not source_stopped:
        raise ValueError("Stop the source server and explicitly confirm --source-stopped")
    source = Path(source).resolve(strict=True)
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        if db.execute("SELECT 1 FROM executions WHERE state='executing' LIMIT 1").fetchone():
            raise ValueError("Source has interrupted executions; recover them before importing")
        snapshot = {}
        for table in TABLES:
            selector = "rowid AS rowid,*" if table in ORDERED else "*"
            ordering = "seq" if table == "events" else "rowid"
            snapshot[table] = [
                dict(r) for r in db.execute(f"SELECT {selector} FROM {table} ORDER BY {ordering}")
            ]
    previous = "genesis"
    for i, row in enumerate(snapshot["events"], 1):
        event = json.loads(row["event"])
        stored_hash = event.pop("hash")
        if (
            row["seq"] != i
            or event["sequence"] != i
            or event["previous_hash"] != previous
            or digest(event) != stored_hash
        ):
            raise ValueError("Source audit chain is invalid; import aborted")
        previous = stored_hash
    target = PostgresStore(destination)
    with target.transaction() as db:
        if any(db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() for table in TABLES):
            raise ValueError("Destination must be empty; existing records are never overwritten")
        for table, records in snapshot.items():
            for record in records:
                # Column names come from the fixed local database schema, never from API input.
                from psycopg import sql

                columns = list(record)
                query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(table),
                    sql.SQL(",").join(map(sql.Identifier, columns)),
                    sql.SQL(",").join(sql.Placeholder() for _ in columns),
                )
                db.raw.execute(query, list(record.values()))
            if table in ORDERED:
                db.raw.execute(
                    f"SELECT setval(pg_get_serial_sequence('{table}','rowid'), COALESCE(MAX(rowid),1), MAX(rowid) IS NOT NULL) FROM {table}"
                )
    return {
        "backend": "postgresql",
        "counts": {t: len(r) for t, r in snapshot.items()},
        "audit_valid": target.verify(),
    }
