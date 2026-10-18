"""PostgreSQL store for Supabase. Small, serialized transactions retain the pilot's invariants.

A dedicated session lock covers each execution across network I/O. Recovery can
claim only executions whose session lock is gone. Requires direct/session pooling.
"""

import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import sha256
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

from .store import Store


class StorageError(Exception):
    """Stable error codes only; connection strings and SQL values never leave the store."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Row(dict):
    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def rows(cursor):
    names = [col.name for col in cursor.description] if cursor.description else []
    return lambda values: Row(zip(names, values))


class Connection:
    def __init__(self, connection):
        self.raw = connection

    def execute(self, statement, parameters=()):
        # Only internal constant SQL reaches here; all untrusted values remain bound parameters.
        statement = re.sub(r"json_extract\(([\w.]+),'\$\.([\w]+)'\)", r"(\1::jsonb ->> '\2')", statement)
        return self.raw.execute(statement.replace("?", "%s"), parameters)


def validate_url(url, require_tls=False):
    if not str(url).startswith(("postgres://", "postgresql://")):
        raise ValueError("DATABASE_URL must be a PostgreSQL connection URI")
    try:
        parts = conninfo_to_dict(url)
    except psycopg.Error:
        raise ValueError("DATABASE_URL is invalid") from None
    if parts.get("port") == "6543":
        raise ValueError("Use Supabase session pooler port 5432, not transaction pooler 6543")
    if require_tls and parts.get("sslmode") not in {"require", "verify-ca", "verify-full"}:
        raise ValueError("Hosted DATABASE_URL requires sslmode=require or certificate verification")
    return parts


class PostgresStore(Store):
    backend = "postgresql"

    def __init__(self, url, schema=None):
        validate_url(url)
        self._url = str(url)
        self.path = self._url  # Internal compatibility with restart tests; never included in API responses.
        self.schema = schema or os.getenv("AGENTSHIELD_DB_SCHEMA", "agentshield")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", self.schema) or self.schema in {
            "public",
            "pg_catalog",
            "information_schema",
        }:
            raise ValueError("Use a private AGENTSHIELD_DB_SCHEMA identifier")
        self._execution = ContextVar("execution_connection", default=None)
        self._migrate()

    def _key(self, name):
        return int.from_bytes(sha256(f"{self.schema}:{name}".encode()).digest()[:8], "big", signed=True)

    def _connect(self):
        try:
            return psycopg.connect(
                self._url,
                connect_timeout=10,
                autocommit=True,
                prepare_threshold=None,
                row_factory=rows,
                application_name="agentshield",
            )
        except psycopg.Error:
            raise StorageError("DATABASE_UNAVAILABLE") from None

    def _migrate(self):
        try:
            with self._connect() as conn, conn.transaction():
                conn.execute("SET LOCAL lock_timeout='15s'")
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._key("transactions"),))
                conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(self.schema)))
                conn.execute(
                    sql.SQL("SET LOCAL search_path TO {},pg_catalog").format(sql.Identifier(self.schema))
                )
                conn.execute("CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY)")
                versions = [r[0] for r in conn.execute("SELECT version FROM schema_versions")]
                if any(v not in {1, 2} for v in versions):
                    raise StorageError("DATABASE_SCHEMA_VERSION_UNSUPPORTED")
                if 1 not in versions:
                    conn.execute((Path(__file__).parent / "migrations/001_postgres.sql").read_text())
                if 2 not in versions:
                    conn.execute((Path(__file__).parent / "migrations/002_auth.sql").read_text())
                tables = [
                    "auth_sessions",
                    "schema_versions",
                    "tasks",
                    "decisions",
                    "grants",
                    "approvals",
                    "executions",
                    "repos",
                    "github_inflight",
                    "events",
                ]
                for table in tables:
                    conn.execute(
                        sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(table))
                    )
                # No anon/browser policies: the backend role owns the schema; credentials stay server-side.
                roles = ["PUBLIC"] + [
                    r[0]
                    for r in conn.execute(
                        "SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated')"
                    )
                ]
                for role in roles:
                    grantee = sql.SQL("PUBLIC") if role == "PUBLIC" else sql.Identifier(role)
                    conn.execute(
                        sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(
                            sql.Identifier(self.schema), grantee
                        )
                    )
                    conn.execute(
                        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}").format(
                            sql.Identifier(self.schema), grantee
                        )
                    )
                    conn.execute(
                        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}").format(
                            sql.Identifier(self.schema), grantee
                        )
                    )
                    conn.execute(
                        sql.SQL("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {} FROM {}").format(
                            sql.Identifier(self.schema), grantee
                        )
                    )
        except psycopg.Error:
            raise StorageError("DATABASE_MIGRATION_FAILED") from None

    @contextmanager
    def transaction(self):
        try:
            owner = self._execution.get()
            if owner:
                owner.execute("SELECT 1")  # Fails closed if the execution's locking session was lost.
            with self._connect() as conn, conn.transaction():
                conn.execute("SET LOCAL lock_timeout='15s'")
                conn.execute("SET LOCAL statement_timeout='20s'")
                conn.execute(
                    sql.SQL("SET LOCAL search_path TO {},pg_catalog").format(sql.Identifier(self.schema))
                )
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._key("transactions"),))
                yield Connection(conn)
        except psycopg.Error:
            raise StorageError("DATABASE_TRANSACTION_FAILED") from None

    @contextmanager
    def execution_lock(self, decision_id, wait=False):
        try:
            with self._connect() as conn:
                if wait:
                    conn.execute("SET lock_timeout='15s'")
                    conn.execute("SELECT pg_advisory_lock(%s)", (self._key("execute:" + decision_id),))
                elif not conn.execute(
                    "SELECT pg_try_advisory_lock(%s)", (self._key("execute:" + decision_id),)
                ).fetchone()[0]:
                    raise StorageError("EXECUTION_ALREADY_RUNNING")
                marker = self._execution.set(conn)
                try:
                    yield
                finally:
                    self._execution.reset(marker)
                    try:
                        conn.execute("SELECT pg_advisory_unlock(%s)", (self._key("execute:" + decision_id),))
                    except psycopg.Error:
                        pass  # A lost session cannot be reused; recovery will resolve its durable intent.
        except psycopg.Error:
            raise StorageError("EXECUTION_LOCK_LOST") from None

    def recoverable(self, db, decision_id):
        return db.execute(
            "SELECT pg_try_advisory_xact_lock(?)", (self._key("execute:" + decision_id),)
        ).fetchone()[0]
