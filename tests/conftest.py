"""Run critical store-independent contracts on both backends when PostgreSQL is available."""

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql


@pytest.fixture(params=["sqlite", "postgresql"])
def database_location(request, tmp_path):
    if request.param == "sqlite":
        return tmp_path / "database.sqlite"
    return request.getfixturevalue("postgres_location")


@pytest.fixture
def postgres_location(monkeypatch):
    url = os.getenv("AGENTSHIELD_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set AGENTSHIELD_TEST_DATABASE_URL to test a real PostgreSQL server")
    schema = "test_" + uuid4().hex
    monkeypatch.setenv("AGENTSHIELD_DB_SCHEMA", schema)
    try:
        yield url
    finally:
        with psycopg.connect(url, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
