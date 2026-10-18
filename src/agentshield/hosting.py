"""Fail-closed configuration checks for the single-instance hosted pilot."""

import os
from pathlib import Path

ROLES = ("developer", "worker", "reviewer", "operator")


def hosted():
    return os.getenv("RENDER") == "true" or os.getenv("AGENTSHIELD_ENV") == "hosted"


def hosted_tokens(data, github, database_url=None):
    if not hosted():
        return None
    if not data.is_absolute():
        raise ValueError("Hosted AGENTSHIELD_DATA_DIR must be absolute")
    if os.getenv("RENDER") == "true" and not database_url:
        raise ValueError("Render requires a persistent PostgreSQL DATABASE_URL; local files are ephemeral")
    if database_url:
        from .postgres import validate_url

        validate_url(database_url, require_tls=True)
    tokens = {role: os.getenv(f"AGENTSHIELD_{role.upper()}_TOKEN", "") for role in ROLES}
    if any(len(token) < 32 or len(token.encode("utf-8")) != len(token) for token in tokens.values()):
        raise ValueError("Hosted role tokens must each contain at least 32 ASCII characters")
    if len(set(tokens.values())) != len(ROLES):
        raise ValueError("Hosted role tokens must be distinct")
    if github:
        s = github.settings
        if s.auth_mode != "app":
            raise ValueError("Hosted GitHub access requires App authentication; CLI auth is local only")
        if not s.app_id or not s.installation_id.isdigit() or not s.private_key_path:
            raise ValueError("Hosted GitHub App configuration is incomplete")
        if not Path(s.private_key_path).is_file():
            raise ValueError("GitHub App secret file is missing")
    return tokens
