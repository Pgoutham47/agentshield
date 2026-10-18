"""User-owned GitHub App connections. User tokens preserve the user/App permission intersection."""

import base64
import hashlib
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from fastapi import Depends, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import Field

from .engine import ShieldError
from .github import GitHubAdapter, GitHubError, GitHubSettings, bounded_request
from .models import Strict, uid

_LOCKS = [threading.RLock() for _ in range(32)]
PAGE_SIZE = 20


@dataclass(frozen=True)
class ConnectionSettings:
    client_id: str
    client_secret: str
    app_id: str
    slug: str
    enable_writes: bool = False

    def __post_init__(self):
        if (
            not self.client_id
            or not self.client_secret
            or not self.app_id.isdecimal()
            or not re.fullmatch(r"[a-z0-9-]+", self.slug)
        ):
            raise ValueError("GitHub connection settings are incomplete")

    @classmethod
    def from_env(cls):
        values = [
            os.getenv(k, "") for k in ("GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET", "GITHUB_APP_SLUG")
        ]
        return (
            cls(
                values[0],
                values[1],
                os.getenv("GITHUB_APP_ID", ""),
                values[2],
                os.getenv("GITHUB_ENABLE_WRITES", "").lower() == "true",
            )
            if any(values)
            else None
        )


class RepositorySelection(Strict):
    installation_id: int = Field(gt=0)
    repository_id: int = Field(gt=0)
    installation_page: int = Field(default=1, ge=1, le=100)
    repository_page: int = Field(default=1, ge=1, le=100)


class Connections:
    def __init__(self, auth, settings, transport=None):
        self.auth, self.store, self.settings, self.transport = auth, auth.store, settings, transport

    @property
    def callback_url(self):
        return self.auth.settings.base_url.rstrip("/") + "/github/callback"

    @property
    def install_url(self):
        return "https://github.com/apps/" + self.settings.slug + "/installations/new"

    def api(self, path, token):
        with httpx.Client(
            base_url="https://api.github.com",
            timeout=15,
            trust_env=False,
            follow_redirects=False,
            transport=self.transport,
        ) as client:
            return bounded_request(client, "GET", path, token=token)[0]

    def exchange(self, body):
        body = {**body, "client_id": self.settings.client_id, "client_secret": self.settings.client_secret}
        try:
            with httpx.Client(
                timeout=15, trust_env=False, follow_redirects=False, transport=self.transport
            ) as client:
                response = client.post(
                    "https://github.com/login/oauth/access_token",
                    json=body,
                    headers={"Accept": "application/json"},
                )
            if response.status_code != 200 or len(response.content) > 16000:
                raise GitHubError("GITHUB_AUTHORIZATION_FAILED")
            data = response.json()
            if not isinstance(data.get("access_token"), str) or not data["access_token"]:
                raise GitHubError("GITHUB_REAUTHORIZE_REQUIRED")
            return {
                "access": data["access_token"],
                "refresh": data.get("refresh_token"),
                "expires": time.time() + int(data.get("expires_in", 8 * 3600)),
            }
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            raise GitHubError("GITHUB_AUTHORIZATION_FAILED") from None

    def start(self, request, principal, profile):
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with self.store.transaction() as db:
            db.execute(
                "DELETE FROM github_flows WHERE expires_at<? OR subject=?", (time.time(), principal.subject)
            )
            db.execute(
                "INSERT INTO github_flows(id,session_id,subject,tenant,github_id,verifier,expires_at) VALUES (?,?,?,?,?,?,?)",
                (
                    hashlib.sha256(state.encode()).hexdigest(),
                    self.auth.session_id(request),
                    principal.subject,
                    principal.tenant,
                    profile["github_id"],
                    self.auth.seal(verifier),
                    time.time() + 600,
                ),
            )
        return {
            "url": "https://github.com/login/oauth/authorize?"
            + urlencode(
                {
                    "client_id": self.settings.client_id,
                    "redirect_uri": self.callback_url,
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        }

    def callback(self, request, principal, profile):
        state = request.query_params.get("state", "")
        if not state or len(state) > 128:
            raise ShieldError("GITHUB_CONNECTION_STATE_INVALID", 400)
        key = hashlib.sha256(state.encode()).hexdigest()
        with self.store.transaction() as db:
            flow = db.execute("SELECT * FROM github_flows WHERE id=?", (key,)).fetchone()
            if (
                not flow
                or flow["consumed"]
                or flow["expires_at"] < time.time()
                or flow["session_id"] != self.auth.session_id(request)
                or flow["subject"] != principal.subject
                or flow["tenant"] != principal.tenant
                or flow["github_id"] != profile["github_id"]
            ):
                raise ShieldError("GITHUB_CONNECTION_STATE_INVALID", 400)
            db.execute("UPDATE github_flows SET consumed=1 WHERE id=?", (key,))
        code = request.query_params.get("code", "")
        if not code or len(code) > 4096:
            raise ShieldError("GITHUB_AUTHORIZATION_FAILED", 400)
        tokens = self.exchange(
            {
                "code": code,
                "code_verifier": self.auth.unseal(flow["verifier"]),
                "redirect_uri": self.callback_url,
            }
        )
        identity = self.api("/user", tokens["access"])
        if str(identity.get("id")) != profile["github_id"]:
            raise ShieldError("GITHUB_ACCOUNT_MISMATCH", 403)
        # Serialize replacement against refresh; a new login never widens selected repositories.
        with self.lock(principal.tenant):
            with self.store.transaction() as db:
                if not db.execute(
                    "SELECT id FROM auth_sessions WHERE id=? AND expires_at>?",
                    (flow["session_id"], time.time()),
                ).fetchone():
                    raise ShieldError("AUTHENTICATION_REQUIRED", 401)
                if not db.execute("SELECT id FROM github_flows WHERE id=? AND consumed=1", (key,)).fetchone():
                    raise ShieldError("GITHUB_CONNECTION_CANCELED", 403)
                db.execute("DELETE FROM github_flows WHERE id=?", (key,))
                db.execute(
                    "INSERT INTO github_accounts(tenant,subject,github_id,tokens) VALUES (?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET subject=excluded.subject,github_id=excluded.github_id,tokens=excluded.tokens",
                    (principal.tenant, principal.subject, profile["github_id"], self.auth.seal(tokens)),
                )

    def lock(self, tenant):
        from contextlib import contextmanager

        @contextmanager
        def locked():
            key = hashlib.sha256(tenant.encode()).hexdigest()
            with (
                _LOCKS[int(key[:2], 16) % len(_LOCKS)],
                self.store.execution_lock("github-account:" + key, wait=True),
            ):
                yield

        return locked()

    def token(self, tenant):
        with self.lock(tenant):
            with self.store.transaction() as db:
                account = db.execute("SELECT * FROM github_accounts WHERE tenant=?", (tenant,)).fetchone()
            if not account:
                raise GitHubError("GITHUB_REAUTHORIZE_REQUIRED")
            tokens = self.auth.unseal(account["tokens"])
            if tokens["expires"] < time.time() + 60:
                if not tokens.get("refresh"):
                    raise GitHubError("GITHUB_REAUTHORIZE_REQUIRED")
                tokens = self.exchange({"grant_type": "refresh_token", "refresh_token": tokens["refresh"]})
                if str(self.api("/user", tokens["access"]).get("id")) != account["github_id"]:
                    raise GitHubError("GITHUB_ACCOUNT_MISMATCH")
                with self.store.transaction() as db:
                    # Disconnect may have removed this account during provider I/O.
                    row = db.execute(
                        "SELECT tokens FROM github_accounts WHERE tenant=?", (tenant,)
                    ).fetchone()
                    if not row or row["tokens"] != account["tokens"]:
                        raise GitHubError("GITHUB_REAUTHORIZE_REQUIRED")
                    db.execute(
                        "UPDATE github_accounts SET tokens=? WHERE tenant=?", (self.auth.seal(tokens), tenant)
                    )
            return tokens["access"]

    def installations(self, principal, page=1):
        data = self.api(f"/user/installations?per_page={PAGE_SIZE}&page={page}", self.token(principal.tenant))
        items = data.get("installations", [])
        result = [
            {
                "id": i["id"],
                "account": i["account"]["login"],
                "account_type": i["account"]["type"],
                "suspended": bool(i.get("suspended_at")),
            }
            for i in items
            if str(i.get("app_id")) == self.settings.app_id
        ]
        return {
            "installations": result,
            "page": page,
            "has_more": page * PAGE_SIZE < data.get("total_count", 0),
        }

    def repositories(self, principal, installation_id, page=1, installation_page=1):
        available = self.installations(principal, installation_page)["installations"]
        match = next((i for i in available if i["id"] == installation_id), None)
        if not match or match["suspended"]:
            raise ShieldError("GITHUB_INSTALLATION_FORBIDDEN", 403)
        data = self.api(
            f"/user/installations/{installation_id}/repositories?per_page={PAGE_SIZE}&page={page}",
            self.token(principal.tenant),
        )
        repos = [
            {"id": r["id"], "name": r["full_name"], "private": bool(r["private"])}
            for r in data.get("repositories", [])
        ]
        return {
            "repositories": repos,
            "page": page,
            "has_more": page * PAGE_SIZE < data.get("total_count", 0),
        }

    def select(self, principal, body):
        repos = self.repositories(
            principal, body.installation_id, body.repository_page, body.installation_page
        )["repositories"]
        selected = next((r for r in repos if r["id"] == body.repository_id), None)
        if not selected:
            raise ShieldError("GITHUB_REPOSITORY_FORBIDDEN", 403)
        name = GitHubSettings(selected["name"]).repository
        with self.store.transaction() as db:
            account = db.execute(
                "SELECT subject FROM github_accounts WHERE tenant=?", (principal.tenant,)
            ).fetchone()
            if not account or account["subject"] != principal.subject:
                raise ShieldError("GITHUB_REAUTHORIZE_REQUIRED", 403)
            count = db.execute(
                "SELECT count(*) FROM github_repositories WHERE tenant=?", (principal.tenant,)
            ).fetchone()[0]
            existing = db.execute(
                "SELECT id FROM github_repositories WHERE tenant=? AND repository_id=?",
                (principal.tenant, body.repository_id),
            ).fetchone()
            if count >= 20 and not existing:
                raise ShieldError("REPOSITORY_LIMIT_REACHED", 400)
            if not existing:
                db.execute(
                    "INSERT INTO github_repositories(id,tenant,installation_id,repository_id,name) VALUES (?,?,?,?,?)",
                    (uid("gc"), principal.tenant, body.installation_id, body.repository_id, name),
                )
        return self.status(principal)

    def status(self, principal):
        with self.store.transaction() as db:
            authorized = (
                db.execute(
                    "SELECT tenant FROM github_accounts WHERE tenant=? AND subject=?",
                    (principal.tenant, principal.subject),
                ).fetchone()
                is not None
            )
            repos = [
                dict(r)
                for r in db.execute(
                    "SELECT id,installation_id,repository_id,name FROM github_repositories WHERE tenant=? ORDER BY name",
                    (principal.tenant,),
                )
            ]
        return {
            "enabled": True,
            "authorized": authorized,
            "repositories": repos,
            "install_url": self.install_url,
            "revoke_url": "https://github.com/settings/apps/authorizations",
        }

    def disconnect(self, principal, connection_id=None):
        with self.store.transaction() as db:
            if connection_id:
                if not db.execute(
                    "SELECT id FROM github_repositories WHERE id=? AND tenant=?",
                    (connection_id, principal.tenant),
                ).fetchone():
                    raise ShieldError("NOT_FOUND", 404)
                db.execute(
                    "DELETE FROM github_repositories WHERE id=? AND tenant=?",
                    (connection_id, principal.tenant),
                )
            else:
                db.execute("DELETE FROM github_flows WHERE tenant=?", (principal.tenant,))
                db.execute("DELETE FROM github_repositories WHERE tenant=?", (principal.tenant,))
                db.execute("DELETE FROM github_accounts WHERE tenant=?", (principal.tenant,))
        return {"disconnected": True}

    def adapter(self, tenant, resource, state=None):
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT * FROM github_repositories WHERE tenant=? AND name=?",
                (tenant, resource.removeprefix("repo:")),
            ).fetchone()
        if not row or (state is not None and state.get("connection_id") != row["id"]):
            raise GitHubError("GITHUB_CONNECTION_REMOVED")
        connection = dict(row)
        manager = self

        class Broker:
            def token(self, permissions):
                manager.check_connection(tenant, connection["id"])
                token = manager.token(tenant)
                manager.verify_access(connection, token)
                metadata = manager.api(f"/repositories/{connection['repository_id']}", token)
                if (
                    metadata.get("id") != connection["repository_id"]
                    or metadata.get("full_name") != connection["name"]
                ):
                    raise GitHubError("GITHUB_REPOSITORY_IDENTITY_CHANGED")
                manager.check_connection(tenant, connection["id"])
                return token

        adapter = GitHubAdapter(
            GitHubSettings(connection["name"], enable_writes=self.settings.enable_writes),
            self.transport,
            Broker(),
        )
        adapter.connection_id = connection["id"]
        return adapter

    def verify_access(self, connection, token):
        # Public repository metadata can remain readable after an installation is
        # removed. Prove current installation membership as well as token validity.
        def find(path, field, predicate):
            for page in range(1, 101):
                data = self.api(f"{path}?per_page=100&page={page}", token)
                match = next((item for item in data.get(field, []) if predicate(item)), None)
                if match:
                    return match
                if page * 100 >= data.get("total_count", 0):
                    break
            raise GitHubError("GITHUB_REPOSITORY_ACCESS_REMOVED")

        find(
            "/user/installations",
            "installations",
            lambda item: (
                item["id"] == connection["installation_id"]
                and str(item.get("app_id")) == self.settings.app_id
                and not item.get("suspended_at")
            ),
        )
        find(
            f"/user/installations/{connection['installation_id']}/repositories",
            "repositories",
            lambda item: (
                item["id"] == connection["repository_id"] and item["full_name"] == connection["name"]
            ),
        )

    def check_connection(self, tenant, connection_id, db=None):
        if db is None:
            with self.store.transaction() as connection:
                return self.check_connection(tenant, connection_id, connection)
        if not db.execute(
            "SELECT id FROM github_repositories WHERE tenant=? AND id=?", (tenant, connection_id)
        ).fetchone():
            raise GitHubError("GITHUB_CONNECTION_REMOVED")

    def preview(self, principal, connection_id, issue_number):
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT name FROM github_repositories WHERE id=? AND tenant=?",
                (connection_id, principal.tenant),
            ).fetchone()
        if not row:
            raise ShieldError("NOT_FOUND", 404)
        adapter = self.adapter(principal.tenant, "repo:" + row["name"])
        with adapter.session() as session:
            metadata = session.metadata()
            issue = session.issue(issue_number)
        return {"repository": metadata["full_name"], "issue": issue}


def install_connections(app, auth, connections):
    def user(request: Request):
        if not auth:
            raise ShieldError("AUTHENTICATION_REQUIRED", 401)
        return auth.authenticate(request)

    def ready():
        if not connections:
            raise ShieldError("GITHUB_CONNECTIONS_NOT_CONFIGURED", 503)
        return connections

    @app.get("/v1/github/connections")
    def status(identity=Depends(user)):
        return (
            connections.status(identity[0])
            if connections
            else {"enabled": False, "authorized": False, "repositories": []}
        )

    @app.post("/v1/github/connect")
    def connect(request: Request, identity=Depends(user)):
        return ready().start(request, *identity)

    @app.get("/github/callback")
    def callback(request: Request):
        try:
            identity = user(request)
            ready().callback(request, *identity)
            return RedirectResponse("/?github=connected", status_code=303)
        except (ShieldError, GitHubError):
            return RedirectResponse("/?github=failed", status_code=303)

    @app.get("/github/setup")
    def setup():
        # Installation callbacks are navigation only; their query parameters never grant access.
        return RedirectResponse("/?github=installed", status_code=303)

    @app.get("/v1/github/installations")
    def installations(page: int = Query(default=1, ge=1, le=100), identity=Depends(user)):
        return ready().installations(identity[0], page)

    @app.get("/v1/github/installations/{installation_id}/repositories")
    def repositories(
        installation_id: int,
        page: int = Query(default=1, ge=1, le=100),
        installation_page: int = Query(default=1, ge=1, le=100),
        identity=Depends(user),
    ):
        return ready().repositories(identity[0], installation_id, page, installation_page)

    @app.post("/v1/github/repositories")
    def select(body: RepositorySelection, identity=Depends(user)):
        return ready().select(identity[0], body)

    @app.delete("/v1/github/repositories/{connection_id}")
    def remove(connection_id: str, identity=Depends(user)):
        return ready().disconnect(identity[0], connection_id)

    @app.delete("/v1/github/connections")
    def disconnect(identity=Depends(user)):
        return ready().disconnect(identity[0])

    @app.get("/v1/github/repositories/{connection_id}/issues/{issue_number}")
    def preview(connection_id: str, issue_number: int, identity=Depends(user)):
        if issue_number < 1:
            raise ShieldError("INVALID_ISSUE_NUMBER", 400)
        return ready().preview(identity[0], connection_id, issue_number)
