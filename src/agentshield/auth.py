"""Supabase GitHub OAuth with PKCE and encrypted, revocable server-side sessions.

Supabase /user is the identity authority; editable metadata never grants access.
No provider access or refresh token is returned to the browser.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from .engine import ShieldError
from .models import Principal

SESSION_SECONDS = 7 * 24 * 3600
# SQLite is single-process development; PostgreSQL also uses a cross-process advisory lock.
_SESSION_LOCKS = [threading.RLock() for _ in range(32)]


@dataclass(frozen=True)
class AuthSettings:
    url: str
    key: str
    base_url: str
    secret: str
    owner_github_id: str = ""

    def __post_init__(self):
        for value in (self.url, self.base_url):
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
                or parsed.username
            ):
                raise ValueError("Auth URLs must be HTTPS origins")
        if len(self.secret) < 32 or not self.key:
            raise ValueError(
                "Supabase Auth requires a public key and a session secret of at least 32 characters"
            )
        if self.owner_github_id and not self.owner_github_id.isdecimal():
            raise ValueError("Owner must be an immutable numeric GitHub user ID")

    @classmethod
    def from_env(cls):
        fields = [
            os.getenv(k, "")
            for k in ("SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "APP_BASE_URL", "APP_SESSION_SECRET")
        ]
        if not any(fields):
            return None
        return cls(*fields, owner_github_id=os.getenv("AGENTSHIELD_OWNER_GITHUB_ID", ""))


class SupabaseAuth:
    cookie = "__Host-agentshield_session"
    flow_cookie = "__Host-agentshield_oauth"

    def __init__(self, settings, store, github=None, transport=None):
        self.settings, self.store, self.github = settings, store, github
        self.transport = transport
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.secret.encode()).digest()))

    def seal(self, data):
        return self.cipher.encrypt(json.dumps(data).encode()).decode()

    def unseal(self, value, ttl=None):
        try:
            return json.loads(self.cipher.decrypt(value.encode(), ttl=ttl))
        except (InvalidToken, ValueError, TypeError, AttributeError):
            raise ShieldError("AUTHENTICATION_REQUIRED", 401) from None

    def remote(self, method, path, token=None, body=None):
        headers = {"apikey": self.settings.key}
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            with httpx.Client(timeout=15, transport=self.transport, follow_redirects=False) as client:
                response = client.request(
                    method, self.settings.url.rstrip("/") + "/auth/v1/" + path, headers=headers, json=body
                )
            if response.status_code in {400, 401, 403, 422}:
                raise ShieldError("AUTHENTICATION_REQUIRED", 401)
            if response.status_code >= 300:
                raise ShieldError("AUTH_SERVICE_UNAVAILABLE", 503)
            return response.json() if response.content else {}
        except (httpx.HTTPError, ValueError):
            raise ShieldError("AUTH_SERVICE_UNAVAILABLE", 503) from None

    def profile(self, user):
        try:
            uid = str(UUID(user["id"]))
            # identity_data belongs to Supabase's verified provider identity, not user_metadata.
            ids = [
                str(i["identity_data"]["sub"])
                for i in user.get("identities", [])
                if i.get("provider") == "github"
            ]
            if len(ids) != 1 or not ids[0].isdecimal():
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise ShieldError("GITHUB_IDENTITY_REQUIRED", 401) from None
        owner = bool(
            self.settings.owner_github_id and hmac.compare_digest(ids[0], self.settings.owner_github_id)
        )
        tenant = "acme" if owner else "user_" + UUID(uid).hex
        resources = ["repo:acme/web-ui"]
        if owner and self.github:
            resources.append("repo:" + self.github.settings.repository)
        principal = Principal(
            tenant=tenant,
            subject="supabase:" + uid,
            requester="supabase:" + uid,
            role="admin",
            resources=resources,
        )
        return principal, {
            "id": uid,
            "email": user.get("email", ""),
            "workspace": "Owner workspace" if owner else "Personal demo workspace",
            "tenant": tenant,
            "owner": owner,
        }

    def same_origin(self, request):
        if request.headers.get("origin") != self.settings.base_url.rstrip("/"):
            raise ShieldError("SAME_ORIGIN_REQUIRED", 403)

    def set_cookie(self, response, name, value, age):
        response.set_cookie(name, value, max_age=age, secure=True, httponly=True, samesite="lax", path="/")

    def clear_cookie(self, response, name):
        response.delete_cookie(name, secure=True, httponly=True, samesite="lax", path="/")

    def login(self, request):
        self.same_origin(request)
        verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        callback = self.settings.base_url.rstrip("/") + "/auth/callback?state=" + state
        params = {
            "provider": "github",
            "redirect_to": callback,
            "code_challenge": challenge,
            "code_challenge_method": "s256",
        }
        response = JSONResponse(
            {"url": self.settings.url.rstrip("/") + "/auth/v1/authorize?" + urlencode(params)}
        )
        self.set_cookie(response, self.flow_cookie, self.seal({"verifier": verifier, "state": state}), 600)
        return response

    def session_tokens(self, payload):
        try:
            access, refresh = payload["access_token"], payload["refresh_token"]
            expiry = time.time() + min(int(payload["expires_in"]), 86400)
            if not isinstance(access, str) or not isinstance(refresh, str) or not access or not refresh:
                raise ValueError()
            return {"access": access, "refresh": refresh, "expires": expiry}
        except (KeyError, ValueError, TypeError):
            raise ShieldError("AUTH_SERVICE_UNAVAILABLE", 503) from None

    @staticmethod
    def session_id(request):
        cookie = request.cookies.get(SupabaseAuth.cookie, "")
        if not cookie or len(cookie) > 128:
            raise ShieldError("AUTHENTICATION_REQUIRED", 401)
        return hashlib.sha256(cookie.encode()).hexdigest()

    def callback(self, request):
        response = RedirectResponse("/", status_code=303)
        try:
            flow = self.unseal(request.cookies.get(self.flow_cookie, ""), ttl=600)
            state = request.query_params.get("state", "")
            code = request.query_params.get("code", "")
            if (
                not state
                or not hmac.compare_digest(state.encode(), flow["state"].encode())
                or not code
                or len(code) > 4096
            ):
                raise ShieldError("AUTHENTICATION_REQUIRED", 401)
            payload = self.remote(
                "POST", "token?grant_type=pkce", body={"auth_code": code, "code_verifier": flow["verifier"]}
            )
            tokens = self.session_tokens(payload)
            _, profile = self.profile(self.remote("GET", "user", tokens["access"]))
            opaque = secrets.token_urlsafe(32)
            key = hashlib.sha256(opaque.encode()).hexdigest()
            with self.store.transaction() as db:
                db.execute("DELETE FROM auth_sessions WHERE expires_at<?", (time.time(),))
                old = request.cookies.get(self.cookie)
                if old:
                    db.execute(
                        "DELETE FROM auth_sessions WHERE id=?", (hashlib.sha256(old.encode()).hexdigest(),)
                    )
                db.execute(
                    "INSERT INTO auth_sessions(id,user_id,tokens,expires_at) VALUES (?,?,?,?)",
                    (key, profile["id"], self.seal(tokens), time.time() + SESSION_SECONDS),
                )
            self.set_cookie(response, self.cookie, opaque, SESSION_SECONDS)
        except ShieldError:
            response = RedirectResponse("/?auth_error=login_failed", status_code=303)
        self.clear_cookie(response, self.flow_cookie)
        return response

    def authenticate(self, request):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            self.same_origin(request)
        key = self.session_id(request)
        # Serialize refresh-token rotation across requests and Render deploys.
        with (
            _SESSION_LOCKS[int(key[:2], 16) % len(_SESSION_LOCKS)],
            self.store.execution_lock("auth:" + key, wait=True),
        ):
            with self.store.transaction() as db:
                row = db.execute(
                    "SELECT * FROM auth_sessions WHERE id=? AND expires_at>?", (key, time.time())
                ).fetchone()
            if not row:
                raise ShieldError("AUTHENTICATION_REQUIRED", 401)
            tokens = self.unseal(row["tokens"])
            try:
                if tokens["expires"] < time.time() + 60:
                    tokens = self.session_tokens(
                        self.remote(
                            "POST",
                            "token?grant_type=refresh_token",
                            body={"refresh_token": tokens["refresh"]},
                        )
                    )
                principal, profile = self.profile(self.remote("GET", "user", tokens["access"]))
                if profile["id"] != row["user_id"]:
                    raise ShieldError("AUTHENTICATION_REQUIRED", 401)
            except ShieldError as error:
                if error.status == 401:
                    with self.store.transaction() as db:
                        db.execute("DELETE FROM auth_sessions WHERE id=?", (key,))
                raise
            with self.store.transaction() as db:
                # Logout can run while the provider request is in flight. Never resurrect it.
                exists = db.execute(
                    "SELECT id FROM auth_sessions WHERE id=? AND expires_at>?", (key, time.time())
                ).fetchone()
                if not exists:
                    raise ShieldError("AUTHENTICATION_REQUIRED", 401)
                db.execute("UPDATE auth_sessions SET tokens=? WHERE id=?", (self.seal(tokens), key))
            return principal, profile

    def logout(self, request):
        self.same_origin(request)
        try:
            key = self.session_id(request)
        except ShieldError:
            key = ""
        with self.store.transaction() as db:
            row = db.execute("SELECT tokens FROM auth_sessions WHERE id=?", (key,)).fetchone()
            db.execute("DELETE FROM auth_sessions WHERE id=?", (key,))
        if row:
            try:
                self.remote("POST", "logout?scope=local", self.unseal(row["tokens"])["access"])
            except ShieldError:
                pass  # Local session is already revoked even if Supabase is unavailable.
        response = JSONResponse({"signed_out": True})
        self.clear_cookie(response, self.cookie)
        self.clear_cookie(response, self.flow_cookie)
        return response


def install_auth(app, auth):
    @app.get("/auth/me")
    def me(request: Request):
        if not auth:
            return {"enabled": False, "user": None}
        try:
            _, user = auth.authenticate(request)
            return {"enabled": True, "user": user}
        except ShieldError as error:
            if error.status != 401:
                raise
            response = JSONResponse({"enabled": True, "user": None})
            auth.clear_cookie(response, auth.cookie)
            return response

    @app.post("/auth/login")
    def login(request: Request):
        if not auth:
            raise ShieldError("AUTH_NOT_CONFIGURED", 404)
        return auth.login(request)

    @app.get("/auth/callback")
    def callback(request: Request):
        if not auth:
            raise ShieldError("AUTH_NOT_CONFIGURED", 404)
        return auth.callback(request)

    @app.post("/auth/logout")
    def logout(request: Request):
        if not auth:
            raise ShieldError("AUTH_NOT_CONFIGURED", 404)
        return auth.logout(request)
