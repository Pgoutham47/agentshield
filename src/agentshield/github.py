"""GitHub Cloud adapter. Credentials stay server-side; no generic HTTP tool is exposed."""

import base64
import os
import re
import subprocess
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx
import jwt

from .models import digest

API_VERSION = "2026-03-10"
ADAPTER_VERSION = "github-rest-1"
MAX_WIRE_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_FILE_BYTES = 64 * 1024


class GitHubError(Exception):
    """Only safe codes leave this module. Never include tokens or provider response bodies."""

    def __init__(self, code, *, unknown=False, request_id=None):
        self.code, self.unknown, self.request_id = code, unknown, request_id
        super().__init__(code)


@dataclass(frozen=True)
class GitHubSettings:
    repository: str
    auth_mode: str = "app"
    app_id: str = ""
    installation_id: str = ""
    private_key_path: str = ""
    enable_writes: bool = False
    dev_account: str = ""

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ValueError("AGENTSHIELD_GITHUB_REPOSITORY must be owner/repository")
        if self.auth_mode not in {"app", "gh"}:
            raise ValueError("GITHUB_AUTH_MODE must be app or gh")
        if self.auth_mode == "gh" and not re.fullmatch(r"[A-Za-z0-9_-]+", self.dev_account):
            raise ValueError("GITHUB_DEV_ACCOUNT is required for explicit CLI development authentication")

    @classmethod
    def from_env(cls):
        repo = os.getenv("AGENTSHIELD_GITHUB_REPOSITORY", "")
        if not repo:
            return None
        mode = os.getenv("GITHUB_AUTH_MODE", "app")
        if mode == "gh" and os.getenv("AGENTSHIELD_ALLOW_GH_DEV_AUTH") != "true":
            raise ValueError("CLI authentication requires AGENTSHIELD_ALLOW_GH_DEV_AUTH=true")
        return cls(
            repo,
            mode,
            os.getenv("GITHUB_APP_ID", ""),
            os.getenv("GITHUB_INSTALLATION_ID", ""),
            os.getenv("GITHUB_PRIVATE_KEY_PATH", ""),
            os.getenv("GITHUB_ENABLE_WRITES") == "true",
            os.getenv("GITHUB_DEV_ACCOUNT", ""),
        )


def headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "AgentShield/0.1",
    }


def bounded_request(client, method, path, *, token, body=None):
    """No redirects, no retries, bounded streaming; ambiguous write outcomes are never called blocked."""
    mutation = method not in {"GET", "HEAD"}
    request_id = None
    try:
        with client.stream(method, path, headers=headers(token), json=body) as response:
            request_id = response.headers.get("x-github-request-id")
            if response.status_code >= 500:
                raise GitHubError("GITHUB_SERVER_ERROR", unknown=mutation, request_id=request_id)
            if response.status_code >= 300:
                code = {
                    301: "GITHUB_REDIRECT_REFUSED",
                    302: "GITHUB_REDIRECT_REFUSED",
                    401: "GITHUB_AUTH_FAILED",
                    403: "GITHUB_FORBIDDEN_OR_RATE_LIMITED",
                    404: "GITHUB_NOT_FOUND",
                    409: "GITHUB_CONFLICT",
                    422: "GITHUB_VALIDATION_FAILED",
                    429: "GITHUB_RATE_LIMITED",
                }.get(response.status_code, "GITHUB_REQUEST_REJECTED")
                raise GitHubError(code, request_id=request_id)
            content = bytearray()
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise GitHubError("GITHUB_RESPONSE_TOO_LARGE", unknown=mutation, request_id=request_id)
            import json

            try:
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise GitHubError(
                    "GITHUB_INVALID_RESPONSE", unknown=mutation, request_id=request_id
                ) from None
            return data, request_id, len(content)
    except httpx.RequestError:
        raise GitHubError("GITHUB_TRANSPORT_ERROR", unknown=mutation, request_id=request_id) from None


class TokenBroker:
    def __init__(self, settings, transport=None):
        self.settings, self.transport = settings, transport

    def token(self, permissions):
        s = self.settings
        if s.auth_mode == "gh":
            try:
                result = subprocess.run(
                    ["gh", "auth", "token", "--hostname", "github.com", "--user", s.dev_account],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                token = result.stdout.strip()
                if not token:
                    raise ValueError()
                return token
            except (OSError, subprocess.SubprocessError, ValueError):
                raise GitHubError("GITHUB_CLI_AUTH_UNAVAILABLE") from None
        if not s.app_id or not s.installation_id.isdigit() or not s.private_key_path:
            raise GitHubError("GITHUB_APP_CONFIGURATION_REQUIRED")
        try:
            timestamp = int(time.time())
            signed = jwt.encode(
                {"iat": timestamp - 60, "exp": timestamp + 540, "iss": s.app_id},
                Path(s.private_key_path).read_bytes(),
                algorithm="RS256",
            )
        except Exception:
            raise GitHubError("GITHUB_APP_KEY_INVALID") from None
        with httpx.Client(
            base_url="https://api.github.com",
            timeout=10,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            data, _, _ = bounded_request(
                client,
                "POST",
                f"/app/installations/{s.installation_id}/access_tokens",
                token=signed,
                body={"repositories": [s.repository.split("/")[1]], "permissions": permissions},
            )
        selected = data.get("repositories", [])
        if (
            not isinstance(selected, list)
            or len(selected) != 1
            or not isinstance(selected[0], dict)
            or selected[0].get("full_name", "").lower() != s.repository.lower()
        ):
            raise GitHubError("GITHUB_TOKEN_SCOPE_MISMATCH")
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubError("GITHUB_TOKEN_MISSING")
        return token


class GitHubSession:
    def __init__(self, settings, token, transport=None):
        self.settings, self._token = settings, token
        self.client = httpx.Client(
            base_url="https://api.github.com",
            timeout=10,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        self.bytes = 0
        self.calls = 0
        self.request_ids = []
        self.mutated = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.client.close()
        self._token = ""

    def request(self, method, suffix="", body=None):
        # All paths are generated by typed adapter methods, never by agent URL arguments.
        if not suffix.startswith("/") and suffix:
            raise GitHubError("GITHUB_INVALID_PATH")
        if self.calls >= 16 or self.bytes + MAX_RESPONSE_BYTES > MAX_WIRE_BYTES:
            raise GitHubError("GITHUB_IO_BUDGET_EXCEEDED", unknown=self.mutated)
        self.calls += 1
        try:
            data, request_id, size = bounded_request(
                self.client,
                method,
                f"/repos/{self.settings.repository}{suffix}",
                token=self._token,
                body=body,
            )
        except GitHubError as error:
            error.unknown = error.unknown or self.mutated
            raise
        self.bytes += size
        if request_id:
            self.request_ids.append(request_id)
        if method != "GET":
            self.mutated = True
        return data

    def metadata(self, expected_id=None):
        data = self.request("GET")
        if data.get("full_name", "").lower() != self.settings.repository.lower() or (
            expected_id is not None and data.get("id") != expected_id
        ):
            raise GitHubError("GITHUB_REPOSITORY_IDENTITY_CHANGED")
        if data.get("archived") or data.get("disabled"):
            raise GitHubError("GITHUB_REPOSITORY_UNAVAILABLE")
        return data

    def head(self, branch):
        data = self.request("GET", "/git/ref/heads/" + quote(branch, safe=""))
        if data.get("ref") != f"refs/heads/{branch}" or data.get("object", {}).get("type") != "commit":
            raise GitHubError("GITHUB_INVALID_REFERENCE")
        return data["object"]["sha"]

    def issue(self, number):
        data = self.request("GET", f"/issues/{number}")
        if data.get("number") != number or "pull_request" in data:
            raise GitHubError("GITHUB_ISSUE_REQUIRED")
        body = data.get("body") or ""
        if len(body.encode()) > MAX_FILE_BYTES:
            raise GitHubError("GITHUB_CONTENT_TOO_LARGE")
        return {
            "number": number,
            "title": data["title"],
            "body": body,
            "updated_at": data["updated_at"],
            "state": data["state"],
        }


def resource_version(repo, action):
    op = action.operation
    args = action.canonical_arguments
    if op in {"read_issue", "comment_issue"}:
        return "github:" + digest(repo["issue"])
    if op in {"read_file", "create_branch"}:
        return "commit:" + repo["base_sha"]
    branch = repo["branches"].get(args.get("branch"))
    if not branch:
        raise GitHubError("TASK_BRANCH_REQUIRED")
    if op == "push_commit":
        return "commit:" + branch["sha"]
    if op == "open_draft_pr":
        return "github:" + digest({"base": repo["base_sha"], "head": branch["sha"]})
    raise GitHubError("UNSUPPORTED_OPERATION")


class GitHubAdapter:
    version = ADAPTER_VERSION

    def __init__(self, settings, transport=None, broker=None):
        self.settings, self.transport = settings, transport
        self.broker = broker or TokenBroker(settings, transport)

    def session(self, operation="read_issue"):
        permissions = {"contents": "read", "issues": "read", "pull_requests": "read"}
        if operation in {"create_branch", "push_commit"}:
            permissions["contents"] = "write"
        if operation == "open_draft_pr":
            permissions["pull_requests"] = "write"
        if operation == "comment_issue":
            permissions["issues"] = "write"
        return GitHubSession(self.settings, self.broker.token(permissions), self.transport)

    def status(self, verify=False):
        result = {
            "configured": True,
            "repository": self.settings.repository,
            "auth_mode": self.settings.auth_mode,
            "writes_enabled": self.settings.enable_writes,
            "adapter_version": self.version,
            "api_version": API_VERSION,
            "coverage": "mediated API only; no sandbox or egress isolation",
            "connection": "not_checked",
        }
        if verify:
            with self.session() as session:
                data = session.metadata()
                result.update(
                    connection="verified", repository_id=data["id"], default_branch=data["default_branch"]
                )
        return result

    def initialize(self, task):
        if task.resources != [f"repo:{self.settings.repository}"] or len(task.issue_ids) != 1:
            raise GitHubError("GITHUB_TASK_SCOPE_INVALID")
        with self.session() as session:
            metadata = session.metadata()
            branch = metadata["default_branch"]
            head = session.head(branch)
            issue = session.issue(task.issue_ids[0])
            return {
                "provider": "github",
                "repository": self.settings.repository,
                "repository_id": metadata["id"],
                "base_branch": branch,
                "base_sha": head,
                "issue": issue,
                "branches": {},
                "prs": [],
                "comments": [],
                "version": 1,
            }

    def execute(self, repo, action, guard):
        """Recheck mutable provider state before mutation. guard rechecks gateway state before every write."""
        updated = deepcopy(repo)
        args, op = action.canonical_arguments, action.operation
        if resource_version(repo, action) != action.expected_resource_version:
            raise GitHubError("RESOURCE_VERSION_CHANGED")
        if op not in {"read_issue", "read_file"} and not self.settings.enable_writes:
            raise GitHubError("GITHUB_WRITES_DISABLED")
        if repo["repository"] != self.settings.repository:
            raise GitHubError("GITHUB_REPOSITORY_IDENTITY_CHANGED")
        with self.session(op) as session:
            session.metadata(repo["repository_id"])

            def write(method, path, body):
                try:
                    guard()
                except Exception:
                    raise GitHubError("TASK_STOPPED_BEFORE_SUBMISSION", unknown=session.mutated) from None
                return session.request(method, path, body)

            try:
                if op in {"read_issue", "comment_issue"}:
                    issue = session.issue(args["issue_number"])
                    if "github:" + digest(issue) != action.expected_resource_version:
                        raise GitHubError("RESOURCE_VERSION_CHANGED")
                    if op == "read_issue":
                        result = {
                            "issue": issue,
                            "source": f"issue:{args['issue_number']}#body",
                            "trust": "untrusted",
                        }
                    else:
                        data = write(
                            "POST", f"/issues/{args['issue_number']}/comments", {"body": args["body"]}
                        )
                        result = {"comment_id": data["id"], "url": data["html_url"]}
                        updated["comments"].append(result)
                elif op == "read_file":
                    commit = session.request("GET", "/git/commits/" + repo["base_sha"])
                    tree_sha = commit["tree"]["sha"]
                    parts = args["path"].split("/")
                    for index, part in enumerate(parts):
                        tree = session.request("GET", "/git/trees/" + tree_sha)
                        if tree.get("truncated"):
                            raise GitHubError("GITHUB_TREE_UNINSPECTED")
                        entry = next((e for e in tree["tree"] if e["path"] == part), None)
                        if not entry:
                            raise GitHubError("GITHUB_NOT_FOUND")
                        if index < len(parts) - 1:
                            if entry["type"] != "tree":
                                raise GitHubError("GITHUB_UNSUPPORTED_FILE")
                            tree_sha = entry["sha"]
                        elif entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}:
                            raise GitHubError("GITHUB_UNSUPPORTED_FILE")
                    data = session.request("GET", "/git/blobs/" + entry["sha"])
                    if (
                        data.get("encoding") != "base64"
                        or data.get("size", MAX_FILE_BYTES + 1) > MAX_FILE_BYTES
                    ):
                        raise GitHubError("GITHUB_UNSUPPORTED_FILE")
                    raw = base64.b64decode(data["content"].replace("\n", ""), validate=True)
                    if len(raw) > MAX_FILE_BYTES:
                        raise GitHubError("GITHUB_CONTENT_TOO_LARGE")
                    result = {
                        "content": raw.decode("utf-8"),
                        "source": args["path"],
                        "trust": "untrusted",
                        "commit": repo["base_sha"],
                    }
                elif op == "create_branch":
                    if args["branch"] in repo["branches"]:
                        raise GitHubError("TASK_BRANCH_ALREADY_EXISTS")
                    data = write(
                        "POST", "/git/refs", {"ref": "refs/heads/" + args["branch"], "sha": repo["base_sha"]}
                    )
                    if data["object"]["sha"] != repo["base_sha"]:
                        raise GitHubError("GITHUB_UNEXPECTED_RESULT", unknown=True)
                    updated["branches"][args["branch"]] = {"sha": repo["base_sha"], "commits": []}
                    result = {"branch": args["branch"], "sha": repo["base_sha"]}
                elif op in {"push_commit", "open_draft_pr"}:
                    branch = repo["branches"][args["branch"]]
                    head = session.head(args["branch"])
                    if head != branch["sha"]:
                        raise GitHubError("RESOURCE_VERSION_CHANGED")
                    if op == "push_commit":
                        commit = session.request("GET", "/git/commits/" + head)
                        existing_tree = session.request(
                            "GET", "/git/trees/" + commit["tree"]["sha"] + "?recursive=1"
                        )
                        if existing_tree.get("truncated"):
                            raise GitHubError("GITHUB_TREE_UNINSPECTED")
                        entries = {entry["path"]: entry for entry in existing_tree["tree"]}
                        for path in args["files"]:
                            entry = entries.get(path)
                            if entry and (
                                entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}
                            ):
                                raise GitHubError("GITHUB_UNSUPPORTED_FILE")
                            parts = path.split("/")
                            for i in range(1, len(parts)):
                                parent = entries.get("/".join(parts[:i]))
                                if parent and parent["type"] != "tree":
                                    raise GitHubError("GITHUB_UNSUPPORTED_FILE")
                        tree = write(
                            "POST",
                            "/git/trees",
                            {
                                "base_tree": commit["tree"]["sha"],
                                "tree": [
                                    {
                                        "path": path,
                                        "mode": entries.get(path, {}).get("mode", "100644"),
                                        "type": "blob",
                                        "content": content,
                                    }
                                    for path, content in sorted(args["files"].items())
                                ],
                            },
                        )
                        new_commit = write(
                            "POST",
                            "/git/commits",
                            {"message": args["message"], "tree": tree["sha"], "parents": [head]},
                        )
                        # GitHub REST has no expected-old-SHA CAS. Re-read, then non-force fast-forward.
                        if session.head(args["branch"]) != head:
                            raise GitHubError("RESOURCE_VERSION_CHANGED", unknown=True)
                        write(
                            "PATCH",
                            "/git/refs/heads/" + quote(args["branch"], safe=""),
                            {"sha": new_commit["sha"], "force": False},
                        )
                        updated["branches"][args["branch"]] = {
                            "sha": new_commit["sha"],
                            "commits": branch["commits"] + [new_commit["sha"]],
                        }
                        result = {"commit": new_commit["sha"], "files": list(args["files"])}
                    else:
                        if not branch["commits"]:
                            raise GitHubError("TASK_COMMIT_REQUIRED")
                        if session.head(repo["base_branch"]) != repo["base_sha"]:
                            raise GitHubError("BASE_BRANCH_CHANGED")
                        if repo["prs"]:
                            raise GitHubError("TASK_PR_ALREADY_EXISTS")
                        data = write(
                            "POST",
                            "/pulls",
                            {
                                "title": args["title"],
                                "body": args["body"],
                                "head": args["branch"],
                                "base": repo["base_branch"],
                                "draft": True,
                                "maintainer_can_modify": False,
                            },
                        )
                        if data.get("draft") is not True:
                            raise GitHubError("GITHUB_UNEXPECTED_RESULT", unknown=True)
                        result = {
                            "pull_request": {"number": data["number"], "url": data["html_url"], "draft": True}
                        }
                        updated["prs"].append(result["pull_request"])
                else:
                    raise GitHubError("UNSUPPORTED_OPERATION")
            except GitHubError as error:
                error.unknown = error.unknown or session.mutated
                raise
            except (KeyError, TypeError, ValueError, UnicodeError):
                raise GitHubError("GITHUB_INVALID_RESPONSE", unknown=session.mutated) from None
            updated["version"] += 1
            return updated, result, session.request_ids, session.bytes
