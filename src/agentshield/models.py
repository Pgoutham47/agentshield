import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any, Literal
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

POLICY = "coding-default-1"
OPERATIONS = ["read_issue", "read_file", "create_branch", "push_commit", "open_draft_pr", "comment_issue"]
WRITES = {"create_branch", "push_commit", "open_draft_pr", "comment_issue", "create_gist"}


def now():
    return datetime.now(UTC)


def uid(prefix):
    return f"{prefix}_{uuid4().hex[:16]}"


def canonical(value):
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return "sha256:" + sha256(canonical(value).encode()).hexdigest()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(Strict):
    max_calls: int = Field(default=200, ge=1, le=1000, strict=True)
    max_bytes: int = Field(default=50 * 1024 * 1024, ge=1, le=50 * 1024 * 1024, strict=True)
    max_concurrency: int = Field(default=4, ge=1, le=16, strict=True)


class Principal(Strict):
    tenant: str
    subject: str
    role: Literal["requester", "worker", "approver", "admin"]
    requester: str
    resources: list[str]


class Task(Strict):
    provider: Literal["mock", "github"] = "mock"
    task_id: str = Field(default_factory=lambda: uid("t"), min_length=1, max_length=100)
    tenant: str = Field(min_length=1, max_length=100)
    requester: str = Field(min_length=1, max_length=200)
    agent: str = "coding-agent"
    purpose: str = Field(min_length=8, max_length=2000)
    resources: list[str] = Field(min_length=1, max_length=10)
    operations: list[str] = Field(default_factory=lambda: OPERATIONS.copy(), min_length=1, max_length=20)
    destinations: list[str] = Field(min_length=1, max_length=10)
    issue_ids: list[int] = Field(default_factory=lambda: [412], min_length=1, max_length=20)
    expires_at: AwareDatetime = Field(default_factory=lambda: now() + timedelta(minutes=30))
    budget: Budget = Field(default_factory=Budget)
    policy_version: str = POLICY
    idempotency_key: str = Field(default_factory=lambda: uid("tk"), min_length=1, max_length=100)

    @field_validator("resources")
    @classmethod
    def repositories(cls, values):
        import re

        if any(not re.fullmatch(r"repo:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", v) for v in values):
            raise ValueError("Use canonical repo:owner/name resources")
        return sorted(set(values))


class Action(Strict):
    task_id: str = Field(min_length=1, max_length=100)
    action_id: str = Field(default_factory=lambda: uid("a"), min_length=1, max_length=100)
    tool_name: Literal["github"] = "github"
    operation: str = Field(min_length=1, max_length=50)
    resource_identifiers: list[str] = Field(min_length=1, max_length=20)
    destination: str = Field(min_length=1, max_length=300)
    canonical_arguments: dict[str, Any]
    source_references: list[str] = Field(default_factory=list, max_length=20)
    data_labels: list[str] = Field(default_factory=list, max_length=20)
    expected_resource_version: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(default_factory=lambda: uid("ak"), min_length=1, max_length=100)
    adapter_version: Literal["mock-github-1", "github-rest-1"] = "mock-github-1"

    @model_validator(mode="after")
    def bounded(self):
        if len(canonical(self).encode()) > 65536:
            raise ValueError("Action exceeds 64 KiB inline inspection limit")
        return self


class ReadIssue(Strict):
    issue_number: int = Field(gt=0, strict=True)


class ReadFile(Strict):
    path: str

    @field_validator("path")
    @classmethod
    def safe_path(cls, value):
        path = PurePosixPath(value)
        if not value or path.is_absolute() or any(p in (".", "..") for p in value.split("/")):
            raise ValueError("Path must be canonical and repository relative")
        if "\\" in value or "%" in value or "\x00" in value or str(path) != value:
            raise ValueError("Noncanonical path")
        return value


class Branch(Strict):
    branch: str = Field(pattern=r"^agent/[A-Za-z0-9_-]+$")


class Commit(Branch):
    files: dict[str, str] = Field(min_length=1, max_length=30)
    message: str = Field(min_length=1, max_length=500)
    force: Literal[False] = False

    @field_validator("files")
    @classmethod
    def paths(cls, files):
        for path in files:
            ReadFile(path=path)
            if any(other != path and other.startswith(path + "/") for other in files):
                raise ValueError("Overlapping file paths are not allowed")
        return files


class PullRequest(Branch):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(max_length=20000)
    draft: Literal[True] = True


class Comment(ReadIssue):
    body: str = Field(min_length=1, max_length=20000)


class Gist(Strict):
    body: str = Field(min_length=1, max_length=20000)


ARGUMENTS = {
    "read_issue": ReadIssue,
    "read_file": ReadFile,
    "create_branch": Branch,
    "push_commit": Commit,
    "open_draft_pr": PullRequest,
    "comment_issue": Comment,
    "create_gist": Gist,
}


class Score(Strict):
    score: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)


class Injection(Score):
    evidence: str = Field(max_length=500)


class Alignment(Score):
    rationale: str = Field(max_length=1000)


class Exposure(Score):
    category: str = Field(max_length=100)


class Signals(Strict):
    injection: Injection
    intent_alignment: Alignment
    exposure: Exposure
    flow: Score


class Decision(Strict):
    decision_id: str = Field(default_factory=lambda: uid("d"))
    disposition: Literal["allow", "deny", "require_approval"]
    reason_codes: list[str]
    applicable_rule_ids: list[str]
    policy_version: str = POLICY
    detector_versions: dict[str, str]
    signals: Signals | None = None
    explanation: str
    suggested_next_step: str
    action_digest: str
    expires_at: AwareDatetime
    approval_id: str | None = None
    parent_decision_id: str | None = None


class Resolution(Strict):
    approve: bool = Field(strict=True)
    action_digest: str
    justification: str = Field(min_length=5, max_length=1000)


class ExecutionRequest(Strict):
    decision_id: str
    envelope: Action


class DraftRequest(Strict):
    provider: Literal["mock", "github"] = "mock"
    request: str = Field(min_length=8, max_length=2000)
    entitlements: list[str] = Field(min_length=1, max_length=10)
    issue_number: int = Field(default=412, gt=0)
