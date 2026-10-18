"""Ordered explicit policy functions. No model or mutable prose can grant authority."""

import re
from pathlib import PurePosixPath

from pydantic import ValidationError

from .models import ARGUMENTS, OPERATIONS, POLICY, WRITES, now

PROHIBITED = {
    "merge",
    "release",
    "create_tag",
    "publish_package",
    "read_secret",
    "write_secret",
    "update_settings",
    "force_push",
    "workflow_dispatch",
    "workflow_rerun",
    "delete_branch",
}
SENSITIVE_NAMES = {
    "Dockerfile",
    "Containerfile",
    "CODEOWNERS",
    "SECURITY.md",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "docker-compose.yml",
}
SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AGENTSHIELD_SECRET_CANARY)"
)


def deterministic(task, action, status="active"):
    # Steps 1-5: identity is authenticated in the service before this function.
    if status != "active":
        return "TASK_INACTIVE"
    if task.expires_at <= now():
        return "TASK_EXPIRED"
    if task.policy_version != POLICY:
        return "POLICY_VERSION_INVALID"
    expected_adapter = "github-rest-1" if task.provider == "github" else "mock-github-1"
    if action.adapter_version != expected_adapter:
        return "ADAPTER_MISMATCH"
    args = action.canonical_arguments
    if task.provider == "github" and action.operation == "push_commit":
        files = args.get("files", {})
        if isinstance(files, dict):
            if any(path.startswith(".github/workflows/") for path in files):
                return "GITHUB_WORKFLOW_WRITE_UNSUPPORTED"
            if any(path.startswith(".git/") or PurePosixPath(path).name.startswith(".env") for path in files):
                return "SECRET_ACCESS"
    if action.operation in PROHIBITED or args.get("force") is True:
        return "EXPLICIT_PROHIBITION"
    if action.operation in {"push_commit", "create_branch", "open_draft_pr"}:
        if not re.fullmatch(r"agent/[A-Za-z0-9_-]+", str(args.get("branch", ""))):
            return "PROTECTED_BRANCH"
    if action.operation == "read_file" and re.search(
        r"(^|/)(\.git|\.env(?:\..*)?|id_rsa|secrets?)(/|$)", str(args.get("path", ""))
    ):
        return "SECRET_ACCESS"
    repos = [r for r in action.resource_identifiers if r.startswith("repo:")]
    if len(repos) != 1 or repos[0] not in task.resources:
        return "RESOURCE_OUT_OF_SCOPE"
    for resource in action.resource_identifiers:
        if resource == repos[0]:
            continue
        if resource not in [f"issue:{n}" for n in task.issue_ids]:
            return "RESOURCE_OUT_OF_SCOPE"
    if action.operation not in task.operations:
        return "OPERATION_OUT_OF_SCOPE"
    if action.destination not in task.destinations:
        return "DESTINATION_OUT_OF_SCOPE"
    if action.destination != repos[0].replace("repo:", "github:", 1):
        return "DESTINATION_RESOURCE_MISMATCH"
    if action.operation not in ARGUMENTS or action.operation not in OPERATIONS:
        return "UNSUPPORTED_OPERATION"
    try:
        parsed = ARGUMENTS[action.operation].model_validate(args)
    except ValidationError:
        return "INVALID_ARGUMENTS"
    if hasattr(parsed, "issue_number"):
        if (
            parsed.issue_number not in task.issue_ids
            or f"issue:{parsed.issue_number}" not in action.resource_identifiers
        ):
            return "ISSUE_OUT_OF_SCOPE"
    if action.operation in WRITES:
        from .models import canonical

        if SECRET.search(canonical(args)):
            return "RESTRICTED_DATA"
    return None


def review_required(action):
    for path in action.canonical_arguments.get("files", {}):
        name = PurePosixPath(path).name
        if (
            path.startswith((".github/", ".circleci/", "ci/", ".buildkite/"))
            or name in SENSITIVE_NAMES
            or name.startswith(("Dockerfile.", "requirements-"))
            or name.endswith((".lock", ".csproj"))
        ):
            return "SENSITIVE_FILE_CHANGE"
    return None


EXPLANATIONS = {
    "RESOURCE_OUT_OF_SCOPE": "This resource is outside the authorized task.",
    "DESTINATION_OUT_OF_SCOPE": "This destination is not authorized for this task.",
    "ISSUE_OUT_OF_SCOPE": "Only the issue named in the task may be accessed.",
    "SENSITIVE_FILE_CHANGE": "This change affects build, dependency, ownership, or security configuration.",
    "ANALYSIS_UNAVAILABLE": "Required contextual analysis is unavailable. This write needs human review.",
    "AI_EXPOSURE_INTERNAL": "This write may publish internal information unrelated to the authorized task.",
    "AI_INTENT_MISMATCH": "This write may not serve the authorized task.",
    "AI_INJECTION": "Untrusted content appears to be steering this write.",
    "AI_FLOW_RISK": "The recent action sequence suggests a sensitive data transfer.",
    "BUDGET_EXCEEDED": "This action exceeds the task's reserved call or byte budget.",
    "LIVE_WRITE_REVIEW": "Real GitHub writes require independent approval of this exact action during the pilot.",
    "ALLOWED": "The action satisfies the task contract and active policy.",
}
