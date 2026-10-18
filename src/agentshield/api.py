import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import Field

from .analyzer import Analyzer
from .demo import DEVELOPER, OPERATOR, REVIEWER, WORKER, run_demo
from .engine import Engine, ShieldError
from .github import GitHubAdapter, GitHubError, GitHubSettings
from .hosting import hosted, hosted_tokens
from .models import Action, DraftRequest, ExecutionRequest, Resolution, Strict, Task

STATIC = Path(__file__).parent / "static"


class DemoRequest(Strict):
    scenario: str = Field(pattern="^[ABC]$")
    leave_pending: bool = False


def local_tokens(directory):
    path = directory / "local-tokens.json"
    if not path.exists():
        directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(
                {role: secrets.token_urlsafe(32) for role in ["developer", "worker", "reviewer", "operator"]},
                f,
            )
    return json.loads(path.read_text())


def create_app(db_path=None, tokens=None, analyzer=None, github=None):
    data = Path(os.getenv("AGENTSHIELD_DATA_DIR", "data"))
    settings = GitHubSettings.from_env() if github is None else None
    github = github or (GitHubAdapter(settings) if settings else None)
    required_tokens = hosted_tokens(data, github)
    if required_tokens:
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
        data.chmod(0o700)
    engine = Engine(
        db_path or data / "console.sqlite",
        analyzer or Analyzer(os.getenv("AGENTSHIELD_ANALYZER", "fixture")),
        github=github,
    )
    tokens = required_tokens or tokens or local_tokens(data)
    identities = {"developer": DEVELOPER, "worker": WORKER, "reviewer": REVIEWER, "operator": OPERATOR}
    identities = {
        name: p.model_copy(
            update={"resources": p.resources + ([f"repo:{github.settings.repository}"] if github else [])}
        )
        for name, p in identities.items()
    }
    for key in identities:
        if os.getenv(f"AGENTSHIELD_{key.upper()}_TOKEN"):
            tokens[key] = os.environ[f"AGENTSHIELD_{key.upper()}_TOKEN"]

    @asynccontextmanager
    async def lifespan(app):
        engine.recover()
        yield

    app = FastAPI(
        title="AgentShield",
        version="0.1.0",
        description="Task-bound authorization · GitHub integration pilot",
        lifespan=lifespan,
    )
    app.state.engine = engine

    def identity(authorization: str = Header(default="")):
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        for role, expected in tokens.items():
            if token and hmac.compare_digest(token, expected):
                return identities[role]
        raise ShieldError("AUTHENTICATION_REQUIRED", 401)

    def reviewer(principal=Depends(identity)):
        if principal.role not in {"admin", "approver"}:
            raise ShieldError("REVIEWER_REQUIRED", 403)
        return principal

    @app.exception_handler(ShieldError)
    async def error_handler(request, error):
        return JSONResponse(status_code=error.status, content={"error": error.code})

    @app.middleware("http")
    async def limits_and_headers(request: Request, call_next):
        # Bound the actual body, including chunked requests; do not trust Content-Length.
        if request.method in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 100_000:
                    return JSONResponse(status_code=413, content={"error": "REQUEST_TOO_LARGE"})
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if hosted():
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path == "/" or request.url.path.startswith("/static"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
        return response

    @app.exception_handler(GitHubError)
    async def github_error_handler(request, error):
        return JSONResponse(status_code=503, content={"error": error.code})

    @app.get("/v1/integrations/github")
    def github_status(verify: bool = False, principal=Depends(reviewer)):
        if not github:
            return {"configured": False, "connection": "not_configured"}
        return github.status(verify=verify)

    @app.post("/v1/actions/prepare")
    def prepare(body: Action, principal=Depends(identity)):
        return engine.prepare(body, principal)

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "provider": "mock-github-1",
            "github_configured": github is not None,
            "coverage": "mediated API only",
        }

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/v1/overview")
    def overview(principal=Depends(reviewer)):
        return engine.overview(principal)

    @app.post("/v1/tasks/draft")
    async def draft(body: DraftRequest, principal=Depends(identity)):
        return await engine.draft(body, principal)

    @app.post("/v1/tasks")
    def task(body: Task, principal=Depends(identity)):
        return engine.create_task(body, principal)

    @app.post("/v1/decisions")
    async def decide(body: Action, principal=Depends(identity)):
        return await engine.decide(body, principal)

    @app.post("/v1/executions")
    def execute(body: ExecutionRequest, principal=Depends(identity)):
        return engine.execute(body.decision_id, body.envelope, principal)

    @app.get("/v1/executions/{execution_id}")
    def execution(execution_id: str, principal=Depends(identity)):
        return engine.execution(execution_id, principal)

    @app.get("/v1/authorizations/{decision_id}/execution")
    def execution_for_authorization(decision_id: str, principal=Depends(identity)):
        return engine.execution_for_authorization(decision_id, principal)

    @app.post("/v1/approvals/{approval_id}/resolve")
    def resolve(approval_id: str, body: Resolution, principal=Depends(reviewer)):
        return engine.resolve(approval_id, body, principal)

    @app.post("/v1/tasks/{task_id}/cancel")
    def cancel(task_id: str, principal=Depends(identity)):
        return engine.cancel(task_id, principal)

    @app.get("/v1/events")
    def events(
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
        principal=Depends(reviewer),
    ):
        items = engine.store.events(principal.tenant, after, limit)
        return {"events": items, "next_cursor": items[-1]["sequence"] if items else after}

    @app.get("/v1/events/export")
    def export(principal=Depends(reviewer)):
        with engine.store.transaction() as db:
            rows = db.execute(
                "SELECT event FROM events WHERE json_extract(event,'$.tenant')=? ORDER BY seq",
                (principal.tenant,),
            )
            content = "".join(row[0] + "\n" for row in rows)
        return Response(
            content,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="agentshield-audit.jsonl"'},
        )

    @app.post("/v1/demo")
    async def demo(body: DemoRequest, principal=Depends(reviewer)):
        if principal.role != "admin":
            raise ShieldError("DEMO_OPERATOR_REQUIRED", 403)
        return await run_demo(engine, body.scenario, reject=not body.leave_pending)

    @app.get("/v1/evaluation")
    def evaluation(principal=Depends(reviewer)):
        path = Path("output/evaluation.json")
        return (
            json.loads(path.read_text())
            if path.exists()
            else {"aggregates": [], "limitation": "Run make eval to generate the local report."}
        )

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
