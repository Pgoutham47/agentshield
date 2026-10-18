import argparse
import asyncio
import json
import os
from pathlib import Path

from .analyzer import Analyzer
from .demo import run_demo
from .engine import Engine
from .evaluation import evaluate


def main():
    parser = argparse.ArgumentParser(description="AgentShield · task-bound authorization")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--scenario", choices=["A", "B", "C", "all"], default="all")
    demo.add_argument("--ai", choices=["off", "fixture", "anthropic"], default="fixture")
    demo.add_argument("--interactive", action="store_true")
    demo.add_argument("--db", default="data/demo.sqlite")
    ev = commands.add_parser("eval")
    ev.add_argument("--ai", choices=["fixture", "anthropic"], default="fixture")
    live = commands.add_parser(
        "github-demo", help="Run real writes against an explicitly authorized disposable sandbox"
    )
    live.add_argument("--issue", type=int, default=1)
    live.add_argument("--db", default="data/console.sqlite")
    live.add_argument("--output", default="output/github-verification.json")
    live.add_argument("--approve-sandbox-writes", action="store_true")
    commands.add_parser("github-check", help="Verify the configured repository with read-only GitHub calls")
    commands.add_parser("db-check", help="Verify PostgreSQL schema and audit without printing credentials")
    migration = commands.add_parser(
        "db-import", help="Import an offline SQLite snapshot into empty PostgreSQL"
    )
    migration.add_argument("--sqlite", required=True)
    migration.add_argument("--source-stopped", action="store_true")
    commands.add_parser("serve")
    args = parser.parse_args()
    if args.command == "serve":
        import uvicorn

        uvicorn.run("agentshield.api:app", host="127.0.0.1", port=8000)
    elif args.command in {"db-check", "db-import"}:
        from .postgres import PostgresStore

        url = os.getenv("DATABASE_URL")
        if not url:
            parser.error("Set DATABASE_URL securely in the server environment")
        if args.command == "db-import":
            from .migrate import import_sqlite

            result = import_sqlite(args.sqlite, url, source_stopped=args.source_stopped)
        else:
            store = PostgresStore(url)
            result = {"backend": store.backend, "schema_version": 3, "audit_valid": store.verify()}
        print(json.dumps(result, indent=2))
    elif args.command == "github-check":
        from .github import GitHubAdapter, GitHubSettings

        settings = GitHubSettings.from_env()
        if not settings:
            parser.error("AGENTSHIELD_GITHUB_REPOSITORY is required")
        print(json.dumps(GitHubAdapter(settings).status(verify=True), indent=2))
    elif args.command == "github-demo":
        from .github_demo import run_github_demo

        asyncio.run(run_github_demo(args.db, args.issue, args.output, args.approve_sandbox_writes))
    elif args.command == "demo":
        engine = Engine(args.db, Analyzer(args.ai))
        print(f"MOCK GITHUB · {args.ai.upper()} ANALYSIS · SCRIPTED PROPOSALS")
        for scenario in "ABC" if args.scenario == "all" else args.scenario:
            result = asyncio.run(
                run_demo(engine, scenario, reject=not args.interactive, prompt=args.interactive)
            )
            print(f"\nRun {scenario} / {result['task_id']}")
            for step in result["trace"]:
                d = step["decision"]
                print(f"  {d['disposition']:18} {step['operation']:18} {','.join(d['reason_codes'])}")
            print(
                f"  Outcome: {result['draft_prs']} draft PR; {result['published_comments']} published comments"
            )
            path = f"output/demo-{scenario}.json"
            Path(path).parent.mkdir(exist_ok=True)
            Path(path).write_text(json.dumps(result, indent=2))
        engine.store.export("acme", "output/audit.jsonl")
        print("\nAudit exported to output/audit.jsonl; chain valid:", engine.store.verify())
    else:
        report = asyncio.run(evaluate(("off", args.ai)))
        print(report["limitation"])
        print(
            f"\n{'Mode':12} {'Family':24} {'Attempts':>8} {'Deny':>6} {'Held':>6} {'Allow':>6} {'False deny':>10} {'False hold':>10}"
        )
        for row in report["aggregates"]:
            print(
                f"{row['mode']:12} {row['family']:24} {row['attempts']:8} {row['denied']:6} {row['held']:6} {row['allowed']:6} {row['false_denials']:10} {row['false_holds']:10}"
            )
        print("\nReport: output/evaluation.json")
