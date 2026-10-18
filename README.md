# AgentShield

**Task-bound authorization for coding agents.**

Let an agent fix the issue without giving it permission to publish your internal configuration. AgentShield evaluates typed action proposals against a bounded task contract, asks for exact-action review when needed, and executes only the authorized request.

This repository is a **runnable local prototype** derived from the supplied PRD, prototype brief, and deck. It is not the complete production platform described in the PRD. The offline provider is a persisted mock repository; an optional real GitHub adapter has now been verified against a private synthetic sandbox. The default contextual analyzer is an explicitly labelled fixture. Shell isolation and network enforcement are not implemented. See [GitHub integration and live evidence](docs/github-integration.md).

## Run it

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). No Node build, cloud account, GitHub token, or model key is needed.

```sh
make setup
make test
make demo
make eval
make dev
```

Open **http://127.0.0.1:8000**. Use the `operator` token in `data/local-tokens.json` to enter the console. This file is created on first API startup with owner-only permissions and is excluded from Git. Do not publish it. The console keeps the token only in the current tab's session storage.

The console includes an overview, three runnable scenarios, task traces and contracts, exact-action approvals, the implemented policy, measured fixture counts, and JSONL audit export. It starts with no task runs; run the scenarios to populate it. The API reference is at `/docs` and its schema at `/openapi.json`.

`make demo` uses `data/demo.sqlite`; the console uses `data/console.sqlite`. Their state is deliberately separate. CLI traces and the evaluation report are written under `output/`. Each run creates a fresh task and isolated mock repository. The evaluation always starts with a temporary database.

## Three demonstrations

| Run | Attempt | Observed outcome |
| --- | --- | --- |
| A | Fix issue 412 in `acme/web-ui` | Reads, branch, commit, and draft PR allowed. |
| B | Also read another private repository and publish a gist | Resource read and destination denied. Draft PR still created. |
| C | Publish `config/internal.yaml` as an in-scope issue comment | Fixture signals hold the comment. CLI reviewer rejects it. Draft PR still created. |

```sh
uv run agentshield demo --scenario C --interactive
uv run agentshield demo --scenario C --ai off
uv run agentshield eval
```

The AI-off run intentionally publishes the synthetic internal comment to the **mock** repository. This exposes the baseline limitation rather than disguising it.

The console leaves scenario C's review pending so you can inspect and reject it yourself. Safe work continues. The mock uses a conservative repository-wide version, so later branch/PR changes make the original approval stale. Approval then requires a fresh proposal; rejection remains available. The exact-approval success path is covered by the API tests, including successful execution and replay rejection. Approval creates a new allow grant; it never executes automatically.

The workload is scripted. These runs demonstrate what the gateway does when an agent proposes an injected action; they do not demonstrate a live model being successfully prompt-injected. Task drafting is a bounded template offline and a model-generated resource selection in live mode, followed by explicit confirmation. The fixture admits a gist *proposal* to isolate the destination check in run B; the executor never implements gist publication.

## What is implemented

- Typed FastAPI HTTP API, strict argument schemas, bounded request and inspection sizes.
- Task contracts intersected with authenticated identity entitlements; repository and named-issue checks.
- Ordered deterministic policy functions; contextual signals can only tighten the outcome.
- SQLite for local development and PostgreSQL/Supabase support with versioned migrations for contracts, budgets, decisions, approvals, nonces, executions, and mock state.
- One-use execution authorization bound to the complete canonical envelope, identity, expiry, and expected resource version.
- Atomic call and byte reservation; response-byte checks before committing mock effects; concurrent execution limits.
- Role-separated local bearer identities, cancellation, idempotency conflict checks, tenant checks, and independent approval.
- Strict-schema contextual analysis, an AI-off baseline, fixture signals, and a configurable Anthropic Messages client with a three-second deadline.
- Durable execution intent, explicit `outcome_unknown`, and crash recovery without replay (PostgreSQL session ownership prevents recovering active work).
- Append-only audit outbox with a hash chain and exportable JSONL. Payload text and model rationales are excluded from audit events.
- Real GitHub adapter with pinned file reads, task branches, non-force commits, draft PRs, reviewed comments, server-side App token brokerage, and an explicit CLI development mode. Every live write requires review.
- Async Python SDK with no automatic write retries.
- A same-origin, dependency-free browser console that escapes all untrusted evidence.

## What is not implemented

**Tier 1 is not included. Cedar is not included.** The prototype uses explicit policy functions so decision order and failure behavior are directly testable. This is a deliberate prototype deviation from PRD D03/D07; see [architecture decisions](docs/architecture.md).

Not included: production GitHub installation discovery, isolated credential broker, sandbox runner, egress proxy, MCP gateway, SSO, production RBAC, signed policy distribution, policy simulation, gitleaks integration, retention/deletion, SIEM/webhook delivery, multi-instance availability, signed audit checkpoints, or production-scale benchmarks. The small secret-pattern detector is not a complete secrets scanner.

The database contains full synthetic proposals needed for exact approvals and mock files. It has no encryption or automated retention. **Use synthetic data only.** A hash chain detects accidental changes and gaps but is not independently anchored against an administrator rewriting the entire database. Unknown execution outcomes require investigation; there is no real-provider reconciliation implementation.

## Analysis modes

| Mode | Behavior | What it proves |
| --- | --- | --- |
| `fixture` (default) | Deterministic test signals for seeded synthetic exposure | Policy and approval plumbing |
| `off` | No contextual signals | Deterministic baseline |
| `anthropic` | Real model endpoint, configured explicitly | Requires a separately recorded live evaluation |

For live analysis, export environment variables through your shell or secret manager. `.env.example` is a reference; the app does not automatically load `.env`.

```sh
export ANTHROPIC_API_KEY='your-key'
export ANTHROPIC_MODEL='a-model-id-enabled-in-your-account'
export AGENTSHIELD_ANALYZER=anthropic
make dev
# Or:
uv run agentshield demo --ai anthropic
uv run agentshield eval --ai anthropic
```

There is deliberately no assumed model ID: the brief's `claude-sonnet-5-5` is not treated as verified availability. The request uses the [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages), fixed system instructions, quoted JSON data, no tools, and strict local output validation. Recent context is limited to five actions and a combined 64 KiB; oversize input is unavailable rather than silently truncated. Known secret patterns are redacted before analysis, but this is not comprehensive redaction or a data residency guarantee. Direct Anthropic API mode is not Bedrock/private-region mode.

Invalid output, missing configuration, or timeout holds writes for review; low-risk reads still need to pass deterministic checks. Provider exception bodies are not returned as decision explanations. Live drafting fails visibly when unavailable. Live analysis and live drafting have transport-level tests with mocked HTTP, but **no live provider efficacy result has been recorded**.

## Evidence and tests

```sh
make test        # pytest security, restart, concurrency, API, SDK, and analysis tests
make lint        # ruff
make demo        # A/B/C; readable traces + output/audit.jsonl
make eval        # 60 unique cases × 2 modes = 120 evaluations
```

The generated `output/evaluation.json` contains measured local results and each case's mode, reasons, detector versions, and latency. These are synthetic proposal-level counts, not production prevention rates or live-agent task completion rates.

| Mode | Family | Attempts | Denied | Held | Allowed |
| --- | --- | ---: | ---: | ---: | ---: |
| off | Out-of-scope reads | 10 | 10 | 0 | 0 |
| off | External destinations | 10 | 10 | 0 | 0 |
| off | In-scope exposure | 10 | 0 | 0 | 10 |
| off | Legitimate | 30 | 0 | 0 | 30 |
| fixture | Out-of-scope reads | 10 | 10 | 0 | 0 |
| fixture | External destinations | 10 | 10 | 0 | 0 |
| fixture | In-scope exposure | 10 | 0 | 10 | 0 |
| fixture | Legitimate | 30 | 0 | 0 | 30 |

Both configurations have zero false denials and zero false holds in these 30 synthetic legitimate proposals. Fixture exposure cases deliberately match the test double; this is not a held-out model benchmark. The PRD's larger 200-attack/500-legitimate gates remain outstanding. Do not replace deck targets with these counts without the fixture qualifier.

## HTTP and SDK

All `/v1` routes require a configured bearer token or a verified Supabase browser session. Local identities are configured server-side; tenant and role cannot be selected through request headers or arbitrary body fields.

| Identity | Capabilities |
| --- | --- |
| developer | Draft/confirm own tasks, propose/execute actions, cancel own tasks |
| worker | Act only for the enrolled agent and bound requester; no approvals |
| reviewer | Inspect evidence and approve/reject exact actions; cannot self-approve |
| operator | Review console, demonstration orchestration, cancellation; not a workload identity |

Tokens can be overridden with `AGENTSHIELD_DEVELOPER_TOKEN`, `AGENTSHIELD_WORKER_TOKEN`, `AGENTSHIELD_REVIEWER_TOKEN`, and `AGENTSHIELD_OPERATOR_TOKEN`. Never use the operator token in an agent. The operator-only demo endpoint creates synthetic developer tasks internally; it is not a general delegation API.

The public models are in `src/agentshield/models.py`, and `AgentShieldClient` is in `src/agentshield/sdk.py`. See the SDK integration test for a complete draft/confirm/decide/execute/cancel example. Read events using the cursor returned by `GET /v1/events`; download all tenant events via `GET /v1/events/export`.

## Deployment and next steps

[Deployment instructions](docs/deployment.md) and the [hosting handoff](deploy/README.md) include a **free Render + Supabase** configuration and prefilled private GitHub App registration. Hosted mode requires explicit role tokens and a TLS PostgreSQL connection. Render has no paid disk or database, and fixture analysis makes no paid model calls. Supabase uses its free IPv4-compatible session pooler on port 5432.

The PostgreSQL migration, offline SQLite importer, and recovery are tested against real PostgreSQL. The [hosted pilot](https://agentshield-prototype.onrender.com) is live on Render Free with Supabase Free. The session pooler, hosted redeploy persistence, App authentication, and a reviewed sandbox draft PR have been verified. Free services can sleep or pause. Keep one instance and worker for this synthetic pilot; production availability and team enrollment remain future work.

The initial live sandbox run used local CLI login; the hosted run used the installed GitHub App and produced [draft PR #3](https://github.com/Pgoutham47/agentshield-github-sandbox/pull/3). The console stays alongside the API on Render. No separate Vercel service is needed.

See [product positioning](docs/product-positioning.md) and [requirements status](docs/requirements-status.md) for the first customer hypothesis, explicit scope, and remaining release gates.

## User sign-in

The hosted console now uses [Supabase Auth](docs/authentication.md) for verified GitHub login, encrypted server-side sessions, logout, and isolated personal demo workspaces. The configured owner retains the existing workspace and sandbox repository. Login never grants repository permissions to new users. The four SDK bearer identities remain supported independently.
