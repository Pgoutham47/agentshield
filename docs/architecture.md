# Architecture decisions

Status: prototype implemented; production boundaries not yet implemented.

## ADR 001: A small transactional core before distributed services

Use Python 3.12, FastAPI, Pydantic 2, SQLite WAL locally or PostgreSQL for hosting, HTTPX, uv, and pytest. Serve the small console as same-origin HTML/CSS/ES modules. There is no frontend build toolchain and no external asset dependency.

The prototype brief explicitly permits a single Python process. The PRD's Go/Python/TypeScript, Cedar, EKS, S3, SQS, and PostgreSQL design is a production direction, not a prerequisite for testing the authorization invariant. The first deliverable benefits more from precise semantics, persistent state, and adversarial tests than from service count. This does not claim Python is faster or more secure than Go.

The console is a deliberate addition to the brief's CLI scope. It gives a reviewer access to the exact payload, reasons, expiry, and approval binding while retaining the CLI as the reproducible acceptance path.

## ADR 002: Explicit policy functions for the prototype

`policy.deterministic` implements identity-adjacent task validity, prohibitions, resource/issue scope, operations, destinations, canonical argument validation, and a limited secret-pattern check. `Engine.decide` performs transactional budget reservation, sensitive-file review, and optional contextual tightening. `Engine.execute` checks mutable restrictions again.

Cedar was not integrated or benchmarked; there is no pretend Cedar adapter. Before a policy-editing pilot, port these fixtures into Cedar contract tests and evaluate whether the engine can express the model without custom authorization prose. This is a deliberate D03 deviation, not a claim of a failed installation.

The brief's example includes `issue:412` as a selector even though the resources list contains only a repository. The implementation resolves that ambiguity with an explicit `issue_ids` contract field. A selector must match both the task and the actual arguments. It does not implicitly authorize every issue in a repository.

## ADR 003: Persistence before approval UX

The configured database is the source of truth. In local SQLite mode, `BEGIN IMMEDIATE` serializes reservations across connections. Task calls and proposed bytes are reserved once when a decision is created; denial and duplicate retries do not add reservations. Reserved call/byte charges are conservative and are not refunded after expiry or rejection. Execution concurrency is reserved at execution and released when the outcome is recorded. Response bytes are checked before committing mock effects.

Analysis happens outside the database transaction. The gateway rechecks identity, task state, policy, idempotency, and budgets after analysis. No transaction is held across a network await.

An execution uses two durable transactions: consume the grant and record execution intent, then check current state and atomically apply the mock effect with the outcome. A crash in between leaves a consumed grant and a recoverable unknown outcome. On exclusive SQLite startup, interrupted executions become `outcome_unknown`; no blind retry occurs. Real-provider atomicity is not implemented by these mock transactions.

Approval adds a new allow grant referencing an immutable original decision. Rejection never grants authority. The original held decision stays non-executable. A different envelope, expiry, resource version, requester, tenant, policy restriction, or consumed grant prevents execution.

The mock deliberately uses a repository-wide version. This causes conservative stale approvals after unrelated writes. The live connector uses issue hashes and commit SHAs; provider race windows are documented in the GitHub integration guide.

## ADR 004: Honest evidence and model boundaries

Audit events are appended in the same database transaction as state changes. A separate filesystem append would create a dual-write failure window, so JSONL is exported from a transactional outbox. Every event is sequenced and hash chained. Decision events include policy and detector versions. The database prevents update/delete through application SQL, but no signed external checkpoint exists.

The default analyzer is labelled `fixture-signals-v1`. It is a test double with obvious seeded indicators. AI-off runs make the baseline exposure visible. Live mode uses an explicitly configured model, no tools, a fixed system message, JSON data, a three-second total deadline, and strict output validation. Known secret indicators are redacted; the prototype does not claim complete redaction, private inference, or Bedrock residency.

## ADR 005: Free Render with Supabase persistence

Use one Render Free service for the same-origin API and console, with a Supabase Free PostgreSQL database. There is no persistent disk or paid model provider. SQLite remains a local default and is prohibited on Render. The free session pooler on port 5432 supplies IPv4 connectivity and supports session ownership; transaction pooling is refused. Free services can sleep/pause, so this pilot does not promise always-on availability.

The server database credential stays only in the backend environment. A private schema, enabled RLS, and revoked browser-role privileges keep this state out of Supabase's browser APIs. Fixed prototype identities remain; authenticated organization memberships are a separate release gate.

## Production trust boundary still required

The workload can currently call arbitrary network or shell tools outside this prototype. Strong enforcement requires a sandbox with no reusable provider credential, controlled egress, and an executor that owns the only provider access path. The real GitHub connector and in-process token broker are implemented. Broker isolation, sandboxing, and bypass verification remain release gates. The UI never labels those absent layers as enforced.

## ADR 006: Real GitHub with mandatory write review

The live adapter uses a server-configured repository, immutable task snapshots, typed REST operations, operation-scoped installation tokens, and no generic URL dispatch. Explicit CLI authentication is supported for a disposable local sandbox only. Every live mutation requires exact-action review regardless of analyzer results. The live executor reserves response bytes and a repository lock before I/O, consumes grants durably, and retains the lock for unknown outcomes. No database transaction spans network calls. See [integration semantics and race limits](github-integration.md).

## ADR 007: PostgreSQL transactions and execution ownership

Versioned SQL migrations preserve existing state semantics. A schema-scoped advisory transaction lock serializes short state mutations and audit sequencing; network requests run outside transactions. Dedicated session locks protect executions across provider calls. Recovery attempts the corresponding transaction lock and skips work with a live owner. Lost sessions fail closed, while abandoned durable intents become unknown without replay. A periodic sweep handles disconnected owners after startup. Repository reservations remain for unknown GitHub results.

The SQLite importer requires an offline source and empty target, validates the entire audit chain, and imports all tables in one transaction. It retains consumed grants and pending reviews. Cross-process crash, concurrency, import, and restart tests run against real PostgreSQL. This conservative locking model favors correctness over throughput; the managed Supabase session pooler and hosted redeploy persistence have also been verified in the synthetic pilot. High availability and production-scale behavior remain unverified.
