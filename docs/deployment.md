# Deployment

## Local prototype (verified)

```sh
make setup
make test
make eval
make dev
```

Use http://127.0.0.1:8000 and the operator token in `data/local-tokens.json`. The default bind address is loopback. Synthetic state persists across restarts. No external accounts are required.

## Render pilot (prepared; account setup pending)

Use the [deployment handoff](../deploy/README.md) for the prefilled GitHub App registration, selected-repository installation, exact Render variables, PEM secret-file setup, current estimated cost, and post-deploy verification. The private deployment source is `Pgoutham47/agentshield`; the executor App must be installed only on `Pgoutham47/agentshield-github-sandbox`.

`render.yaml` selects Singapore, a 512 MB service, a 1 GB persistent disk, and four generated tokens. The service starts with GitHub writes disabled. In hosted mode the application rejects missing/duplicate/short role tokens, local CLI GitHub authentication, missing App key files, and state paths outside Render's persistent `/var/data` disk. It never creates fallback local login tokens in hosted mode. Builds and automatic deploys use the checked-in source and passing CI.

Run exactly one instance and one Uvicorn worker. Startup recovery assumes exclusive ownership of the database. The pilot remains synthetic-workload only: real customer authentication, broker isolation, and production tenancy are unfinished. No paid Render service has been created or verified yet.

## Supabase PostgreSQL (next implementation)

The current store uses SQLite SQL and JSON functions. Setting `DATABASE_URL` alone will not enable Supabase; no such unsupported switch is provided.

Before a shared pilot:

- Introduce PostgreSQL migrations and transactions for tasks, reservations, approvals, grants, executions, and the event outbox.
- Replace the single-process startup sweep with worker ownership and leases; preserve nonce consumption and outcome-unknown recovery.
- Re-run concurrency tests across separate processes/instances, including cancellation/approval races and interrupted execution recovery.
- Add authenticated tenant memberships, per-resource authority, and database-level isolation checks.
- Select a supported database connection mode for the Render service and configure TLS using [Supabase's connection guidance](https://supabase.com/docs/guides/database/connecting-to-postgres).
- Keep backend database credentials out of browser code and workload agent environments.

## Vercel frontend (optional later)

A separate console could be hosted on Vercel after introducing a frontend build and an authenticated API session design. The current console is intentionally same-origin, with bearer tokens and no permissive CORS. Do not move it to another origin and enable wildcard CORS as a shortcut. Keep the stateful gateway on a suitable backend host.

## Live evaluator configuration

Configure `ANTHROPIC_API_KEY`, an enabled `ANTHROPIC_MODEL`, and `AGENTSHIELD_ANALYZER=anthropic` only after agreeing on data handling. Live calls use the direct Anthropic endpoint; in-region Bedrock and private inference remain unimplemented. Timeouts are three seconds and cause writes to be held. The prototype never silently swaps from unavailable live analysis to fixture signals.
