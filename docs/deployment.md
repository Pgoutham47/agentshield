# Deployment

## Local prototype

```sh
make setup
make test
make eval
make dev
```

Open http://127.0.0.1:8000 using the operator token in `data/local-tokens.json`. Without `DATABASE_URL`, local development uses SQLite. Hosted Render deliberately requires PostgreSQL and explicit role tokens; it cannot silently fall back to ephemeral SQLite or local credentials.

## Free Render + Supabase pilot

The [hosting handoff](../deploy/README.md) describes account setup and deployment. `render.yaml` selects **Render Free**, one instance, one worker, no disk, and fixture analysis with no paid model calls. Durable state lives in a **Supabase Free** PostgreSQL project. No paid services or add-ons are authorized.

The PostgreSQL implementation has real database tests for reservations, replay prevention, pending approvals, audit integrity, restart persistence, separate-process execution ownership, and crash recovery. The hosted pilot is now verified on Render Free, Supabase's managed session pooler, and installed GitHub App authentication. A task and pending approval survived redeployment; the hosted API produced sandbox draft PR #3. See the handoff for resource links and exact evidence.

Use the Supabase **session pooler on port 5432** with `sslmode=require` (or certificate verification). This provides IPv4 connectivity without purchasing the IPv4 add-on. Do not use the transaction pooler on port 6543: execution ownership requires session advisory locks. Store the database URI in Render's secret environment as `DATABASE_URL`; encode reserved password characters. Never put it in frontend code, source control, chat, or agent credentials.

Startup applies versioned SQL migrations to the private `agentshield` schema. `AGENTSHIELD_DB_SCHEMA` can select another private schema. Tables have RLS enabled and no anonymous/authenticated browser policies; schema/table/sequence/function privileges are revoked from PUBLIC and Supabase's browser roles. The backend database owner can access the schema. Do not add it to Supabase's exposed API schemas. The Supabase publishable key used for optional Auth is not a database credential; application data remains server-side.

The store serializes short state transactions with an advisory transaction lock. Each execution also holds a dedicated session lock across provider calls; no database transaction spans network I/O. Startup and periodic recovery skip live execution owners, then mark abandoned intent `outcome_unknown` without replay. A lost execution session fails closed. Unknown GitHub outcomes retain their repository reservation for investigation. This conservative pilot design is not a throughput or high-availability claim.

Render Free sleeps after inactivity and uses ephemeral files. Supabase Free has database/project limits and can pause inactive projects. This is a demo/pilot deployment, not an always-on production service. If a quota prevents creation, stop; do not upgrade automatically. See [Render Free limits](https://render.com/docs/free), [Supabase pricing](https://supabase.com/pricing), and [connection modes](https://supabase.com/docs/guides/database/connecting-to-postgres).

## Import existing SQLite history

The offline importer preserves contracts, decisions, pending approvals, consumed grants, executions, repository reservations, mock contents, and the complete audit chain. It requires an empty destination schema and rejects an invalid audit chain or still-executing source records. All data copying commits atomically; the source is opened read-only.

1. Stop every process using the source SQLite database. Recover interrupted executions with the old engine first if necessary, then stop it again.
2. Make a SQLite backup and retain it for rollback. Do not migrate a database being changed by another process.
3. Set the destination `DATABASE_URL` securely in the process environment. Run:

```sh
uv run agentshield db-import --sqlite data/console.sqlite --source-stopped
uv run agentshield db-check
```

4. Start only the PostgreSQL-backed service. Check existing tasks, pending approvals, and exported audit before enabling writes. The flag confirms an operator precondition; it does not stop source processes for you.

Do not resume the old SQLite writer after accepting new PostgreSQL writes: the histories would diverge. Re-running the importer against a populated target is rejected. This is not a bidirectional synchronization tool.

## Validation and remaining scope

CI runs the suite against SQLite and a real PostgreSQL 17 service. For a dedicated local test database, export `AGENTSHIELD_TEST_DATABASE_URL` and run `uv run pytest -q`; tests create and drop isolated schemas. Without it, PostgreSQL-specific cases are skipped. Never point tests at customer data.

Run one hosted instance and worker for this pilot. Legacy SDK identities, synthetic workloads, and mandatory GitHub write reviews remain. Optional GitHub user login is described in [Auth setup](authentication.md). Enterprise SSO, team enrollment, isolated runners, controlled egress, provider reconciliation, retention, and production capacity work are still outstanding.

A separate Vercel frontend is unnecessary for this pilot: Render serves the console and API on the same origin. Keep fixture analysis enabled to avoid paid inference. Optional live model code exists but is not part of this free deployment.
