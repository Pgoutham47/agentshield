# Hosted pilot handoff

Status: deployed and verified on 18 October 2026. All resources created for this pilot use free plans. No paid disk, IPv4 add-on, database, or model service was purchased.

| Resource | Configuration |
| --- | --- |
| Product | [AgentShield](https://agentshield-prototype.onrender.com) |
| Render service | `srv-dba7aolg1s2s73b2ai00`, Free, Singapore, one worker, no disk |
| Render Blueprint | `agentshield-free`, `exs-dba79t3rjlhs7396daf0` |
| Source | [Pgoutham47/agentshield](https://github.com/Pgoutham47/agentshield), `main` |
| Supabase | [AgentShield](https://supabase.com/dashboard/project/oanpbakftuafjikwkzzp), Free, Singapore, project `oanpbakftuafjikwkzzp` |
| Database | Private `agentshield` schema; TLS session pooler on port 5432 |
| GitHub App | [AgentShield Pgoutham47 Pilot](https://github.com/settings/apps/agentshield-pgoutham47-pilot), App ID `5366143` |
| Installation | `172622857`, only `Pgoutham47/agentshield-github-sandbox` |

## Access and credentials

Open the console and choose **Continue with GitHub**. Supabase Auth signs users in; GitHub user ID `140201744` opens the existing owner workspace. New users receive isolated personal workspaces and can connect their own repositories through Integrations. Legacy developer, worker, reviewer, and operator tokens remain for the SDK/API; never give an agent the operator or reviewer token.

`DATABASE_URL` is stored in Render's secret environment. The App PEM is the secret file `github-app.pem`, read at `/etc/secrets/github-app.pem`. Neither belongs in Git or chat. Protected local copies of the PEM and gateway tokens are under the ignored `data/hosting/` directory for the operator's verification workflow. The database password was generated during project setup and is available inside Render's protected connection URI. Supabase API keys are not used for application database access. User login uses the project publishable key only; see [Auth setup](../docs/authentication.md).

The Supabase Data API was disabled at project creation. Application migrations enable RLS and revoke browser-role privileges on the private schema. Do not expose this schema through browser APIs.

## Verified behavior

- HTTPS console and PostgreSQL health check respond successfully; unauthenticated API calls return 401.
- A mock task and its pending approval survived a hosted redeploy.
- Hosted GitHub App verification resolves only the configured sandbox repository.
- Hosted task `t_a3295109dbd64a7e` read the issue/files, rejected internal-configuration publication, denied a different-repository read, rejected grant replay, and created a reviewed branch, commit, and [draft PR #3](https://github.com/Pgoutham47/agentshield-github-sandbox/pull/3).
- Both Node regression checks passed against the exact draft PR commit.
- The exported 72-event audit chain verified after this run. Evidence is saved locally in `output/hosted-verification.json` and its adjacent audit export.

Proposals, contextual signals, and reviews in this verification were scripted synthetic fixtures. This is integration evidence, not a live-model detection benchmark. The PR is unmerged, and no issue comment was published by this hosted verification.

The initial cloud history is fresh; older SQLite demonstration history remains local and was not overwritten. The offline importer requires an empty destination and cannot merge those histories into this populated cloud database.

## Operating the pilot

`render.yaml` is authoritative for nonsecret configuration and stays on `plan: free`. `GITHUB_ENABLE_WRITES=true` was enabled after successful read verification; exact-action approval remains mandatory for every GitHub mutation. To stop provider writes, change it to `false` in the Blueprint and deploy. Keep the owner pilot installation restricted to its sandbox. Users choose repositories for their own installations; do not add the deployment repository during testing.

To rerun the hosted verification, use a protected JSON token file with `developer`, `worker`, and `reviewer` fields:

```sh
uv run python scripts/verify_hosted.py \
  --url https://agentshield-prototype.onrender.com \
  --tokens data/hosting/render-tokens.json \
  --approve-sandbox-writes
```

Each invocation creates another branch, commit, and draft PR. It never merges or automatically retries writes. After an unknown outcome, investigate the saved trace and remote state before any further attempt.

Free Render sleeps with inactivity, and free Supabase projects can pause. Stay within free quotas; do not upgrade or buy add-ons to resolve a limit. No always-on or high-availability guarantee is made. Keep one instance/worker and synthetic workloads.

## Recreating the deployment

Do not create duplicates of the running resources. If recovery requires a new project, select Supabase Free in Singapore and use its **session pooler on 5432** with `sslmode=require`; never buy the IPv4 add-on. Passwords with reserved characters must be URL-encoded. Transaction pooling on 6543 is unsupported by execution session locks.

In Render choose **New → Blueprint**, select the deployment repository and `main`, supply `DATABASE_URL`, and confirm Free with no disk or additional database. The current Blueprint includes App identifiers: add the matching PEM secret file before expecting startup to succeed, or prepare a bootstrap configuration without GitHub variables and with writes disabled. Render generates four role tokens. Restore/import the intended database before accepting new writes, following [the offline import procedure](../docs/deployment.md).

References: [Render Free](https://render.com/docs/free), [Blueprint fields](https://render.com/docs/blueprint-spec), [Supabase connection modes](https://supabase.com/docs/guides/database/connecting-to-postgres).

## User login verification

GitHub sign-in through Supabase Auth is enabled and verified on the hosted console. The separate [AgentShield Sign In OAuth app](https://github.com/settings/applications/3943202) requests read-only email identity access; it has no repository scopes. Its client secret is stored only in Supabase. Render holds the project publishable key and stable `APP_SESSION_SECRET`, with private local recovery configuration under ignored `data/hosting/supabase-auth.env`.

Live checks confirmed owner mapping, both original tasks, one pending approval, all 72 existing audit events, and sandbox GitHub read verification. Signing out returned the login screen and protected endpoints returned 401. Signing in again restored the owner workspace. Browser local/session storage contains no authentication tokens and JavaScript cannot read the session cookie. Automated SQLite/PostgreSQL tests cover new-user isolation, forgery, expiry, refresh rotation, and concurrent logout; no additional external GitHub account was created for testing.

The full implementation suite passed 167 tests in CI. See [Auth setup](../docs/authentication.md) for session behavior, configuration, and remaining team/installation scope.


## User repository connections (2026-10-18)

The executor GitHub App is public so other accounts can install it. Its exact callback is `/github/callback`, its setup return is `/github/setup`, and user access tokens expire after eight hours with refresh enabled. Render stores the App OAuth client secret separately from the Supabase sign-in OAuth credentials. All services remain on Free; no paid infrastructure or model calls were added.

Implementation commit `638cd8b` passed all 179 SQLite/PostgreSQL tests in [CI](https://github.com/Pgoutham47/agentshield/actions/runs/39140675047) and deployed successfully as `dep-dbaec0p42hec73dh4sqg`.

Hosted browser checks verified GitHub App authorization, installation/repository discovery, connecting the sandbox, and reading issue #1. Disconnecting the selected repository made its preview endpoint return 404. Disconnecting the whole account cleared authorization and selections. Reauthorization and repository selection worked again. These checks made no repository changes. New-account isolation, revoked permissions, public repository removal, and stale task connection IDs are covered by automated tests; an additional external account was not created.

See [repository connections](../docs/repository-connections.md) for user steps, environment setup, token handling, and remaining personal-agent onboarding scope. No additional keys or account access are needed from the owner for the current setup.
