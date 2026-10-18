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

Use `AGENTSHIELD_OPERATOR_TOKEN` from [Render Environment](https://dashboard.render.com/web/srv-dba7aolg1s2s73b2ai00/env) to enter the console. The browser used for verification is already signed in. Reviewer, developer, and worker tokens are separate; never give an agent the operator or reviewer token.

`DATABASE_URL` is stored in Render's secret environment. The App PEM is the secret file `github-app.pem`, read at `/etc/secrets/github-app.pem`. Neither belongs in Git or chat. Protected local copies of the PEM and gateway tokens are under the ignored `data/hosting/` directory for the operator's verification workflow. The database password was generated during project setup and is available inside Render's protected connection URI. Supabase API keys are not used for application database access. Optional user login uses the project publishable key only; see [Auth setup](../docs/authentication.md).

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

`render.yaml` is authoritative for nonsecret configuration and stays on `plan: free`. `GITHUB_ENABLE_WRITES=true` was enabled after successful read verification; exact-action approval remains mandatory for every GitHub mutation. To stop provider writes, change it to `false` in the Blueprint and deploy. Never widen the App installation to the deployment repository or unrelated projects.

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

## User login preparation

Supabase Auth support is implemented and tested. Activation requires the separate [AgentShield Sign In OAuth app](https://github.com/settings/applications/3943202) client secret, GitHub provider configuration in Supabase, and the four Auth environment values listed in [Auth setup](../docs/authentication.md). GitHub requested fresh account verification before it would generate the client secret. Do not enable the hosted login UI until the provider is configured and an end-to-end sign-in can be verified. The existing token console remains available meanwhile.
