# Hosting handoff

Status: deployment source prepared; GitHub App registration and Render deployment require signed-in browser sessions. No App ID or installation ID has been created or invented.

## GitHub App

[Open the prefilled App registration form](https://github.com/settings/apps/new?name=AgentShield+Pgoutham47+Pilot&description=Task-bound+authorization+for+a+private+synthetic+coding-agent+pilot.&url=https%3A%2F%2Fgithub.com%2FPgoutham47%2Fagentshield&public=false&webhook_active=false&request_oauth_on_install=false&contents=write&issues=write&pull_requests=write&metadata=read). This uses GitHub's documented URL parameters. Review the form before creating it: private App, Contents/Issues/Pull requests read and write, Metadata read, webhooks disabled, no user OAuth flow. The same nonsecret definition is in `github-app.json`.

Create it under **Pgoutham47**, then install it on **only `agentshield-github-sandbox`**. Do not install this agent executor on its own deployment repository. Generate a private key and keep it outside Git, under a protected local folder or the hosting secret-file store. Record the App ID and installation ID; these identifiers are not credentials.

## Supabase Free

Sign in to Supabase, select an organization on the **Free** plan, and create a free project in Singapore if a free project slot is available. Do not purchase compute, IPv4, backups, or plan upgrades. Keep the generated database password in a password manager/server secret store.

From the project's Connect dialog, select the **session pooler (5432)** and copy its PostgreSQL URI into Render's `DATABASE_URL` secret. URL-encode reserved password characters and include `?sslmode=require`. Transaction pooling (6543) is incompatible with the execution locks. Use the database connection URI, not the Supabase API URL or anonymous key.

The app creates a private `agentshield` schema with RLS and no browser-role grants. Keep it out of exposed API schemas. See [database design and offline import](../docs/deployment.md) to preserve the existing local history before the first hosted run.

## Render Free

The private deployment source is `Pgoutham47/agentshield`. Render's GitHub connection needs access to this repository; it is separate from the executor App installed on the sandbox.

Create a Blueprint from `render.yaml`. Confirm **Free**, one Singapore instance, **no disk**, and no paid database/service/add-on. Supply `DATABASE_URL` securely. Four role tokens are generated. The initial service starts without GitHub App credentials, with fixture analysis and writes disabled. There are no paid model calls. Do not proceed if the dashboard requires a paid resource.

To connect the GitHub App after registration, add these environment settings:

- `AGENTSHIELD_GITHUB_REPOSITORY=Pgoutham47/agentshield-github-sandbox`
- `GITHUB_APP_ID`: registered App ID
- `GITHUB_INSTALLATION_ID`: selected-repository installation ID
- `GITHUB_PRIVATE_KEY_PATH=/etc/secrets/github-app.pem`

Add the PEM as a Render secret file named `github-app.pem`. Keep `GITHUB_AUTH_MODE=app` and `GITHUB_ENABLE_WRITES=false` until the reviewer/operator's `GET /v1/integrations/github?verify=true` succeeds and the selected repository is correct. Do not put the private key or role tokens in Git or chat. A configured App with a missing key intentionally prevents startup.

Enable sandbox writes only after verification by changing the Blueprint's `GITHUB_ENABLE_WRITES` to `"true"` and deploying that reviewed configuration change. A Dashboard override may be reset by Blueprint sync. Exact-action review remains mandatory for each write.

## Verify after deployment

1. Confirm HTTPS console and `/health`, including `storage: postgresql`. API calls without a bearer token must return 401.
2. Sign in with Render's generated operator token. Run a mock scenario, record its task ID, restart/redeploy, and verify task/audit history survives.
3. Verify GitHub App read access with writes disabled. After enabling reviewed sandbox writes, exercise the six-operation flow and inspect the resulting draft PR and audit.
4. Confirm the account billing pages still show free resources. Free Render sleeps after inactivity; Supabase may pause an inactive free project. Do not create keep-alive traffic or silently upgrade to bypass limits.
5. Keep one instance/worker. Unknown remote outcomes require investigation, not automatic retry.

Current status: PostgreSQL migration and local real-database tests completed; cloud resources and App registration are awaiting account sign-ins. No cloud deployment or Supabase pooler verification is claimed.

References: [GitHub App URL parameters](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-using-url-parameters), [Render Blueprint fields](https://render.com/docs/blueprint-spec), [Render Free](https://render.com/docs/free), [Supabase Free](https://supabase.com/pricing).
