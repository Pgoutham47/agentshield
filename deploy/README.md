# Hosting handoff

Status: deployment source prepared; GitHub App registration and Render deployment require signed-in browser sessions. No App ID or installation ID has been created or invented.

## GitHub App

[Open the prefilled App registration form](https://github.com/settings/apps/new?name=AgentShield+Pgoutham47+Pilot&description=Task-bound+authorization+for+a+private+synthetic+coding-agent+pilot.&url=https%3A%2F%2Fgithub.com%2FPgoutham47%2Fagentshield&public=false&webhook_active=false&request_oauth_on_install=false&contents=write&issues=write&pull_requests=write&metadata=read). This uses GitHub's documented URL parameters. Review the form before creating it: private App, Contents/Issues/Pull requests read and write, Metadata read, webhooks disabled, no user OAuth flow. The same nonsecret definition is in `github-app.json`.

Create it under **Pgoutham47**, then install it on **only `agentshield-github-sandbox`**. Do not install this agent executor on its own deployment repository. Generate a private key and keep it outside Git, under a protected local folder or the hosting secret-file store. Record the App ID and installation ID; these identifiers are not credentials.

## Render

The deployment source is the private `Pgoutham47/agentshield` repository. Render's own GitHub connection needs read access to this source repository. This is separate from the AgentShield GitHub App, which operates only on the dummy sandbox.

Create a Blueprint using the repository's `render.yaml`. It selects Singapore, one 512 MB instance, one 1 GB persistent disk, and four generated role tokens. Current base cost is about **$7.25/month**, plus any applicable workspace fees, usage, and tax. Review the displayed charge before creating paid resources. No paid resources have been created by this task.

Supply the prompted variables:

- `AGENTSHIELD_GITHUB_REPOSITORY=Pgoutham47/agentshield-github-sandbox`
- `GITHUB_APP_ID`: the registered App's ID
- `GITHUB_INSTALLATION_ID`: the selected-repository installation's ID

Add a Render secret file named **`github-app.pem`**, containing the generated PEM. The service reads `/etc/secrets/github-app.pem`; neither the key nor local role tokens belong in this repository. A missing key intentionally prevents startup. If Blueprint creation does not expose secret-file configuration, add it in the new service's Environment settings before retrying its initial deploy.

The Blueprint initially sets `GITHUB_ENABLE_WRITES=false`. Keep it disabled until `GET /v1/integrations/github?verify=true` succeeds using the reviewer/operator token and the selected repository is correct. On Render, use `uv run --no-dev agentshield github-check` for the equivalent read-only check. Enable reviewed writes by changing `GITHUB_ENABLE_WRITES` to `"true"` in the Blueprint and deploying that reviewed configuration change; an ad hoc Dashboard override can be reset by a later Blueprint sync.

## Verify after deployment

1. Confirm `/health` and the console load over HTTPS. API calls without a bearer token must return 401.
2. Sign in with the generated operator token from Render settings. Verify the GitHub App connection and confirm that writes are disabled.
3. Run one mock scenario, record its task ID, restart the service, and confirm its task/audit history survives. Do not upload the local SQLite database.
4. After intentionally enabling sandbox writes, run the reviewed six-operation workflow against the disposable repository using gateway credentials. Check the draft PR, rejected exposure, and audit outcomes. Never give the agent the App PEM.
5. Keep one process and one instance. Supabase and multi-instance recovery are not implemented. Unknown remote outcomes require investigation; there is no automatic reconciliation.

The hosted pilot uses fixed local-style identities and synthetic workloads. SSO, customer enrollment, isolated runners, and controlled egress remain separate implementation work.

References: [GitHub App URL parameters](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-using-url-parameters), [Render Blueprint fields](https://render.com/docs/blueprint-spec), [Render pricing](https://render.com/pricing).
