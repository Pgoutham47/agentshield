# Connect your GitHub repositories

Sign in, open **Integrations**, and choose **Install or manage App**. On GitHub choose **Only select repositories**, then return to AgentShield. Choose **Authorize GitHub** using the same account as your login. Select an account installation and **Connect repository**. Enter an issue number and choose **Read issue** to verify access without changing the repository. Organization installations may need an organization owner's approval.

Each personal workspace can connect up to 20 repositories. Discovery is paginated in groups of 20. Installation alone does not connect repositories to a workspace. The existing owner's server-configured sandbox is a separate integration, shown in its own section.

## Operator configuration

This feature uses the existing executor GitHub App, separate from the Supabase sign-in OAuth App. Keep Render and Supabase on Free and fixture analysis enabled; no additional service is required.

1. Make the GitHub App public so other accounts can install it. Keep only Contents, Issues, and Pull requests read/write plus Metadata read. Webhooks are not required.
2. Set its exact OAuth callback to `https://YOUR_HOST/github/callback` and setup URL to `https://YOUR_HOST/github/setup`. Enable redirect on installation updates; leave wildcard callbacks and automatic OAuth during installation disabled.
3. Set `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, and `GITHUB_APP_SLUG` together in Render, alongside the existing `GITHUB_APP_ID` and Supabase Auth settings. Use the executor App's credentials, not the sign-in OAuth App's credentials. Store the secret only in the environment. `GITHUB_ENABLE_WRITES=false` disables writes for connected repositories too.
4. Deploy. Migration 3 creates private, RLS-enabled account, repository selection, and authorization-flow tables. Keep the stable `APP_SESSION_SECRET`: it encrypts connection credentials as well as login sessions.

The pilot uses public App `agentshield-pgoutham47-pilot`, App ID `5366143`, and client ID `Iv23lirRXDuCYo785NT9`. Its callback and setup URLs use `https://agentshield-prototype.onrender.com`.

## Access boundary

Authorization uses one-use, session-bound state and PKCE. The backend checks that the App-authorized immutable GitHub identity matches the signed-in user, then discovers installations and repositories directly from GitHub. Forged installation callback parameters never grant access. User access/refresh tokens are encrypted server-side and absent from browser storage and API responses.

Connected repository calls use a GitHub App **user access token**, so GitHub enforces the intersection of the user's permissions and the App's permissions and installations. Tokens refresh under a workspace lock; revocation/provider failure fails closed. Each adapter session rechecks the current installation and repository membership, including public repositories, as well as the immutable repository ID and current name. Rename/transfer requires disconnecting and selecting the repository again. Exact-action review remains mandatory for live writes, and the operator's writes switch still applies.

A disconnect removes workspace selections or credentials immediately. A request already submitted to GitHub may finish. Disconnecting does not uninstall an App shared with other users; use GitHub's authorized Apps settings to revoke provider access. Reconnecting creates a new connection ID: old task contracts cannot silently resume with new authority. Existing history remains stored; disconnected resource history becomes inaccessible to the user's current entitlements until that resource is connected again, while old tasks still cannot execute.

This delivers personal repository connection, issue verification, and tenant-scoped task adapter routing. Personal agent credential issuance, team invitations, and a live-run creation wizard remain separate work. Do not share the legacy owner SDK tokens with new users. Preview reads are connection checks, not task executions or task audit events.

## Validation

`tests/test_connections.py` runs against SQLite and PostgreSQL and covers PKCE/state/session binding, wrong GitHub identity, CSRF, encrypted credentials, forged/suspended/foreign App selections, cross-workspace reads/deletes, refresh serialization, disconnect during authorization, repository revocation/identity change, and task connection pinning. Provider calls are mocked; hosted browser verification is recorded separately in the deployment handoff.

GitHub reference: [Generating a user access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app).
