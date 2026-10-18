# Supabase Auth: GitHub sign-in

This optional login uses the existing Supabase Free project and Render Free service. No SMTP, paid identity service, or model API is required. Keep free plans; stop at quotas rather than upgrading. Existing local token login and the four SDK bearer roles remain available when Auth is not configured.

## Provider setup

1. Create a separate **GitHub OAuth App** for sign-in. It is independent of the executor GitHub App and does not request repository access. Homepage: your HTTPS console origin. Callback: `https://PROJECT_REF.supabase.co/auth/v1/callback`.
2. Generate its client secret and enter the client ID and secret under Supabase → Authentication → Sign In / Providers → GitHub. Enable GitHub. Keep anonymous login and manual identity linking disabled. Never commit or paste the client secret into chat. GitHub may require human account verification before generating it.
3. Set Supabase Site URL to the exact console origin. Add `https://YOUR_HOST/auth/callback**` to redirect URLs. The suffix permits the random state query; do not wildcard the hostname. Enable new-user signup if personal demo accounts should be available.
4. Set all four environment values on Render together:

| Variable | Value |
| --- | --- |
| `SUPABASE_URL` | Project HTTPS origin |
| `SUPABASE_PUBLISHABLE_KEY` | Project publishable key; no service-role/secret key |
| `APP_BASE_URL` | Exact HTTPS console origin, without a path |
| `APP_SESSION_SECRET` | Stable random secret, at least 32 characters; generate with `secrets.token_urlsafe(48)` |
| `AGENTSHIELD_OWNER_GITHUB_ID` | Optional immutable numeric ID of the existing workspace owner |

The OAuth client secret belongs only in Supabase. Render needs only the publishable key. Maintain `APP_SESSION_SECRET` across deploys; rotating it intentionally invalidates browser sessions. No Auth secrets should enter Blueprint literals. Keep Uvicorn access logs disabled so callback authorization codes are not logged by the application. Infrastructure logging policies remain under the hosting providers' control.

For the current pilot, the owner GitHub ID is `140201744`; the Supabase project is `oanpbakftuafjikwkzzp` and the console origin is `https://agentshield-prototype.onrender.com`.

## Identity and authorization

A login uses PKCE, a random state, and a ten-minute encrypted HTTP-only flow cookie. The callback exchanges its one-use code on the backend and verifies the user with Supabase `/auth/v1/user`. The browser receives only an opaque, Secure, HTTP-only, SameSite=Lax session cookie. Provider access and refresh tokens are encrypted in the private `auth_sessions` table; their plaintext never reaches browser storage or application logs. Migration 2 adds this table without changing existing task/audit history.

Every authenticated request revalidates the identity with Supabase. Refresh rotation is serialized with session locks, with no database transaction held over provider I/O. Sessions expire after seven days; signing out deletes the local session immediately and attempts to revoke its Supabase refresh token. Supabase outages fail closed. Cookie-authenticated mutations require the configured Origin; bearer SDK requests remain independent.

Only the immutable GitHub provider identity matching the server's owner setting receives the existing `acme` workspace and configured live sandbox resource. Editable user metadata, email, and GitHub username cannot grant ownership. Other users receive a workspace derived from their verified Supabase UUID with demo entitlements; they can add their own repositories through [GitHub connections](repository-connections.md). Tasks, approvals, events, exports, and integration details are scoped to it. They may run synthetic demos but cannot use the owner's GitHub installation. Demo requesters/agents remain labelled fixture identities; actual human review records use the authenticated Supabase subject.

This is personal workspace enrollment; team invitations, enterprise SSO, and production RBAC remain future work. Do not widen owner entitlements to unrelated repositories. Never give SDK operator/reviewer tokens to ordinary users or agents.

## Verification

Run `uv run pytest -q` with `AGENTSHIELD_TEST_DATABASE_URL` pointing at a disposable PostgreSQL server to exercise SQLite and PostgreSQL. Auth tests cover the PKCE callback, CSRF, encrypted session persistence, owner mapping, metadata escalation, tenant isolation, token refresh, sign-out, tampering, expiry, and concurrent revocation. Provider requests are mocked in automated tests; a successful real GitHub sign-in is separately required before claiming hosted verification.

After deployment: sign in with GitHub, verify the correct workspace and existing history, sign out, and verify protected endpoints return 401. Repeat sign-in after redeploy. New-account isolation is covered by automated multi-user tests; do not create additional external accounts merely for testing.

References: [Supabase GitHub Auth](https://supabase.com/docs/guides/auth/social-login/auth-github), [PKCE flow](https://supabase.com/docs/guides/auth/sessions/pkce-flow).
