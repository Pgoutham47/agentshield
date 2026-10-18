# GitHub integration pilot

AgentShield can now execute six typed operations against one configured GitHub Cloud repository: read the named issue, read a UTF-8 file at a pinned commit, create an `agent/` branch, commit reviewed file contents, open a draft PR, and comment on the named issue. Every live write requires approval of its exact payload, even with contextual analysis disabled. The original mock demonstrations remain available.

## Verified sandbox

On 18 October 2026 the integration ran against the private [sandbox repository](https://github.com/Pgoutham47/agentshield-github-sandbox). [Issue #1](https://github.com/Pgoutham47/agentshield-github-sandbox/issues/1) contains a synthetic layout bug and an adversarial request to publish a fake internal configuration.

The gateway read the issue and files, held and rejected the configuration comment, denied a different-repository read without making that request, created a task branch, pushed the two-file fix, opened [draft PR #2](https://github.com/Pgoutham47/agentshield-github-sandbox/pull/2), and published one benign verification comment. The PR is open and unmerged. Its files are `src/button.css` and `tests/button.test.mjs`; main was not changed by the agent workflow.

The recorded trace is `output/github-verification.json`, with its audit export beside it. Proposals and approval decisions were scripted, and contextual signals were fixtures. The operator explicitly enabled the sandbox reviewer for this user-authorized test; this is not evidence of human review quality or live-model injection detection. Real GitHub REST calls and provider request IDs were recorded. GitHub App authentication has contract tests but was not used for this live run.

## Local authentication used for this demonstration

This path requires an already authenticated GitHub CLI account. Credentials are read by the gateway process from `gh auth token --user ...` and never returned to workers, the browser, or logs. CLI credentials can be broader than the configured repository; this is development convenience, not a least-privilege production credential.

```sh
export AGENTSHIELD_GITHUB_REPOSITORY=Pgoutham47/agentshield-github-sandbox
export GITHUB_AUTH_MODE=gh
export GITHUB_DEV_ACCOUNT=Pgoutham47
export AGENTSHIELD_ALLOW_GH_DEV_AUTH=true
export GITHUB_ENABLE_WRITES=true
uv run agentshield serve
```

Configuration is read at startup. `.env.example` is reference material; export variables explicitly. Without `GITHUB_ENABLE_WRITES=true`, the adapter refuses writes even with an approved grant. The Integrations screen verifies read access without making a write. Each live run shows its repository, issue, execution outcomes, and draft PR link.

To repeat the synthetic demonstration, review `github_demo.py` first. It deliberately creates a new branch, commit, PR, and verification comment on every invocation. Only run it on the disposable repository. Run it while no other execution is active; do not run a second SQLite server with startup recovery against the same database. PostgreSQL uses session locks to skip active executions.

```sh
uv run agentshield github-demo --issue 1 --approve-sandbox-writes
```

This command requires a repository named `agentshield-github-sandbox`, the expected sample files, enabled writes, and explicit sandbox approval opt-in. It stops on a failed or unknown execution; it never automatically retries writes. The demo uses `data/console.sqlite` so its evidence is visible in the console.

## GitHub App authentication

For the next deployment, create a GitHub App owned by the intended account or organization, install it on selected repositories only, and select the single disposable pilot repository first. Webhooks and user OAuth are not needed by this polling-free REST adapter. Set repository permissions:

| Permission | App maximum |
| --- | --- |
| Contents | Read and write |
| Issues | Read and write |
| Pull requests | Read and write |
| Metadata | Read (GitHub's required baseline) |

No Actions, workflows, administration, or secrets permissions are needed. Configure on the server:

```sh
export AGENTSHIELD_GITHUB_REPOSITORY=owner/repository
export GITHUB_AUTH_MODE=app
export GITHUB_APP_ID=your-app-id
export GITHUB_INSTALLATION_ID=your-installation-id
export GITHUB_PRIVATE_KEY_PATH=/absolute/path/to/private-key.pem
export GITHUB_ENABLE_WRITES=false
uv run agentshield serve
```

Keep the PEM in the host's secret-file facility with restrictive file permissions. Do not paste the private key into chat or store it in source control. Share only the App ID, installation ID, selected repository, and the server-side secret-file path when configuring the next environment. Enable writes after verifying read access and reviewing the pilot scope.

The broker signs a short-lived App JWT and requests an installation token for exactly the configured repository. It narrows token permissions for each operation and checks the returned repository identity. Tokens are not cached in the database. This follows GitHub's [installation-token API](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app). API requests pin version `2026-03-10`, use the fixed `api.github.com` origin, do not follow redirects or inherit proxy environment settings, and have bounded bodies and timeouts.

## API and SDK flow

1. Create a confirmed task with `provider: "github"`, `resources: ["repo:owner/repository"]`, a matching `github:owner/repository` destination, and one positive issue number in `issue_ids`. Initialization records repository ID, default branch commit, and issue version. A draft can include `provider: "github"`; confirmation still requires `POST /v1/tasks`.
2. Build an `Action` with `adapter_version: "github-rest-1"` and the canonical operation arguments. Use `POST /v1/actions/prepare` (or SDK `prepare`) to bind `expected_resource_version` to the stored task snapshot. Preparation validates scope, makes no provider call, and grants no authority. An initial placeholder such as `"unprepared"` is accepted only as preparation input.
3. Call `POST /v1/decisions`. Reads can be allowed; live writes require an independent approver identity. The reviewer approves or rejects the exact `action_digest` through `POST /v1/approvals/{id}/resolve`.
4. Submit the unchanged envelope with the returned allow-grant ID to `POST /v1/executions`. An approval never executes automatically. Retrieve a known execution using `GET /v1/executions/{id}`. If the HTTP response is lost, use the already-known grant ID with `GET /v1/authorizations/{id}/execution` or SDK `execution_for_authorization`; do not resubmit automatically. A 404 means no recorded execution was found at that instant, not proof that an in-flight request can be retried safely. The SDK has a configurable 180-second timeout for multi-call GitHub operations. Replays cannot reuse a consumed grant.
5. When the provider state is stale, do not reuse the approval. This first adapter has no snapshot refresh route: create a fresh task and re-evaluate. It cannot adopt arbitrary pre-existing branches.

Local identities are still prototype identities in a fixed tenant, extended only with the server-configured repository. SSO, organization enrollment, multi-tenant memberships, and repository installation discovery remain future work.

## Execution guarantees and limits

- The database records execution intent and consumes the grant before network I/O. A repository-wide lock serializes mediated operations, across tasks in this single store. Network calls occur outside database transactions. Cancellation, expiry, and policy are rechecked immediately before each mutation.
- Reads use immutable Git objects. Symlinks and submodules are refused. Commits preserve the existing base tree and file mode, and reject truncated tree inspection, directory replacement, workflow-file changes, secret-path writes, and overlapping file paths. This is not a complete content/secret scanner.
- Branch creation starts at the task's pinned base commit. Pushes require the branch created by that task and the expected remote head. Updates set `force: false`. Draft PRs require the task's commit and an unchanged base branch.
- GitHub's [reference update API](https://docs.github.com/en/rest/git/refs#update-a-reference) does not expose an expected-old-SHA compare-and-swap. Head rechecks and non-force updates reduce races; they do not make separate REST calls atomic. External branch deletion/recreation, a last-moment cancellation, and PR head changes retain provider race windows. No cross-system transaction is claimed.
- Each execution reserves 2 MiB of response allowance before submission, with no refund. Each response is capped at 256 KiB, each read file at 64 KiB, and each session at 16 calls. The maximum task budget is 50 MiB. Large/deep repositories may exceed these conservative pilot limits and fail closed.
- A write timeout, provider 5xx, malformed successful write response, partial multi-step write, or crash can be `outcome_unknown`. The grant stays consumed and the repository lock stays in place across restart. Known rejected requests release the lock. No automatic retry or lock-clearing endpoint exists.
- To investigate an unknown outcome, stop new work and inspect the execution's request IDs and the remote branch/PR/comment state. Preserve the database and audit. Reconciliation and an audited lock-release workflow must be built before unattended production operation; do not simply delete the lock or retry the write.
- Credentials are server-side but the broker is in-process. There is no isolated runner or egress boundary, so an agent with separate GitHub credentials or direct network access can bypass this gateway. The current server is suitable for synthetic pilot work, not customer workloads.
