# Requirements status

The prototype brief governs this iteration. The PRD remains the production reference. The original PDFs and deck are unchanged; slide 10's broad “what we built” claims must not be used to describe this narrower implementation.

| Source requirement | Current evidence | Remaining gap |
| --- | --- | --- |
| Brief runs A/B/C; PRD T01/T12/T13 | CLI and console demos; acceptance tests | Mock demos plus a verified live GitHub sandbox; proposals and contextual signals are still scripted/fixtures |
| AI03 contract drafting | Template draft offline; configured model selects bounded resources live; confirmation endpoint | No live model run, richer least-privilege argument drafting not implemented |
| FR02/FR04 contract/scope | Identity-bound task, resource, issue, operation, destination, expiry tests | Production identity service and provider entitlements |
| FR11 / T07 budgets | Concurrent call tests, byte reservation and response cap, concurrency limit | Multi-instance PostgreSQL and spend limits |
| FR13/FR14 / T04/T05 approvals | Immutable original decisions, linked allow grants, digest/version/replay tests | Delegated organization RBAC and production approvals UX |
| FR15 persistent pending state | Restart approval test | HA and restore semantics |
| FR17 cancellation | Existing grants rechecked before execution; cancel tests | Provider revocation and running sandbox containment |
| FR18 / T10 outcome accuracy | Unknown outcome on timeout; startup recovery test | Provider reconciliation |
| AI06 / T06 evaluator failure | Strict output, no tools, fixed instructions, timeout and malformed-output tests | Independent evaluator adversarial benchmark |
| T08 benign security terms | Synthetic legitimate proposal corpus includes security terminology | Representative real workload validation |
| T09 tenant checks | API identity mapping and tenant-scoped engine tests | Real multi-tenant enrollment, SSO, membership lifecycle |
| FR20 audit | Transactional append-only outbox and hash chain; redaction test | Signing, external checkpoints, encryption, archival |
| T14 evaluation | 60 unique synthetic proposals × off/fixture; optional live mode | Real model run, classifier tier, held-out attacks, cost, uncertainty intervals |
| FR24 SDK | Async Python client and end-to-end SDK test | Versioned published package and connector conformance |
| FR03/FR09 / T03 | GitHub App token broker implemented and transport-tested; CLI-authenticated sandbox verified | Isolated broker/runner, egress controls, bypass tests, installed App live verification |
| FR10 / T02 | Not implemented | Manifest pinning, drift quarantine, MCP gateway |
| FR19/FR21/FR22 | Not implemented | Webhook export, policy lifecycle, retention/deletion |

## Known prototype constraints

- One fixed tenant, fixture repository, and optional server-configured live repository through the HTTP identities. Engine tenant checks exist; general tenant provisioning does not.
- One process, one SQLite owner. Startup recovery must not run beside an active worker.
- Call/byte reservations are conservative and do not refund rejected or expired decisions.
- Repository-wide versions invalidate approvals after unrelated mock mutations.
- Pending approvals are checked for expiry when resolved; there is no background expiry scheduler.
- Review payloads and mock contents are stored locally without encryption or retention. Synthetic data only.
- Fixture data and detector indicators are intentionally coupled. No general model-quality conclusion follows from fixture evaluation.
- The limited secret detector is not gitleaks and cannot detect all encoded secrets or private data.
- Approval checks and execution work through the backend API. The console's scenario C deliberately continues safe work, so its pending approval will normally be stale for approval and still rejectable.
- The UI reads up to 100 task runs and the first 1,000 events. Full JSONL export includes all events for the tenant. Production pagination/streaming remains work.
- Local API tests pass. Real GitHub was exercised against a private disposable repository; see the integration guide and output trace. Live Anthropic, installed GitHub App auth, hosted Render, and Supabase remain unverified.
