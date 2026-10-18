CREATE TABLE IF NOT EXISTS github_accounts (
 tenant TEXT PRIMARY KEY, subject TEXT NOT NULL, github_id TEXT NOT NULL, tokens TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS github_repositories (
 id TEXT PRIMARY KEY, tenant TEXT NOT NULL REFERENCES github_accounts(tenant) ON DELETE CASCADE,
 installation_id BIGINT NOT NULL, repository_id BIGINT NOT NULL, name TEXT NOT NULL,
 UNIQUE(tenant,repository_id), UNIQUE(tenant,name)
);
CREATE TABLE IF NOT EXISTS github_flows (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, subject TEXT NOT NULL, tenant TEXT NOT NULL,
 github_id TEXT NOT NULL, verifier TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, expires_at DOUBLE PRECISION NOT NULL
);
INSERT INTO schema_versions(version) VALUES (3) ON CONFLICT DO NOTHING;
