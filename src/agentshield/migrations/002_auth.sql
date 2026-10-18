CREATE TABLE IF NOT EXISTS auth_sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, tokens TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry ON auth_sessions(expires_at);
INSERT INTO schema_versions(version) VALUES (2) ON CONFLICT DO NOTHING;
