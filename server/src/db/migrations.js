// Portable DDL (works on both SQLite and PostgreSQL).
export const migrations = [
  {
    version: 1,
    name: 'initial schema',
    up: [
      `CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        password_hash TEXT,
        avatar_url TEXT,
        created_at BIGINT NOT NULL,
        last_login_at BIGINT
      )`,
      `CREATE TABLE oauth_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        login TEXT,
        access_token_enc TEXT,
        scope TEXT,
        created_at BIGINT NOT NULL,
        UNIQUE (provider, provider_user_id)
      )`,
      `CREATE TABLE user_settings (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        data TEXT NOT NULL
      )`,
      `CREATE TABLE api_keys (
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        key_enc TEXT NOT NULL,
        hint TEXT,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, provider)
      )`,
      `CREATE TABLE scans (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        label TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        source_ref TEXT,
        status TEXT NOT NULL,
        engine TEXT,
        ai_model TEXT,
        progress TEXT,
        counts TEXT,
        total INTEGER NOT NULL DEFAULT 0,
        score INTEGER,
        grade TEXT,
        files_scanned INTEGER NOT NULL DEFAULT 0,
        lines_scanned INTEGER NOT NULL DEFAULT 0,
        warnings TEXT,
        error TEXT,
        duration_ms INTEGER,
        created_at BIGINT NOT NULL,
        finished_at BIGINT
      )`,
      'CREATE INDEX idx_scans_user ON scans (user_id, created_at)',
      `CREATE TABLE findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT,
        cwe TEXT,
        owasp TEXT,
        cvss DOUBLE PRECISION,
        file TEXT,
        line INTEGER,
        snippet TEXT,
        description TEXT,
        impact TEXT,
        recommendation TEXT,
        engines TEXT,
        agent TEXT,
        rule_id TEXT,
        confidence TEXT,
        extra TEXT,
        created_at BIGINT NOT NULL
      )`,
      'CREATE INDEX idx_findings_scan ON findings (scan_id)',
    ],
  },
  {
    version: 2,
    name: 'session version for revocable sessions',
    up: ['ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0'],
  },
  {
    version: 3,
    name: 'app-wide configuration set from the UI (e.g. GitHub OAuth app)',
    up: ['CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at BIGINT NOT NULL)'],
  },
];
