import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(here, '..', '..');

// Load .env files (repo root, then server/) without overriding real env vars.
for (const p of [path.join(ROOT_DIR, '.env'), path.join(ROOT_DIR, 'server', '.env'), process.env.INTELLITEST_ENV_FILE]) {
  if (p && fs.existsSync(p)) {
    try { process.loadEnvFile(p); } catch (e) { console.warn(`[config] could not read ${p}: ${e.message}`); }
  }
}

const env = process.env;
const isProd = env.NODE_ENV === 'production';

function int(v, d) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; }

const dataDir = path.resolve(env.DATA_DIR || path.join(ROOT_DIR, 'data'));
fs.mkdirSync(dataDir, { recursive: true });

/**
 * Secrets: in production they MUST come from the environment (a regenerated secret would
 * log everyone out and make stored API keys undecryptable). Locally / on the desktop app
 * we generate them once and persist them in the data directory.
 */
function loadSecrets() {
  const file = path.join(dataDir, 'secrets.json');
  let stored = {};
  try { stored = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* first run */ }
  const out = {
    jwt: env.JWT_SECRET || stored.jwt,
    enc: env.ENC_KEY || stored.enc,
  };
  if ((!env.JWT_SECRET || !env.ENC_KEY) && isProd && env.DATABASE_URL) {
    throw new Error('JWT_SECRET and ENC_KEY must be set in production.');
  }
  let changed = false;
  if (!out.jwt) { out.jwt = crypto.randomBytes(48).toString('base64url'); changed = true; }
  if (!out.enc) { out.enc = crypto.randomBytes(32).toString('base64url'); changed = true; }
  if (changed) {
    fs.writeFileSync(file, JSON.stringify({ jwt: out.jwt, enc: out.enc }, null, 2), { mode: 0o600 });
  }
  return out;
}

const secrets = loadSecrets();
const port = int(env.PORT, 8787);
const appUrl = (env.APP_URL || `http://localhost:${port}`).replace(/\/+$/, '');

export const config = {
  isProd,
  host: env.HOST || (isProd ? '0.0.0.0' : '127.0.0.1'),
  port,
  appUrl,
  cookieSecure: appUrl.startsWith('https://'),
  dataDir,
  tmpDir: path.resolve(env.TMP_DIR || path.join(dataDir, 'tmp')),
  webDist: path.resolve(env.WEB_DIST || path.join(ROOT_DIR, 'web', 'dist')),
  databaseUrl: env.DATABASE_URL || '',
  sqliteFile: path.join(dataDir, 'intellitest.db'),
  jwtSecret: secrets.jwt,
  encKey: secrets.enc,
  sessionDays: int(env.SESSION_DAYS, 7),
  github: {
    clientId: env.GITHUB_CLIENT_ID || '',
    clientSecret: env.GITHUB_CLIENT_SECRET || '',
    token: env.GITHUB_TOKEN || '', // optional server-wide token for higher rate limits
  },
  ai: {
    anthropicKey: env.ANTHROPIC_API_KEY || '',
    geminiKey: env.GEMINI_API_KEY || '',
    claudeModel: env.CLAUDE_MODEL || 'claude-opus-5-5',
    geminiModel: env.GEMINI_MODEL || 'gemini-3.5-flash-lite',
  },
  limits: {
    uploadBytes: int(env.MAX_UPLOAD_MB, 100) * 1024 * 1024,
    unzippedBytes: int(env.MAX_UNZIPPED_MB, 300) * 1024 * 1024,
    maxFiles: int(env.MAX_FILES, 20000),
    maxFileBytes: int(env.MAX_FILE_KB, 1024) * 1024,
    concurrentScans: int(env.CONCURRENT_SCANS, 2),
  },
  allowRegistration: env.ALLOW_REGISTRATION !== 'false',
  trustProxy: /^\d+$/.test(env.TRUST_PROXY || '') ? Number(env.TRUST_PROXY) : env.TRUST_PROXY === 'true',
  allowedHosts: (env.ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean),
  osvEnabled: env.OSV_ENABLED !== 'false',
};

fs.mkdirSync(config.tmpDir, { recursive: true });
