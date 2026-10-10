import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { decrypt, encrypt, keyHint } from '../util/crypto.js';
import { parseJson } from '../util/http.js';
import { CLAUDE_MODELS, GEMINI_MODELS } from '../engines/ai/providers.js';
import { DEPTHS } from '../engines/ai/chunker.js';

export const DEFAULT_SETTINGS = {
  engine: 'auto',            // auto | rules | claude | gemini
  claudeModel: config.ai.claudeModel,
  geminiModel: config.ai.geminiModel,
  aiDepth: 'standard',       // quick | standard | deep
  agents: ['sentinel', 'phantom', 'cipher', 'nexus', 'oracle'],
  alertThreshold: 'critical', // critical | high | off
  theme: 'system',
};

/** Keys a user can save from Settings. AI keys (Anthropic, Gemini) come only from the server environment. */
export const PROVIDERS = ['github'];

export async function getSettings(userId) {
  const row = await getDb().get('SELECT data FROM user_settings WHERE user_id = ?', [userId]);
  return { ...DEFAULT_SETTINGS, ...parseJson(row?.data, {}) };
}

export function sanitizeSettings(input, current) {
  const s = { ...current };
  const pick = (k, allowed) => { if (input[k] !== undefined && allowed.includes(input[k])) s[k] = input[k]; };
  pick('engine', ['auto', 'rules', 'claude', 'gemini']);
  pick('claudeModel', CLAUDE_MODELS.map((m) => m.id));
  pick('geminiModel', GEMINI_MODELS.map((m) => m.id));
  pick('aiDepth', Object.keys(DEPTHS));
  pick('alertThreshold', ['critical', 'high', 'off']);
  pick('theme', ['system', 'dark', 'light']);
  if (Array.isArray(input.agents)) {
    const a = input.agents.filter((x) => DEFAULT_SETTINGS.agents.includes(x));
    if (a.length) s.agents = [...new Set(a)];
  }
  return s;
}

export async function saveSettings(userId, s) {
  const db = getDb();
  const data = JSON.stringify(s);
  // Upsert (SQLite >= 3.24 and PostgreSQL): two first-time saves racing must not hit the primary key.
  await db.run('INSERT INTO user_settings (user_id, data) VALUES (?, ?) ON CONFLICT (user_id) DO UPDATE SET data = excluded.data', [userId, data]);
}

export async function setApiKey(userId, provider, key) {
  const db = getDb();
  if (!key) return void await db.run('DELETE FROM api_keys WHERE user_id = ? AND provider = ?', [userId, provider]);
  await db.run(
    `INSERT INTO api_keys (user_id, provider, key_enc, hint, updated_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (user_id, provider) DO UPDATE SET key_enc = excluded.key_enc, hint = excluded.hint, updated_at = excluded.updated_at`,
    [userId, provider, encrypt(key), keyHint(key), Date.now()]);
}

export async function keyStatus(userId) {
  const rows = await getDb().all('SELECT provider, hint, updated_at FROM api_keys WHERE user_id = ?', [userId]);
  const mine = Object.fromEntries(rows.map((r) => [r.provider, { hint: r.hint, updatedAt: Number(r.updated_at) }]));
  return {
    anthropic: { user: null, server: !!config.ai.anthropicKey },
    gemini: { user: null, server: !!config.ai.geminiKey },
    github: { user: mine.github || null, server: !!config.github.token },
  };
}

/**
 * AI keys (Anthropic, Gemini) come only from the server environment (.env).
 * GitHub: the user's own token first, then the server-wide token.
 */
export async function resolveApiKey(userId, provider) {
  if (provider === 'anthropic') return config.ai.anthropicKey;
  if (provider === 'gemini') return config.ai.geminiKey;
  if (provider !== 'github') return '';
  const row = await getDb().get('SELECT key_enc FROM api_keys WHERE user_id = ? AND provider = ?', [userId, provider]);
  if (row) { try { return decrypt(row.key_enc); } catch { /* key rotated */ } }
  return config.github.token;
}

/**
 * Token for GitHub downloads: personal token > OAuth token > server token.
 * `shared` marks the operator's server-wide token, which must only be used for public repos.
 */
export async function resolveGithubToken(userId) {
  const db = getDb();
  const pat = await db.get("SELECT key_enc FROM api_keys WHERE user_id = ? AND provider = 'github'", [userId]);
  if (pat) { try { return { token: decrypt(pat.key_enc), shared: false }; } catch { /* */ } }
  const oauth = await db.get("SELECT access_token_enc FROM oauth_accounts WHERE user_id = ? AND provider = 'github'", [userId]);
  if (oauth?.access_token_enc) { try { return { token: decrypt(oauth.access_token_enc), shared: false }; } catch { /* */ } }
  return { token: config.github.token, shared: true };
}

/** Decide which AI engine a scan will use given settings and available keys. */
export async function resolveEngine(userId, settings) {
  const want = settings.engine;
  if (want === 'rules') return { provider: null };
  const order = want === 'gemini' ? ['gemini'] : want === 'claude' ? ['anthropic'] : ['anthropic', 'gemini'];
  for (const p of order) {
    const key = await resolveApiKey(userId, p);
    if (key) return { provider: p === 'anthropic' ? 'claude' : 'gemini', apiKey: key, model: p === 'anthropic' ? settings.claudeModel : settings.geminiModel };
  }
  return { provider: null, missing: want === 'auto' ? null : want };
}
