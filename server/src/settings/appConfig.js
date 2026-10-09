/**
 * Server-wide settings that can be configured from the UI on local/desktop installs
 * (currently the GitHub OAuth app). Environment variables always take precedence.
 */
import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { decrypt, encrypt } from '../util/crypto.js';
import { HttpError } from '../util/http.js';

const fromEnv = { clientId: config.github.clientId, clientSecret: config.github.clientSecret };

/** Load UI-saved values into config.github (called once at start-up). */
export async function loadAppConfig() {
  if (fromEnv.clientId && fromEnv.clientSecret) { config.github.source = 'env'; return; }
  const rows = await getDb().all("SELECT key, value FROM app_config WHERE key IN ('github_client_id', 'github_client_secret')");
  const v = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  if (v.github_client_id && v.github_client_secret) {
    try {
      config.github.clientId = v.github_client_id;
      config.github.clientSecret = decrypt(v.github_client_secret);
      config.github.source = 'app';
    } catch { config.github.clientId = ''; config.github.clientSecret = ''; }
  }
}

export function githubOAuthStatus() {
  return {
    configured: !!(config.github.clientId && config.github.clientSecret),
    source: config.github.source || null, // 'env' | 'app' | null
    canConfigure: config.allowLocalAdmin && config.github.source !== 'env',
    callbackUrl: `${config.appUrl}/api/auth/github/callback`,
    homepageUrl: config.appUrl,
    clientId: config.github.clientId ? `${config.github.clientId.slice(0, 6)}…` : null,
  };
}

/**
 * Check the credentials with GitHub: exchanging a dummy code returns "bad_verification_code" when the
 * client ID/secret are right and "incorrect_client_credentials" when they are wrong.
 */
async function verifyWithGithub(clientId, clientSecret) {
  let body;
  try {
    const r = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code: 'intellitest-credential-check' }),
      signal: AbortSignal.timeout(15000),
    });
    body = await r.json().catch(() => ({}));
  } catch {
    throw new HttpError(502, 'Could not reach GitHub to check the credentials. Check your internet connection.');
  }
  if (body.error === 'incorrect_client_credentials') throw new HttpError(400, 'GitHub rejected this Client ID / Client secret pair. Copy both again from your OAuth app.');
  if (body.error && body.error !== 'bad_verification_code' && body.error !== 'redirect_uri_mismatch') {
    throw new HttpError(400, `GitHub said: ${body.error_description || body.error}`);
  }
}

export async function saveGithubOAuth(clientId, clientSecret) {
  if (!config.allowLocalAdmin) throw new HttpError(403, 'GitHub sign-in is configured by the server administrator (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET).');
  if (config.github.source === 'env') throw new HttpError(409, 'GitHub sign-in is already configured through environment variables.');
  const id = String(clientId || '').trim();
  const secret = String(clientSecret || '').trim();
  if (!/^[A-Za-z0-9._-]{10,100}$/.test(id)) throw new HttpError(400, 'That does not look like a GitHub Client ID (e.g. Ov23li…).');
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(secret)) throw new HttpError(400, 'That does not look like a GitHub Client secret (40 characters).');
  await verifyWithGithub(id, secret);
  const db = getDb();
  const now = Date.now();
  const up = 'INSERT INTO app_config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at';
  await db.run(up, ['github_client_id', id, now]);
  await db.run(up, ['github_client_secret', encrypt(secret), now]);
  Object.assign(config.github, { clientId: id, clientSecret: secret, source: 'app' });
}

export async function removeGithubOAuth() {
  if (!config.allowLocalAdmin || config.github.source === 'env') throw new HttpError(403, 'GitHub sign-in is managed by the server administrator.');
  await getDb().run("DELETE FROM app_config WHERE key IN ('github_client_id', 'github_client_secret')");
  Object.assign(config.github, { clientId: '', clientSecret: '', source: null });
}
