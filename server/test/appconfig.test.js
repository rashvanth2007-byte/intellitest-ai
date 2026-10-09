import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'it-appcfg-'));
Object.assign(process.env, {
  DATA_DIR: dataDir, DATABASE_URL: '', OSV_ENABLED: 'false', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '',
  ALLOW_LOCAL_ADMIN: 'true', INTELLITEST_ENV_FILE: path.join(dataDir, 'none.env'),
});

let base, server;
const jar = {};
async function call(method, url, body) {
  const h = { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') };
  if (jar.it_csrf) h['x-csrf-token'] = jar.it_csrf;
  if (body) h['content-type'] = 'application/json';
  const r = await realFetch(base + url, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); if (kv.slice(i + 1)) jar[kv.slice(0, i)] = kv.slice(i + 1); }
  return { status: r.status, json: await r.json().catch(() => null) };
}
const realFetch = globalThis.fetch;

// Fake GitHub's token endpoint: the right secret yields "bad_verification_code", anything else "incorrect_client_credentials".
const GOOD_SECRET = 'a'.repeat(40);
function fakeGithub() {
  return mock.method(globalThis, 'fetch', async (url, opts) => {
    if (String(url).startsWith('https://github.com/login/oauth/access_token')) {
      const { client_secret } = JSON.parse(opts.body);
      return new Response(JSON.stringify({ error: client_secret === GOOD_SECRET ? 'bad_verification_code' : 'incorrect_client_credentials' }), { headers: { 'content-type': 'application/json' } });
    }
    return realFetch(url, opts);
  });
}

before(async () => {
  const { startServer } = await import('../src/app.js');
  const s = await startServer({ port: 0, host: '127.0.0.1' });
  server = s.server;
  base = `http://127.0.0.1:${s.port}`;
  await call('GET', '/api/auth/me');
  await call('POST', '/api/auth/register', { email: 'admin@example.com', password: 'Passw0rd!' });
});
after(async () => {
  server?.close();
  const { getDb } = await import('../src/db/index.js');
  await getDb().close();
});

test('GitHub sign-in can be set up from Settings on a local install, with credentials verified', async () => {
  let r = await call('GET', '/api/settings');
  assert.equal(r.json.githubOAuth.configured, false);
  assert.equal(r.json.githubOAuth.canConfigure, true);
  assert.match(r.json.githubOAuth.callbackUrl, /\/api\/auth\/github\/callback$/);
  assert.equal((await call('GET', '/api/auth/me')).json.providers.github, false);

  const m = fakeGithub();
  try {
    r = await call('PUT', '/api/settings/github-oauth', { clientId: 'Ov23liTESTCLIENT01', clientSecret: 'b'.repeat(40) });
    assert.equal(r.status, 400);
    assert.match(r.json.error, /rejected/);
    r = await call('PUT', '/api/settings/github-oauth', { clientId: 'bad id!', clientSecret: GOOD_SECRET });
    assert.equal(r.status, 400);
    r = await call('PUT', '/api/settings/github-oauth', { clientId: 'Ov23liTESTCLIENT01', clientSecret: GOOD_SECRET });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(r.json.githubOAuth.configured, true);
    assert.equal(r.json.githubOAuth.source, 'app');
    assert.ok(!JSON.stringify(r.json).includes(GOOD_SECRET), 'secret must never be returned');
  } finally { m.mock.restore(); }

  assert.equal((await call('GET', '/api/auth/me')).json.providers.github, true);

  // Persisted encrypted, and loaded again on restart.
  const { getDb } = await import('../src/db/index.js');
  const row = await getDb().get("SELECT value FROM app_config WHERE key = 'github_client_secret'");
  assert.ok(row && !row.value.includes(GOOD_SECRET));
  const { config } = await import('../src/config.js');
  Object.assign(config.github, { clientId: '', clientSecret: '', source: null });
  const { loadAppConfig } = await import('../src/settings/appConfig.js');
  await loadAppConfig();
  assert.equal(config.github.clientSecret, GOOD_SECRET);

  r = await call('DELETE', '/api/settings/github-oauth');
  assert.equal(r.json.githubOAuth.configured, false);
  assert.equal((await call('GET', '/api/auth/me')).json.providers.github, false);
});

test('public servers do not allow changing GitHub sign-in from the UI', async () => {
  const { config } = await import('../src/config.js');
  config.allowLocalAdmin = false;
  try {
    const r = await call('PUT', '/api/settings/github-oauth', { clientId: 'Ov23liTESTCLIENT01', clientSecret: GOOD_SECRET });
    assert.equal(r.status, 403);
    assert.equal((await call('GET', '/api/settings')).json.githubOAuth.canConfigure, false);
  } finally { config.allowLocalAdmin = true; }
});
