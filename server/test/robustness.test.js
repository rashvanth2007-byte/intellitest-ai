import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'it-rob-'));
Object.assign(process.env, {
  DATA_DIR: dataDir, DATABASE_URL: '', OSV_ENABLED: 'false', ANTHROPIC_API_KEY: '', GEMINI_API_KEY: '',
  GITHUB_CLIENT_ID: 'test-client', GITHUB_CLIENT_SECRET: 'test-secret', GITHUB_TOKEN: '',
  INTELLITEST_ENV_FILE: path.join(dataDir, 'none.env'),
});

// The server runs in this process: simulate GitHub being unreachable without touching the network.
const realFetch = globalThis.fetch;
globalThis.fetch = (url, opts) => (String(url).includes('/repos/octo/slow')
  // Hangs until the scan's AbortController fires, like a stalled download.
  ? new Promise((_res, rej) => opts.signal.addEventListener('abort', () => rej(opts.signal.reason)))
  : /^https:\/\/(api\.)?github\.com\//.test(String(url))
  ? Promise.reject(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } }))
  : realFetch(url, opts));

let base, server;
function client() {
  const jar = {};
  return async function call(method, url, body, { form } = {}) {
    const h = { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') };
    if (jar.it_csrf) h['x-csrf-token'] = jar.it_csrf;
    let payload;
    if (form) payload = form;
    else if (body !== undefined) { h['content-type'] = 'application/json'; payload = JSON.stringify(body); }
    const r = await realFetch(base + url, { method, headers: h, body: payload, redirect: 'manual' });
    for (const c of r.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (kv.slice(i + 1)) jar[kv.slice(0, i)] = kv.slice(i + 1); else delete jar[kv.slice(0, i)];
    }
    const text = await r.text();
    let json; try { json = JSON.parse(text); } catch { json = text; }
    return { status: r.status, json, headers: r.headers };
  };
}
async function signedIn(email) {
  const c = client();
  await c('GET', '/api/auth/me');
  assert.equal((await c('POST', '/api/auth/register', { email, password: 'Passw0rd!' })).status, 201);
  return c;
}
async function waitScan(c, id) {
  for (let i = 0; i < 80; i++) {
    const s = (await c('GET', `/api/scans/${id}`)).json;
    if (!['queued', 'running'].includes(s.status)) return s;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('scan did not finish');
}

before(async () => {
  const { startServer } = await import('../src/app.js');
  const s = await startServer({ port: 0, host: '127.0.0.1' });
  server = s.server;
  base = `http://127.0.0.1:${s.port}`;
});
after(async () => {
  server?.close();
  globalThis.fetch = realFetch;
  const { getDb } = await import('../src/db/index.js');
  await getDb().close();
});

test('concurrent duplicate registrations give one 201 and 409s, never a 500', async () => {
  const clients = [client(), client(), client()];
  await Promise.all(clients.map((c) => c('GET', '/api/auth/me')));
  const res = await Promise.all(clients.map((c) => c('POST', '/api/auth/register', { email: 'race@example.com', password: 'Passw0rd!' })));
  const codes = res.map((r) => r.status).sort();
  assert.deepEqual(codes, [201, 409, 409]);
});

test('concurrent first-time settings saves and key saves do not collide', async () => {
  const c = await signedIn('settings@example.com');
  const res = await Promise.all([
    c('PUT', '/api/settings', { aiDepth: 'deep' }),
    c('PUT', '/api/settings', { theme: 'dark' }),
    c('PUT', '/api/settings/keys/github', { key: 'ghp_aaaaaaaaaaaaaaaaaaaa', verify: false }),
    c('PUT', '/api/settings/keys/github', { key: 'ghp_bbbbbbbbbbbbbbbbbbbb', verify: false }),
  ]);
  assert.deepEqual(res.map((r) => r.status), [200, 200, 200, 200]);
  const s = await c('GET', '/api/settings');
  assert.ok(s.json.keys.github.user);
  assert.equal((await c('DELETE', '/api/settings/keys/github')).status, 200);
  assert.equal((await c('GET', '/api/settings')).json.keys.github.user, null);
});

test('GitHub OAuth callback redirects to the login page when GitHub is unreachable', async () => {
  const c = client();
  await c('GET', '/api/auth/me');
  const start = await c('GET', '/api/auth/github/start');
  assert.equal(start.status, 302);
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const r = await c('GET', `/api/auth/github/callback?code=abc&state=${encodeURIComponent(state)}`);
  assert.equal(r.status, 302);
  assert.match(r.headers.get('location'), /#\/login\?error=github_failed$/);

  // A tampered state cookie ("null") is a redirect too, not a 500.
  const r2 = await realFetch(`${base}/api/auth/github/callback?state=x`, { headers: { cookie: 'it_oauth_state=null' }, redirect: 'manual' });
  assert.equal(r2.status, 302);
  assert.match(r2.headers.get('location'), /error=github_state/);
});

test('GitHub scans fail with a readable error when GitHub is unreachable', async () => {
  const c = await signedIn('gh@example.com');
  const r = await c('POST', '/api/scans', { kind: 'github', url: 'https://github.com/octo/repo' });
  assert.equal(r.status, 202);
  const scan = await waitScan(c, r.json.id);
  assert.equal(scan.status, 'failed');
  assert.match(scan.error, /Could not reach GitHub/);
});

test('UTF-8 upload names, unicode report filenames and huge pagination offsets', async () => {
  const c = await signedIn('utf8@example.com');
  const fd = new FormData();
  fd.append('kind', 'files');
  fd.append('files', new Blob(['import os\nos.system("rm " + name)\n']), 'résumé_日本.py');
  const r = await c('POST', '/api/scans', null, { form: fd });
  assert.equal(r.status, 202);
  const scan = await waitScan(c, r.json.id);
  assert.equal(scan.status, 'completed', scan.error);
  assert.equal(scan.label, 'résumé_日本.py');
  assert.ok(scan.findings.some((f) => f.file === 'résumé_日本.py'));

  const rep = await c('GET', `/api/scans/${scan.id}/report.csv`);
  assert.equal(rep.status, 200);
  assert.match(rep.headers.get('content-type'), /^text\/csv/);
  assert.match(rep.headers.get('content-disposition'), /filename\*=UTF-8''intellitest-r%C3%A9sum%C3%A9_%E6%97%A5%E6%9C%AC\.py\.csv/);

  const list = await c('GET', '/api/scans?offset=99999999999999999999&limit=-5');
  assert.equal(list.status, 200);
  assert.deepEqual(list.json.scans, []);
});

test('Windows-reserved upload paths are written under safe names', async () => {
  const c = await signedIn('win@example.com');
  const fd = new FormData();
  fd.append('kind', 'files');
  fd.append('paths', JSON.stringify(['proj/CON.py', 'proj/x.py:stream']));
  fd.append('files', new Blob(['import os\nos.system("rm " + name)\n']), 'a.py');
  fd.append('files', new Blob(['import os\nos.system("ls " + d)\n']), 'b.py');
  const r = await c('POST', '/api/scans', null, { form: fd });
  const scan = await waitScan(c, r.json.id);
  assert.equal(scan.status, 'completed', scan.error);
  const files = new Set(scan.findings.map((f) => f.file));
  assert.ok(files.has('proj/_CON.py'), [...files].join());
  assert.equal(scan.filesScanned, 2);
});

test('cancelling a running scan aborts its download and ends the SSE stream', async () => {
  const c = await signedIn('cancel@example.com');
  const r = await c('POST', '/api/scans', { kind: 'github', url: 'https://github.com/octo/slow' });
  assert.equal(r.status, 202);
  const id = r.json.id;
  for (let i = 0; i < 50 && (await c('GET', `/api/scans/${id}`)).json.status !== 'running'; i++) await new Promise((res) => setTimeout(res, 50));
  const sse = c('GET', `/api/scans/${id}/events`); // resolves only when the server ends the stream
  await new Promise((res) => setTimeout(res, 100));
  assert.equal((await c('POST', `/api/scans/${id}/cancel`)).json.ok, true);
  const stream = await sse;
  assert.match(stream.json, /event: done\ndata: \{"status":"cancelled"/);
  const scan = await waitScan(c, id);
  assert.equal(scan.status, 'cancelled');
});
