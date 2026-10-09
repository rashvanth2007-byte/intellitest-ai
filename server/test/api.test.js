import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'it-api-'));
process.env.DATA_DIR = dataDir;
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || '';
process.env.OSV_ENABLED = 'false';
process.env.ANTHROPIC_API_KEY = '';
process.env.GEMINI_API_KEY = '';
process.env.INTELLITEST_ENV_FILE = path.join(dataDir, 'none.env');

let base, server;
const jar = {};
async function call(method, url, body, { form } = {}) {
  const headers = { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ') };
  if (jar.it_csrf) headers['x-csrf-token'] = jar.it_csrf;
  let payload;
  if (form) payload = form;
  else if (body) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  const r = await fetch(base + url, { method, headers, body: payload, redirect: 'manual' });
  for (const c of r.headers.getSetCookie()) {
    const [kv] = c.split(';');
    const i = kv.indexOf('=');
    const v = kv.slice(i + 1);
    if (v) jar[kv.slice(0, i)] = v; else delete jar[kv.slice(0, i)];
  }
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, json };
}

before(async () => {
  const { startServer } = await import('../src/app.js');
  const s = await startServer({ port: 0, host: '127.0.0.1' });
  server = s.server;
  base = `http://127.0.0.1:${s.port}`;
});
after(async () => {
  server?.close();
  const { getDb } = await import('../src/db/index.js');
  await getDb().close();
});

test('auth flow, CSRF and a paste scan end-to-end', async () => {
  let r = await call('GET', '/api/auth/me');
  assert.equal(r.status, 200);
  assert.equal(r.json.user, null);
  assert.ok(jar.it_csrf);

  // CSRF required
  const saved = jar.it_csrf; delete jar.it_csrf;
  r = await call('POST', '/api/auth/register', { email: 'a@b.co', password: 'Passw0rd!' });
  assert.equal(r.status, 403);
  jar.it_csrf = saved;

  r = await call('POST', '/api/auth/register', { email: 'a@b.co', password: 'short' });
  assert.equal(r.status, 400);
  r = await call('POST', '/api/auth/register', { email: 'dev@example.com', password: 'Passw0rd!', name: 'Dev' });
  assert.equal(r.status, 201);
  assert.ok(jar.it_session);

  r = await call('POST', '/api/auth/register', { email: 'dev@example.com', password: 'Passw0rd!' });
  assert.equal(r.status, 409);

  r = await call('POST', '/api/auth/logout');
  r = await call('GET', '/api/scans');
  assert.equal(r.status, 401);
  r = await call('POST', '/api/auth/login', { email: 'dev@example.com', password: 'wrong-pass1' });
  assert.equal(r.status, 401);
  r = await call('POST', '/api/auth/login', { email: 'DEV@example.com', password: 'Passw0rd!' });
  assert.equal(r.status, 200);

  const code = 'const q = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(q);\nconst k = "AKIAIOSFODNN7ABCDEFG";\n';
  r = await call('POST', '/api/scans', { kind: 'paste', code, filename: 'app.js' });
  assert.equal(r.status, 202);
  const id = r.json.id;

  let scan;
  for (let i = 0; i < 50; i++) {
    scan = (await call('GET', `/api/scans/${id}`)).json;
    if (!['queued', 'running'].includes(scan.status)) break;
    await new Promise((res) => setTimeout(res, 100));
  }
  assert.equal(scan.status, 'completed', scan.error);
  assert.ok(scan.findings.some((f) => f.cwe === 'CWE-89'), 'SQL injection expected');
  assert.ok(scan.findings.some((f) => f.ruleId === 'secret-aws-access-key'), 'AWS key expected');
  assert.ok(scan.warnings.some((w) => /AI agents skipped/.test(w)));
  assert.ok(scan.score < 60);

  for (const fmt of ['json', 'html', 'sarif', 'csv']) {
    r = await call('GET', `/api/scans/${id}/report.${fmt}`);
    assert.equal(r.status, 200, fmt);
  }
  r = await call('GET', '/api/scans/stats');
  assert.equal(r.json.completed, 1);

  // SSE for a finished scan ends immediately with a done event
  r = await call('GET', `/api/scans/${id}/events`);
  assert.equal(r.status, 200);
  assert.match(r.json, /event: done/);

  // A POST with no body is a 400, not a crash (Express 5 leaves req.body undefined)
  r = await call('POST', '/api/scans');
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'Unknown scan type.');

  // Another user cannot see it
  await call('POST', '/api/auth/logout');
  await call('POST', '/api/auth/register', { email: 'other@example.com', password: 'Passw0rd!' });
  r = await call('GET', `/api/scans/${id}`);
  assert.equal(r.status, 404);
});

test('zip upload scan via multipart', async () => {
  const fd = new FormData();
  fd.append('kind', 'files');
  fd.append('paths', JSON.stringify(['proj/app.py', 'proj/Dockerfile']));
  fd.append('files', new Blob(['import os\nos.system("rm " + name)\n']), 'app.py');
  fd.append('files', new Blob(['FROM python\nCMD python app.py\n']), 'Dockerfile');
  let r = await call('POST', '/api/scans', null, { form: fd });
  assert.equal(r.status, 202);
  let scan;
  for (let i = 0; i < 50; i++) {
    scan = (await call('GET', `/api/scans/${r.json.id}`)).json;
    if (!['queued', 'running'].includes(scan.status)) break;
    await new Promise((res) => setTimeout(res, 100));
  }
  assert.equal(scan.status, 'completed', scan.error);
  assert.equal(scan.filesScanned, 2);
  const rules = new Set(scan.findings.map((f) => f.ruleId));
  assert.ok(rules.has('py-cmd-injection'));
  assert.ok(rules.has('docker-root-user'));
  assert.ok(scan.findings.every((f) => !f.file || f.file.startsWith('proj/')));
});
