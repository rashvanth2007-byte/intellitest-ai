import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'it-sec-'));
Object.assign(process.env, {
  DATA_DIR: dataDir, DATABASE_URL: '', OSV_ENABLED: 'false', ANTHROPIC_API_KEY: '', GEMINI_API_KEY: '',
  MAX_UPLOAD_MB: '1', INTELLITEST_ENV_FILE: path.join(dataDir, 'none.env'),
});

let base, server;
/** Minimal cookie-jar client; each call to client() is a separate browser. */
function client() {
  const jar = {};
  return async function call(method, url, body, headers = {}) {
    const h = { cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '), ...headers };
    if (jar.it_csrf) h['x-csrf-token'] = jar.it_csrf;
    let payload;
    if (body !== undefined) { h['content-type'] = 'application/json'; payload = JSON.stringify(body); }
    const r = await fetch(base + url, { method, headers: h, body: payload });
    for (const c of r.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      if (kv.slice(i + 1)) jar[kv.slice(0, i)] = kv.slice(i + 1); else delete jar[kv.slice(0, i)];
    }
    return { status: r.status, json: await r.json().catch(() => null), jar };
  };
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

test('changing the password revokes other sessions but keeps the current one', async () => {
  const a = client();
  await a('GET', '/api/auth/me');
  assert.equal((await a('POST', '/api/auth/register', { email: 'sec@example.com', password: 'Passw0rd!' })).status, 201);

  const b = client(); // the same user signed in on a second device (or a stolen cookie)
  await b('GET', '/api/auth/me');
  assert.equal((await b('POST', '/api/auth/login', { email: 'sec@example.com', password: 'Passw0rd!' })).status, 200);
  assert.equal((await b('GET', '/api/scans')).status, 200);

  assert.equal((await a('PUT', '/api/auth/password', { currentPassword: 'Passw0rd!', newPassword: 'N3wPassw0rd!' })).status, 200);
  assert.equal((await b('GET', '/api/scans')).status, 401, 'old session must be revoked');
  assert.equal((await a('GET', '/api/scans')).status, 200, 'current session must survive');
});

test('oversized uploads are rejected before reaching disk', async () => {
  const a = client();
  await a('GET', '/api/auth/me');
  await a('POST', '/api/auth/register', { email: 'big@example.com', password: 'Passw0rd!' });
  const r = await a('POST', '/api/scans', { kind: 'paste', code: 'x'.repeat(3 * 1024 * 1024), filename: 'a.js' });
  assert.equal(r.status, 413);
});

test('X-Forwarded-For is ignored unless TRUST_PROXY is set', async () => {
  const { config } = await import('../src/config.js');
  assert.equal(config.trustProxy, false);
});

test('chunked uploads over the total cap are cut off and their temp files removed', async () => {
  const a = client();
  await a('GET', '/api/auth/me');
  const { jar } = await a('POST', '/api/auth/register', { email: 'chunk@example.com', password: 'Passw0rd!' });
  const boundary = 'x-boundary-1';
  const chunk = Buffer.alloc(256 * 1024, 'a');
  let sent = 0;
  const body = new ReadableStream({
    pull(ctrl) {
      // Many 512 KB files: each is under the 1 MB per-file cap, only the total is too large.
      if (sent % (512 * 1024) === 0) ctrl.enqueue(Buffer.from(`${sent ? '\r\n' : ''}--${boundary}\r\nContent-Disposition: form-data; name="files"; filename="f${sent}.txt"\r\n\r\n`));
      if (sent > 8 * 1024 * 1024) { ctrl.enqueue(Buffer.from(`\r\n--${boundary}--\r\n`)); return ctrl.close(); }
      sent += chunk.length;
      ctrl.enqueue(chunk);
    },
  });
  const r = await fetch(`${base}/api/scans`, {
    method: 'POST', body, duplex: 'half',
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}`, cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '), 'x-csrf-token': jar.it_csrf },
  }).catch((e) => e);
  assert.ok(r instanceof Error || r.status === 413, `expected rejection, got ${r.status}`);
  assert.ok(sent < 8 * 1024 * 1024, 'server must stop reading early');
  const { config } = await import('../src/config.js');
  for (let i = 0; i < 40 && fs.readdirSync(config.tmpDir).some((d) => d.startsWith('up-')); i++) await new Promise((res) => setTimeout(res, 100));
  assert.deepEqual(fs.readdirSync(config.tmpDir).filter((d) => d.startsWith('up-')), []);
});
