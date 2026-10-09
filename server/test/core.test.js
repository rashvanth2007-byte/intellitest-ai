import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'it-core-'));
Object.assign(process.env, { DATA_DIR: dataDir, DATABASE_URL: '', INTELLITEST_ENV_FILE: path.join(dataDir, 'none.env') });

const { openDb, isUniqueViolation } = await import('../src/db/index.js');
const { safeRelPath } = await import('../src/ingest/paths.js');
const tick = () => new Promise((r) => setTimeout(r, 5));

test('sqlite transactions are serialised and outside statements wait for them', async () => {
  const db = await openDb({ sqliteFile: path.join(dataDir, 'tx.db') });
  await db.exec('CREATE TABLE t (k TEXT PRIMARY KEY, v INTEGER)');
  // Two async transactions that would previously BEGIN inside each other ("cannot start a transaction within a transaction").
  const a = db.tx(async (t) => { await t.run('INSERT INTO t VALUES (?, ?)', ['a', 1]); await tick(); await t.run('INSERT INTO t VALUES (?, ?)', ['a2', 1]); });
  const b = db.tx(async (t) => { await t.run('INSERT INTO t VALUES (?, ?)', ['b', 2]); await tick(); });
  // A failing transaction must roll back only its own work.
  const c = db.tx(async (t) => { await t.run('INSERT INTO t VALUES (?, ?)', ['c', 3]); await tick(); throw new Error('boom'); });
  // A plain statement issued while a transaction is open must not become part of it.
  const d = db.run('INSERT INTO t VALUES (?, ?)', ['d', 4]);
  const res = await Promise.allSettled([a, b, c, d]);
  assert.deepEqual(res.map((r) => r.status), ['fulfilled', 'fulfilled', 'rejected', 'fulfilled']);
  const keys = (await db.all('SELECT k FROM t ORDER BY k')).map((r) => r.k);
  assert.deepEqual(keys, ['a', 'a2', 'b', 'd']);
  await assert.rejects(db.run('INSERT INTO t VALUES (?, ?)', ['a', 9]), (e) => isUniqueViolation(e));
  await db.close();
});

test('migrations tolerate a database that already has the v2 column', async () => {
  const file = path.join(dataDir, 'old.db');
  const { DatabaseSync } = await import('node:sqlite');
  const raw = new DatabaseSync(file);
  raw.exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL);
    INSERT INTO schema_migrations VALUES (1, 0);
    CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT, avatar_url TEXT,
      created_at BIGINT NOT NULL, last_login_at BIGINT, session_version INTEGER NOT NULL DEFAULT 0);`);
  raw.close();
  const db = await openDb({ sqliteFile: file });
  assert.ok(await db.get('SELECT version FROM schema_migrations WHERE version = 2'));
  await db.close();
});

test('safeRelPath neutralises Windows reserved names, ADS and trailing dots', () => {
  assert.equal(safeRelPath('src/CON'), 'src/_CON');
  assert.equal(safeRelPath('nul.txt'), '_nul.txt');
  assert.equal(safeRelPath('a/com1.js/lpt9'), 'a/_com1.js/_lpt9');
  assert.equal(safeRelPath('aux .txt'), '_aux .txt');
  assert.equal(safeRelPath('file.js:secret'), 'file.js_secret');
  assert.equal(safeRelPath('dir. /x.js. '), 'dir/x.js');
  assert.equal(safeRelPath('../.../a'), 'a');
  assert.equal(safeRelPath('C:\\x\\console.js'), 'x/console.js');
  assert.equal(safeRelPath('...'), null);
  assert.equal(safeRelPath('résumé/日本.py'), 'résumé/日本.py');
});
