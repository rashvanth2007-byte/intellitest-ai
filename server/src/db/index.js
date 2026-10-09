/**
 * Tiny database adapter: SQLite (node:sqlite, zero native deps — used on localhost and in the
 * Windows app) or PostgreSQL (cloud). SQL is written with `?` placeholders and a portable subset.
 */
import { migrations } from './migrations.js';

let db = null;

export function getDb() {
  if (!db) throw new Error('Database not initialised');
  return db;
}

export async function openDb(cfg) {
  if (cfg.databaseUrl && /^postgres(ql)?:\/\//.test(cfg.databaseUrl)) {
    db = await openPostgres(cfg.databaseUrl);
  } else {
    db = await openSqlite(cfg.sqliteFile);
  }
  await migrate(db);
  return db;
}

async function openSqlite(file) {
  const { DatabaseSync } = await import('node:sqlite');
  const conn = new DatabaseSync(file);
  conn.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const norm = (params) => params.map((p) => (typeof p === 'boolean' ? (p ? 1 : 0) : p === undefined ? null : p));
  // Raw statements run directly on the one connection (used inside a transaction).
  const direct = {
    kind: 'sqlite',
    async all(sql, params = []) { return conn.prepare(sql).all(...norm(params)); },
    async get(sql, params = []) { return conn.prepare(sql).get(...norm(params)) || null; },
    async run(sql, params = []) { const r = conn.prepare(sql).run(...norm(params)); return { changes: Number(r.changes) }; },
    async exec(sql) { conn.exec(sql); },
    async tx(fn) { return fn(direct); }, // nested tx: already inside one
  };
  // One connection is shared by every request, so an async transaction must not interleave with
  // other callers: transactions are serialised, and outside statements wait for the active one.
  let active = null; // promise settled when the running transaction ends
  let tail = Promise.resolve();
  const idle = async () => { while (active) await active; };
  const api = {
    kind: 'sqlite',
    async all(sql, params) { await idle(); return direct.all(sql, params); },
    async get(sql, params) { await idle(); return direct.get(sql, params); },
    async run(sql, params) { await idle(); return direct.run(sql, params); },
    async exec(sql) { await idle(); return direct.exec(sql); },
    async tx(fn) {
      let release;
      const mine = new Promise((r) => { release = r; });
      const prev = tail;
      tail = prev.then(() => mine);
      await prev;
      active = mine;
      try {
        conn.exec('BEGIN');
        try { const r = await fn(direct); conn.exec('COMMIT'); return r; }
        catch (e) { try { conn.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; }
      } finally { active = null; release(); }
    },
    async close() { await idle(); conn.close(); },
  };
  return api;
}

/** True for UNIQUE / PRIMARY KEY violations on either backend (used to turn races into 409s). */
export function isUniqueViolation(e) {
  return e?.code === '23505' || /UNIQUE constraint failed|PRIMARY KEY constraint failed/i.test(String(e?.message || ''));
}

async function openPostgres(url) {
  const { default: pg } = await import('pg');
  pg.types.setTypeParser(20, (v) => Number(v));   // BIGINT -> number
  pg.types.setTypeParser(1700, (v) => Number(v)); // NUMERIC -> number
  const needsSsl = !/localhost|127\.0\.0\.1|@db[:/]/.test(url) && !/sslmode=disable/.test(url);
  const pool = new pg.Pool({
    connectionString: url,
    max: Number(process.env.PG_POOL_MAX) || 5,
    idleTimeoutMillis: 30000,
    ssl: needsSsl ? { rejectUnauthorized: false } : undefined,
  });
  pool.on('error', (e) => console.error('[db] idle client error', e.message));
  const toPg = (sql) => { let i = 0; return sql.replace(/\?/g, () => `$${++i}`); };
  const make = (q) => ({
    kind: 'postgres',
    async all(sql, params = []) { return (await q(toPg(sql), params)).rows; },
    async get(sql, params = []) { return (await q(toPg(sql), params)).rows[0] || null; },
    async run(sql, params = []) { const r = await q(toPg(sql), params); return { changes: r.rowCount }; },
    async exec(sql) { await q(sql); },
  });
  const api = make((s, p) => pool.query(s, p));
  api.tx = async (fn) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = await fn(make((s, p) => client.query(s, p)));
      await client.query('COMMIT');
      return r;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  };
  api.close = () => pool.end();
  return api;
}

async function migrate(d) {
  await d.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at BIGINT NOT NULL)');
  const done = new Set((await d.all('SELECT version FROM schema_migrations')).map((r) => Number(r.version)));
  for (const m of migrations) {
    if (done.has(m.version)) continue;
    await d.tx(async (t) => {
      for (const stmt of m.up) {
        const addCol = /^\s*ALTER TABLE .* ADD COLUMN/is.test(stmt);
        const pg = d.kind === 'postgres';
        if (addCol && pg) await t.exec('SAVEPOINT add_col'); // a failed statement would abort the whole PG transaction
        try { await t.exec(stmt); } catch (e) {
          // Idempotent on databases that already have the column (e.g. created by an older build).
          if (addCol && (e.code === '42701' || /duplicate column/i.test(e.message))) {
            if (pg) await t.exec('ROLLBACK TO SAVEPOINT add_col');
            continue;
          }
          throw e;
        }
      }
      await t.run('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)', [m.version, Date.now()]);
    });
    console.log(`[db] applied migration ${m.version} (${m.name})`);
  }
}
