import fs from 'node:fs';
import path from 'node:path';
import { Router } from 'express';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { requireAuth } from '../auth/session.js';
import { ah, HttpError, parseJson } from '../util/http.js';
import { newId } from '../util/crypto.js';
import { parseGithubUrl } from '../ingest/github.js';
import { enqueue, cancel, queuePosition } from './jobs.js';
import { workDirFor } from './pipeline.js';
import { subscribe, snapshot, finalState } from './events.js';
import { renderReport } from '../reports/index.js';

export const scanRouter = Router();
scanRouter.use(requireAuth);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => {
      req.uploadDir ||= fs.mkdtempSync(path.join(config.tmpDir, 'up-'));
      cb(null, req.uploadDir);
    },
    filename: (_req, _file, cb) => cb(null, newId()),
  }),
  limits: { fileSize: config.limits.uploadBytes, files: 5000, fields: 20, fieldSize: 2 * 1024 * 1024 },
  defParamCharset: 'utf8', // browsers send UTF-8 filenames; the latin1 default garbles "résumé.py" / "日本.js"
});

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: (req) => req.user.id,
  message: { error: 'Too many scans started — wait a minute.' },
});

/** Never throws: it runs inside multer's callback, where a throw would crash the process. */
const rmUploads = (req) => {
  if (!req.uploadDir) return;
  const dir = req.uploadDir;
  const rm = () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  // Windows: a write stream of an aborted upload may still hold a file open, retry once later.
  try { rm(); } catch { setTimeout(() => { try { rm(); } catch (e) { console.warn('[scan] upload cleanup failed', e.message); } }, 2000).unref(); }
};

const MAX_ACTIVE_PER_USER = 3;
const MAX_ACTIVE_TOTAL = 50;

/* Create a scan */
scanRouter.post('/', scanLimiter, ah(async (req, _res, next) => {
  // Reject oversized bodies before writing anything to disk (multer only caps each file).
  const len = Number(req.get('content-length') || 0);
  if (len > config.limits.uploadBytes + 1024 * 1024) throw new HttpError(413, `Upload is larger than ${Math.round(config.limits.uploadBytes / 1048576)} MB.`);
  const db = getDb();
  const mine = await db.get("SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND status IN ('queued','running')", [req.user.id]);
  if (Number(mine.n) >= MAX_ACTIVE_PER_USER) throw new HttpError(429, `You already have ${MAX_ACTIVE_PER_USER} scans in progress — wait for one to finish.`);
  const all = await db.get("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')");
  if (Number(all.n) >= MAX_ACTIVE_TOTAL) throw new HttpError(503, 'The scanner is busy — try again in a few minutes.');
  next();
}), (req, res, next) => {
  // multer only caps each file; a chunked body (no Content-Length) could still stream thousands of them.
  const maxTotal = config.limits.uploadBytes + 1024 * 1024;
  let got = 0;
  const count = (c) => {
    got += c.length;
    if (got > maxTotal) { req.off('data', count); req.destroy(Object.assign(new Error('Upload too large'), { code: 'LIMIT_TOTAL' })); }
  };
  req.on('data', count);
  upload.array('files')(req, res, (err) => {
    req.off('data', count);
    if (err) {
      rmUploads(req);
      const tooBig = err.code === 'LIMIT_FILE_SIZE' || err.code === 'LIMIT_TOTAL';
      return next(new HttpError(tooBig ? 413 : 400,
        tooBig ? `Upload is larger than ${Math.round(config.limits.uploadBytes / 1048576)} MB.` : err.message));
    }
    next();
  });
}, ah(async (req, res) => {
  try {
    req.body ||= {}; // Express 5 leaves req.body undefined when the request has no parsed body
    const kind = String(req.body.kind || '');
    const id = newId();
    const workDir = workDirFor(id);
    let source, label, sourceRef = null;

    if (kind === 'paste') {
      const code = String(req.body.code || '');
      if (code.trim().length < 8) throw new HttpError(400, 'Paste some code to scan.');
      if (code.length > 2 * 1024 * 1024) throw new HttpError(413, 'Pasted code is larger than 2 MB — upload a file or zip instead.');
      const filename = String(req.body.filename || 'snippet.txt').slice(0, 120);
      source = { kind, code, filename };
      label = `Pasted code (${filename})`;
    } else if (kind === 'github') {
      const parsed = parseGithubUrl(req.body.url);
      if (!parsed) throw new HttpError(400, 'Enter a GitHub repository URL like https://github.com/owner/repo');
      source = { kind, url: String(req.body.url) };
      label = `${parsed.owner}/${parsed.repo}${parsed.ref ? `@${parsed.ref}` : ''}${parsed.subdir ? `/${parsed.subdir}` : ''}`;
      sourceRef = `https://github.com/${parsed.owner}/${parsed.repo}`;
    } else if (kind === 'files' || kind === 'zip') {
      const files = req.files || [];
      if (!files.length) throw new HttpError(400, 'Choose files, a folder or a .zip to scan.');
      const paths = parseJson(req.body.paths, []);
      const uploads = files.map((f, i) => ({ tmpPath: f.path, relPath: String((Array.isArray(paths) && paths[i]) || f.originalname) }));
      if (files.length === 1 && /\.zip$/i.test(uploads[0].relPath)) {
        source = { kind: 'zip', zipPath: uploads[0].tmpPath };
        label = uploads[0].relPath.split('/').pop();
      } else {
        source = { kind: 'files', uploads };
        const roots = [...new Set(uploads.map((u) => String(u.relPath).replace(/\\/g, '/').split('/')[0]))];
        label = roots.length === 1 && uploads.length > 1 ? `${roots[0]}/ (${uploads.length} files)` : uploads.length === 1 ? uploads[0].relPath : `${uploads.length} files`;
      }
    } else {
      throw new HttpError(400, 'Unknown scan type.');
    }

    const now = Date.now();
    await getDb().run(
      'INSERT INTO scans (id, user_id, label, source_kind, source_ref, status, progress, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, req.user.id, label.slice(0, 200), source.kind, sourceRef, 'queued', JSON.stringify({ stage: 'queued', message: 'Waiting in queue…' }), now],
    );
    const uploadDir = req.uploadDir;
    enqueue({ id, userId: req.user.id, source, workDir, cleanup: () => uploadDir && fs.rmSync(uploadDir, { recursive: true, force: true }) });
    res.status(202).json({ id, status: 'queued', position: queuePosition(id) });
  } catch (e) {
    rmUploads(req);
    throw e;
  }
}));

function scanRow(r) {
  return {
    id: r.id, label: r.label, sourceKind: r.source_kind, sourceRef: r.source_ref, status: r.status,
    engine: r.engine, aiModel: r.ai_model, counts: parseJson(r.counts, { critical: 0, high: 0, medium: 0, low: 0 }),
    total: Number(r.total || 0), score: r.score == null ? null : Number(r.score), grade: r.grade,
    filesScanned: Number(r.files_scanned || 0), linesScanned: Number(r.lines_scanned || 0),
    warnings: parseJson(r.warnings, []), error: r.error, durationMs: r.duration_ms == null ? null : Number(r.duration_ms),
    createdAt: Number(r.created_at), finishedAt: r.finished_at == null ? null : Number(r.finished_at),
    progress: r.progress !== undefined ? parseJson(r.progress, null) : undefined,
  };
}

export function findingRow(f) {
  return {
    id: f.id, severity: f.severity, title: f.title, category: f.category, cwe: f.cwe, owasp: f.owasp,
    cvss: f.cvss == null ? null : Number(f.cvss), file: f.file, line: f.line == null ? null : Number(f.line),
    snippet: parseJson(f.snippet, null), description: f.description, impact: f.impact, recommendation: f.recommendation,
    engines: String(f.engines || '').split(',').filter(Boolean), agent: f.agent, ruleId: f.rule_id, confidence: f.confidence,
    extra: parseJson(f.extra, null),
  };
}

export async function loadScan(userId, id, withFindings = true) {
  const db = getDb();
  const s = await db.get('SELECT * FROM scans WHERE id = ? AND user_id = ?', [id, userId]);
  if (!s) throw new HttpError(404, 'Scan not found.');
  const scan = scanRow(s);
  if (withFindings) {
    const rows = await db.all('SELECT * FROM findings WHERE scan_id = ?', [id]);
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    scan.findings = rows.map(findingRow).sort((a, b) => rank[a.severity] - rank[b.severity] || (b.cvss || 0) - (a.cvss || 0));
  }
  return scan;
}

/* List scans (history) */
scanRouter.get('/', ah(async (req, res) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
  const offset = Math.min(1e6, Math.max(0, parseInt(req.query.offset, 10) || 0)); // huge values would overflow the SQL integer bind
  const q = String(req.query.q || '').trim().toLowerCase().slice(0, 200);
  const db = getDb();
  const where = ['user_id = ?'];
  const params = [req.user.id];
  if (q) { where.push('LOWER(label) LIKE ?'); params.push(`%${q.replace(/[%_]/g, '')}%`); }
  const rows = await db.all(
    `SELECT id, label, source_kind, source_ref, status, engine, ai_model, counts, total, score, grade, files_scanned, lines_scanned, warnings, error, duration_ms, created_at, finished_at
     FROM scans WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
  const { n } = await db.get(`SELECT COUNT(*) AS n FROM scans WHERE ${where.join(' AND ')}`, params);
  res.json({ scans: rows.map(scanRow), total: Number(n) });
}));

/* Dashboard aggregates */
scanRouter.get('/stats', ah(async (req, res) => {
  const db = getDb();
  const rows = await db.all("SELECT id, label, status, counts, total, score, grade, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 500", [req.user.id]);
  const done = rows.filter((r) => r.status === 'completed');
  const totals = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of done) { const c = parseJson(r.counts, {}); for (const k of Object.keys(totals)) totals[k] += c[k] || 0; }
  const cats = await db.all(
    `SELECT category, COUNT(*) AS n FROM findings WHERE user_id = ? GROUP BY category ORDER BY n DESC LIMIT 8`, [req.user.id]);
  const engines = await db.all(`SELECT engines, COUNT(*) AS n FROM findings WHERE user_id = ? GROUP BY engines`, [req.user.id]);
  const byEngine = {};
  for (const e of engines) for (const k of String(e.engines).split(',')) byEngine[k] = (byEngine[k] || 0) + Number(e.n);
  res.json({
    scans: rows.length,
    completed: done.length,
    findings: done.reduce((n, r) => n + Number(r.total || 0), 0),
    totals,
    avgScore: done.length ? Math.round(done.reduce((n, r) => n + Number(r.score || 0), 0) / done.length) : null,
    trend: done.slice(0, 20).reverse().map((r) => ({ id: r.id, label: r.label, score: Number(r.score), total: Number(r.total), at: Number(r.created_at) })),
    topCategories: cats.map((c) => ({ category: c.category, count: Number(c.n) })),
    byEngine,
    recent: rows.slice(0, 6).map((r) => ({ id: r.id, label: r.label, status: r.status, grade: r.grade, total: Number(r.total || 0), at: Number(r.created_at) })),
  });
}));

scanRouter.get('/:id', ah(async (req, res) => {
  res.json(await loadScan(req.user.id, req.params.id));
}));

/* Live progress via Server-Sent Events */
scanRouter.get('/:id/events', ah(async (req, res) => {
  const scan = await loadScan(req.user.id, req.params.id, false);
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  const send = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  if (!['queued', 'running'].includes(scan.status)) {
    send('done', { status: scan.status, error: scan.error });
    return res.end();
  }
  send('progress', snapshot(scan.id) || scan.progress || { stage: scan.status });
  const unsub = subscribe(scan.id, ({ type, data }) => {
    send(type, data);
    if (type === 'done') { unsub(); clearInterval(ping); res.end(); }
  });
  const ping = setInterval(() => res.write(': ping\n\n'), 20000);
  res.on('close', () => { unsub(); clearInterval(ping); }); // client went away (or we ended the stream)
  // The scan may have finished between the DB read above and subscribing: don't leave the stream hanging.
  const fin = finalState(scan.id);
  if (fin) { unsub(); clearInterval(ping); send('done', fin); res.end(); }
}));

scanRouter.post('/:id/cancel', ah(async (req, res) => {
  await loadScan(req.user.id, req.params.id, false);
  res.json({ ok: cancel(req.params.id) });
}));

scanRouter.delete('/:id', ah(async (req, res) => {
  const scan = await loadScan(req.user.id, req.params.id, false);
  if (['queued', 'running'].includes(scan.status)) cancel(scan.id);
  const db = getDb();
  await db.tx(async (t) => {
    await t.run('DELETE FROM findings WHERE scan_id = ?', [scan.id]);
    await t.run('DELETE FROM scans WHERE id = ?', [scan.id]);
  });
  res.json({ ok: true });
}));

scanRouter.delete('/', ah(async (req, res) => {
  const db = getDb();
  const active = await db.all("SELECT id FROM scans WHERE user_id = ? AND status IN ('queued','running')", [req.user.id]);
  active.forEach((s) => cancel(s.id));
  await db.tx(async (t) => {
    await t.run('DELETE FROM findings WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM scans WHERE user_id = ?', [req.user.id]);
  });
  res.json({ ok: true });
}));

/* Reports: json | html | sarif | csv */
scanRouter.get('/:id/report.:fmt', ah(async (req, res) => {
  const scan = await loadScan(req.user.id, req.params.id);
  const { body, type, ext } = renderReport(scan, req.params.fmt);
  const safe = scan.label.replace(/[^\p{L}\p{N}_.-]+/gu, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 60) || 'scan';
  // res.attachment() emits an ASCII fallback plus RFC 5987 filename* for non-ASCII labels (a raw header would throw).
  if (req.query.inline !== '1') res.attachment(`intellitest-${safe}.${ext}`);
  res.set('Content-Type', type);
  res.send(body);
}));
