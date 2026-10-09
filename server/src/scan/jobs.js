import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { runScan, cleanupWorkDir } from './pipeline.js';
import { publish } from './events.js';

/** Simple in-process FIFO queue with bounded concurrency. */
const queue = [];
const running = new Map(); // scanId -> job

export function enqueue(job) {
  job.controller = new AbortController();
  queue.push(job);
  pump();
}

export function cancel(scanId) {
  const qi = queue.findIndex((j) => j.id === scanId);
  if (qi >= 0) {
    const [job] = queue.splice(qi, 1);
    finish(job, 'cancelled', 'Cancelled before start');
    return true;
  }
  const job = running.get(scanId);
  if (job) { job.controller.abort(); return true; }
  return false;
}

export const queuePosition = (scanId) => queue.findIndex((j) => j.id === scanId);

function pump() {
  while (running.size < config.limits.concurrentScans && queue.length) {
    const job = queue.shift();
    running.set(job.id, job);
    runScan(job)
      .then(() => publish(job.id, 'done', { status: 'completed' }))
      .catch((e) => {
        const cancelled = e.name === 'AbortError' || job.controller.signal.aborted;
        if (!cancelled && !e.userFacing && !e.status) console.error(`[scan ${job.id}]`, e);
        const msg = String(e.message || 'Scan failed').split(config.tmpDir).join('').split(config.dataDir).join('');
        return finish(job, cancelled ? 'cancelled' : 'failed', cancelled ? 'Cancelled' : msg);
      })
      .finally(() => {
        running.delete(job.id);
        cleanupWorkDir(job.workDir);
        runCleanup(job);
        pump();
      });
  }
}

async function finish(job, status, error) {
  try {
    await getDb().run('UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?', [status, String(error).slice(0, 1000), Date.now(), job.id]);
  } catch (e) { console.error('[jobs] could not record failure', e.message); }
  publish(job.id, 'done', { status, error });
  if (!running.has(job.id)) { cleanupWorkDir(job.workDir); runCleanup(job); }
}

/** Upload cleanup must never throw: a throw in .finally() would stall the queue and surface as an unhandled rejection. */
function runCleanup(job) {
  try { job.cleanup?.(); } catch (e) { console.warn('[jobs] upload cleanup failed', e.message); }
}

/** On boot: scans left running by a previous process can't resume (their temp sources are gone). */
export async function recoverInterrupted() {
  const r = await getDb().run(
    "UPDATE scans SET status = 'failed', error = 'Interrupted by a server restart — please run the scan again.', finished_at = ? WHERE status IN ('queued', 'running')",
    [Date.now()],
  );
  if (r.changes) console.log(`[jobs] marked ${r.changes} interrupted scan(s) as failed`);
}
