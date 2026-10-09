import { get, del } from '../lib/api.js';
import { esc, icon, toast, confirmDialog, fmtDate } from '../lib/ui.js';
import { navigate, state } from '../main.js';
import { renderReport, maybeAlert } from '../components/report.js';
import { liveProgress } from '../components/live.js';

export async function renderScanPage(root, { params }) {
  const id = params[0];
  let stop = null;
  let disposed = false;
  root.innerHTML = `<div class="page"><div class="page-head"><div>
      <a href="#/history" class="dim" style="font-size:12px">← History</a>
      <div class="page-title" id="title">Loading…</div><div class="page-sub" id="sub"></div>
    </div></div><div id="body"><div class="spinner"></div></div></div>`;
  const body = root.querySelector('#body');

  const load = async (alert = false) => {
    let scan;
    try { scan = await get(`/scans/${encodeURIComponent(id)}`); } catch (e) {
      if (disposed) return;
      root.querySelector('#title').textContent = 'Scan not found';
      body.innerHTML = `<div class="card empty-state">${icon('alert')}<p>${esc(e.message)}</p></div>`;
      return;
    }
    if (disposed) return; // user navigated away while loading
    root.querySelector('#title').textContent = scan.label;
    root.querySelector('#sub').textContent = `${fmtDate(scan.createdAt)} · ${scan.sourceKind}${scan.status !== 'completed' ? ` · ${scan.status}` : ''}`;
    if (['queued', 'running'].includes(scan.status)) {
      stop = liveProgress(body, id, (done) => {
        stop = null;
        if (done.status === 'disconnected') {
          body.innerHTML = `<div class="card empty-state">${icon('alert')}<p>${esc(done.error)}</p><button class="btn btn-ghost btn-sm" id="retry">Retry</button></div>`;
          body.querySelector('#retry').onclick = () => load(true);
          return;
        }
        load(true);
      });
      return;
    }
    if (scan.status !== 'completed') {
      body.innerHTML = `<div class="card empty-state">${icon('alert')}<h3>Scan ${esc(scan.status)}</h3><p>${esc(scan.error || '')}</p>
        <div class="btn-row"><a class="btn btn-primary btn-sm" href="#/scanner">New scan</a><button class="btn btn-danger btn-sm" id="del">Delete</button></div></div>`;
      body.querySelector('#del').onclick = remove;
      return;
    }
    renderReport(body, scan, { onDelete: remove });
    if (alert) maybeAlert(scan, state.settings?.alertThreshold || 'critical');
  };

  async function remove() {
    if (!(await confirmDialog('Delete scan?', 'This permanently removes the scan and its findings.'))) return;
    try { await del(`/scans/${encodeURIComponent(id)}`); toast('Scan deleted', 'ok'); navigate('#/history'); } catch (e) { toast(e.message, 'err'); }
  }

  await load();
  return () => { disposed = true; stop?.(); };
}
