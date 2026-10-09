import { get, del } from '../lib/api.js';
import { esc, icon, toast, confirmDialog, fmtDate, gradeColor } from '../lib/ui.js';

const PAGE = 30;
const KIND = { files: 'Files', zip: 'ZIP', paste: 'Paste', github: 'GitHub' };

export async function renderHistory(root) {
  let offset = 0, total = 0, q = '', timer, seq = 0;
  root.innerHTML = `<div class="page">
    <div class="page-head"><div><div class="page-title">History</div><div class="page-sub">Every scan saved to your account.</div></div></div>
    <div class="toolbar">
      <input class="input" id="q" type="search" placeholder="Search scans…" aria-label="Search scans">
      <div class="btn-row" style="align-items:center"><span class="dim" id="count" style="font-size:12px"></span>
        <button class="btn btn-danger btn-sm" id="clearAll">${icon('trash')}Clear all</button></div>
    </div>
    <div class="hist-table" id="list"></div>
    <div style="text-align:center;margin-top:14px"><button class="btn btn-ghost btn-sm hidden" id="more">Load more</button></div>
  </div>`;
  const list = root.querySelector('#list');

  // The row is a <div>: the scan name is the real link (stretched over the row with CSS), and the
  // delete button is a sibling, not nested inside the link (interactive content can't nest in <a>).
  const row = (s) => `<div class="hist-row" data-id="${esc(s.id)}">
      <span class="grade-pill" style="color:${gradeColor(s.grade)}">${s.status === 'completed' ? esc(s.grade || '–') : s.status === 'failed' ? '!' : s.status === 'cancelled' ? '×' : '…'}</span>
      <div style="min-width:0"><a class="hr-name hr-link" href="#/scan/${encodeURIComponent(s.id)}">${esc(s.label)}</a>
        <div class="hr-time">${fmtDate(s.createdAt)} · ${esc(KIND[s.sourceKind] || s.sourceKind)} · ${esc(s.aiModel || s.engine || 'rules')}${s.status !== 'completed' ? ` · ${esc(s.status)}` : ''}</div></div>
      <div class="hr-sevs">${s.status === 'completed'
        ? (Object.entries(s.counts || {}).filter(([, n]) => n > 0).map(([k, n]) => `<span class="badge ${esc(k)}">${esc(n)} ${esc(k)}</span>`).join('') || '<span class="badge low">clean</span>')
        : s.error ? `<span class="dim" style="font-size:11px">${esc(s.error.slice(0, 60))}</span>` : ''}</div>
      <div class="hr-total">${s.status === 'completed' ? `${esc(s.total)} total` : ''}</div>
      <button class="icon-btn hr-del" type="button" data-del="${esc(s.id)}" title="Delete scan" aria-label="Delete scan ${esc(s.label)}">${icon('trash')}</button>
    </div>`;

  const setCount = () => { root.querySelector('#count').textContent = `${total} scan${total === 1 ? '' : 's'}`; };
  const showEmpty = () => { list.innerHTML = `<div class="card empty-state">${icon('history')}<h3>${q ? 'No matching scans' : 'No scans yet'}</h3><p>${q ? 'Try another search.' : 'Run a scan to see it here.'}</p></div>`; };

  async function load(reset) {
    const my = ++seq; // ignore responses from superseded requests (fast typing, double clicks)
    const more = root.querySelector('#more');
    if (reset) { offset = 0; list.innerHTML = '<div class="spinner"></div>'; }
    more.disabled = true;
    let r;
    try { r = await get(`/scans?limit=${PAGE}&offset=${offset}&q=${encodeURIComponent(q)}`); }
    catch (ex) {
      if (my !== seq) return;
      more.disabled = false;
      if (reset) list.innerHTML = '';
      return toast(ex.message, 'err');
    }
    if (my !== seq) return;
    more.disabled = false;
    total = r.total;
    if (reset) list.innerHTML = '';
    list.insertAdjacentHTML('beforeend', r.scans.map(row).join(''));
    offset += r.scans.length;
    if (!total) showEmpty();
    setCount();
    more.classList.toggle('hidden', offset >= total);
  }

  list.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-del]');
    if (!b || b.disabled) return;
    e.preventDefault();
    e.stopPropagation();
    if (!(await confirmDialog('Delete scan?', 'This permanently removes the scan and its findings.'))) return;
    b.disabled = true;
    try {
      await del(`/scans/${encodeURIComponent(b.dataset.del)}`);
      if (!b.isConnected) return; // list was reloaded meanwhile
      b.closest('.hist-row').remove();
      total--; offset--; // keep "Load more" paging aligned after removing a row
      if (!total) showEmpty();
      setCount();
    }
    catch (ex) { b.disabled = false; toast(ex.message, 'err'); }
  });
  root.querySelector('#q').addEventListener('input', (e) => { clearTimeout(timer); timer = setTimeout(() => { q = e.target.value.trim(); load(true); }, 250); });
  root.querySelector('#more').onclick = () => load(false);
  const clearBtn = root.querySelector('#clearAll');
  clearBtn.onclick = async () => {
    if (!(await confirmDialog('Delete all scans?', 'Every scan and finding on your account will be permanently removed.', 'Delete all'))) return;
    clearBtn.disabled = true;
    try { await del('/scans'); toast('History cleared', 'ok'); await load(true); } catch (ex) { toast(ex.message, 'err'); }
    clearBtn.disabled = false;
  };
  await load(true);
  return () => clearTimeout(timer);
}
