import { post } from '../lib/api.js';
import { esc, icon, AGENT_META, toast } from '../lib/ui.js';
import { findingList, wireCards } from './report.js';

const STAGES = [['ingest', 'Ingest'], ['rules', 'Rule engine'], ['secrets', 'Secrets'], ['deps', 'Dependencies / CVEs'], ['ai', 'AI agents']];

export function agentsRow(progress) {
  return `<div class="agents-row">${Object.entries(AGENT_META).map(([id, m]) => {
    const a = progress?.agents?.[id] || { status: 'idle', static: 0, ai: 0 };
    const n = (a.static || 0) + (a.ai || 0);
    return `<div class="ag-card ${esc(a.status)}" title="${a.message ? esc(a.message) : ''}">
      <div class="ag-top"><div class="ag-name">${m.name}</div><div class="ag-dot"></div></div>
      <div class="ag-role">${m.role}</div>
      <div class="ag-count">${a.status === 'off' ? '–' : esc(n)}<small>${a.status === 'off' ? 'disabled' : a.ai ? `${esc(a.ai)} AI` : 'found'}</small></div>
    </div>`;
  }).join('')}</div>`;
}

/**
 * Subscribe to a running scan and render live progress into root.
 * onDone(status) fires once when the scan finishes. Returns an unsubscribe function.
 */
export function liveProgress(root, scanId, onDone) {
  let progress = null;
  const findings = [];
  root.innerHTML = `
    <div id="lpAgents">${agentsRow(null)}</div>
    <div class="stepper" id="lpSteps"></div>
    <div class="live-status"><div class="spinner"></div><div style="flex:1" id="lpMsg">Starting…</div>
      <button class="btn btn-ghost btn-sm" id="lpCancel" type="button">${icon('stop')}Cancel</button></div>
    <div id="lpFindings"></div>`;
  const fl = root.querySelector('#lpFindings');
  const openSet = new Set(); // keeps expanded cards open while new findings stream in
  wireCards(fl, openSet);

  const paint = () => {
    if (!progress) return;
    root.querySelector('#lpAgents').innerHTML = agentsRow(progress);
    root.querySelector('#lpSteps').innerHTML = STAGES.map(([k, l]) => `<span class="step ${esc(progress.stages?.[k] || 'pending')}"><i></i>${l}</span>`).join('');
    root.querySelector('#lpMsg').textContent = progress.message || '';
  };
  let pending = false;
  const paintFindings = () => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      const rank = { critical: 0, high: 1, medium: 2, low: 3 };
      findings.sort((a, b) => rank[a.severity] - rank[b.severity] || (b.cvss || 0) - (a.cvss || 0));
      if (finished && !root.isConnected) return;
      fl.innerHTML = findingList(findings, 'live', openSet);
    });
  };

  const sid = encodeURIComponent(scanId);
  const cancelBtn = root.querySelector('#lpCancel');
  cancelBtn.onclick = async () => {
    cancelBtn.disabled = true;
    try {
      const r = await post(`/scans/${sid}/cancel`);
      if (r && r.ok === false && !finished) { cancelBtn.disabled = false; toast('The scan could not be cancelled (it may be finishing).', 'err'); }
      else root.querySelector('#lpMsg').textContent = 'Cancelling…';
    } catch (ex) { cancelBtn.disabled = false; toast(ex.message, 'err'); }
  };

  let finished = false;
  const parse = (e) => { try { return JSON.parse(e.data); } catch { return null; } };
  const es = new EventSource(`/api/scans/${sid}/events`);
  es.addEventListener('progress', (e) => { const p = parse(e); if (p && !finished) { progress = p; paint(); } });
  es.addEventListener('findings', (e) => { const f = parse(e); if (Array.isArray(f) && !finished) { findings.push(...f); paintFindings(); } });
  es.addEventListener('done', (e) => {
    if (finished) return;
    finished = true;
    es.close();
    Promise.resolve().then(() => onDone(parse(e) || { status: 'failed', error: 'Unexpected response from the server.' }))
      .catch((ex) => toast(ex?.message || String(ex), 'err'));
  });
  es.onerror = () => {
    // EventSource auto-reconnects; if the scan already ended the server answers with "done".
    if (finished) { es.close(); return; }
    // A non-200 answer (401/404/500) closes the stream for good — don't leave the spinner running forever.
    if (es.readyState === EventSource.CLOSED) {
      finished = true;
      Promise.resolve().then(() => onDone({ status: 'disconnected', error: 'Lost connection to the live progress stream. Open the scan from History to check its status.' }))
        .catch((ex) => toast(ex?.message || String(ex), 'err'));
    }
  };
  return () => { finished = true; es.close(); };
}
