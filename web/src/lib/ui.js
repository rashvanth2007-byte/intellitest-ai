/* Shared UI helpers: escaping, icons, toasts, modals, formatting, theme. */

export const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const P = {
  scan: '<path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3.5"/><path d="m16 16-1.5-1.5"/>',
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
  shield: '<path d="M12 3 5 6v5c0 5 3 8.5 7 10 4-1.5 7-5 7-10V6z"/><path d="m9 12 2 2 4-4"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  github: '<path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"/>',
  code: '<path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  sparkle: '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1"/>',
};
export function icon(name, cls = '') {
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

export function toast(msg, kind = '', ms = 4500) {
  const host = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.setAttribute('role', kind === 'err' ? 'alert' : 'status');
  el.innerHTML = `<div style="flex:1">${esc(msg)}</div><button class="icon-btn" aria-label="Dismiss">${icon('x')}</button>`;
  el.querySelector('button').onclick = () => el.remove();
  host.appendChild(el);
  if (ms) setTimeout(() => el.remove(), ms);
}

/** Simple modal. Returns a promise resolved with the clicked button value (or null when dismissed). */
let modalSeq = 0;
export function modal({ title, body, buttons = [{ label: 'Close', value: null, cls: 'btn-ghost' }], wide = false }) {
  return new Promise((resolve) => {
    const ov = document.createElement('div');
    const hid = `modal-h-${++modalSeq}`;
    const prevFocus = document.activeElement;
    ov.className = 'modal-overlay';
    ov.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-labelledby="${hid}" ${wide ? 'style="max-width:680px"' : ''}>
      <div class="modal-head"><h3 id="${hid}">${title}</h3><button class="icon-btn" data-v="__close" aria-label="Close">${icon('x')}</button></div>
      <div class="modal-body">${body}</div>
      ${buttons.length ? `<div class="modal-foot">${buttons.map((b, i) => `<button class="btn btn-sm ${b.cls || 'btn-ghost'}" data-i="${i}">${esc(b.label)}</button>`).join('')}</div>` : ''}
    </div>`;
    const close = (v) => {
      ov.remove();
      document.removeEventListener('keydown', onKey);
      if (prevFocus && document.contains(prevFocus)) prevFocus.focus?.();
      resolve(v);
    };
    const onKey = (e) => {
      // Only the top-most modal handles keys.
      if ([...document.querySelectorAll('.modal-overlay')].pop() !== ov) return;
      if (e.key === 'Escape') { e.preventDefault(); close(null); return; }
      if (e.key !== 'Tab') return;
      // Keep keyboard focus inside the dialog.
      const f = [...ov.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter((el) => !el.disabled);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (!ov.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    ov.addEventListener('click', (e) => {
      if (e.target === ov || e.target.closest('[data-v="__close"]')) return close(null);
      const b = e.target.closest('[data-i]');
      if (b) close(buttons[+b.dataset.i].value);
    });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(ov);
    ov.querySelector('.icon-btn')?.focus(); // safe default: never pre-focus a destructive action
  });
}

/** Only allow http(s) links from server/AI-provided data (blocks javascript: etc.). */
export const safeUrl = (u) => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '');

export const confirmDialog = (title, text, okLabel = 'Delete') =>
  modal({ title: esc(title), body: `<p>${esc(text)}</p>`, buttons: [{ label: 'Cancel', value: false }, { label: okLabel, value: true, cls: 'btn-danger' }] });

export function fmtTime(ts) {
  if (!ts) return '—';
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)}d ago`;
  return new Date(ts).toLocaleDateString();
}
export const fmtDate = (ts) => (ts ? new Date(ts).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—');
export const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
export const fmtNum = (n) => Number(n || 0).toLocaleString();
export const fmtDuration = (ms) => (ms == null ? '—' : ms < 1000 ? `${ms} ms` : ms < 60000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`);

export const SEVS = ['critical', 'high', 'medium', 'low'];
export const SEV_VAR = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)' };
export const AGENT_META = {
  sentinel: { name: 'SENTINEL', role: 'Security vulns' },
  phantom: { name: 'PHANTOM', role: 'Runtime & logic' },
  cipher: { name: 'CIPHER', role: 'Secrets & crypto' },
  nexus: { name: 'NEXUS', role: 'Deps & supply chain' },
  oracle: { name: 'ORACLE', role: 'API & data exposure' },
};
export const ENGINE_LABEL = { rules: 'Rules', secrets: 'Secrets', deps: 'Dependencies', ai: 'AI' };

export function applyTheme(theme) {
  try { localStorage.setItem('it_theme', theme); } catch { /* storage blocked */ }
  if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
export function initTheme() {
  let t = 'system';
  try { t = localStorage.getItem('it_theme') || 'system'; } catch { /* */ }
  applyTheme(t);
}

export function gradeColor(g) {
  return { A: 'var(--low)', B: 'var(--low)', C: 'var(--medium)', D: 'var(--high)', F: 'var(--critical)' }[g] || 'var(--text-mid)';
}

export function initials(name) {
  return String(name || '?').split(/\s+/).map((s) => s[0]).join('').slice(0, 2).toUpperCase();
}
