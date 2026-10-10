import './styles.css';
import { get, post, setUnauthorizedHandler } from './lib/api.js';
import { esc, icon, initials, initTheme, applyTheme, toast, safeUrl } from './lib/ui.js';
import { renderAuth } from './pages/auth.js';
import { renderScanner, clearScannerDraft } from './pages/scanner.js';
import { renderDashboard } from './pages/dashboard.js';
import { renderHistory } from './pages/history.js';
import { renderScanPage } from './pages/scan.js';
import { renderSettings } from './pages/settings.js';

initTheme();

/** Global app state shared with pages. */
export const state = { user: null, providers: { github: false, registration: true }, settings: null, keys: null, options: null };

const app = document.getElementById('app');
let cleanup = null;
let routeSeq = 0;

const ROUTES = {
  scanner: { title: 'Scanner', render: renderScanner, nav: 'scanner' },
  dashboard: { title: 'Dashboard', render: renderDashboard, nav: 'dashboard' },
  history: { title: 'History', render: renderHistory, nav: 'history' },
  scan: { title: 'Scan report', render: renderScanPage, nav: 'history' },
  settings: { title: 'Settings', render: renderSettings, nav: 'settings' },
};

export function navigate(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

export async function refreshSession() {
  const me = await get('/auth/me');
  state.user = me.user;
  state.providers = me.providers;
  if (state.user) await refreshSettings();
  return me;
}

export async function refreshSettings() {
  const s = await get('/settings');
  state.settings = s.settings;
  state.keys = s.keys;
  state.options = s.options;
  state.githubOAuth = s.githubOAuth || null;
  applyTheme(s.settings.theme);
  updateEnginePill();
}

/** Human description of the engine the next scan will use. */
export function engineSummary() {
  const s = state.settings, k = state.keys;
  if (!s || !k) return { ai: false, label: 'Rules' };
  const has = (p) => !!(k[p]?.user || k[p]?.server);
  const model = (id) => [...(state.options?.claudeModels || []), ...(state.options?.geminiModels || [])].find((m) => m.id === id)?.label.split(' — ')[0] || id;
  if (s.engine === 'rules') return { ai: false, label: 'Rules + secrets + CVEs', detail: 'AI agents disabled' };
  if ((s.engine === 'claude' || s.engine === 'auto') && has('anthropic')) return { ai: true, label: model(s.claudeModel), detail: `${s.aiDepth} depth` };
  if ((s.engine === 'gemini' || s.engine === 'auto') && has('gemini')) return { ai: true, label: model(s.geminiModel), detail: `${s.aiDepth} depth` };
  return { ai: false, label: 'Rules only', detail: 'no AI key on the server', missingKey: true };
}

function updateEnginePill() {
  const el = document.getElementById('enginePill');
  if (!el) return;
  const e = engineSummary();
  el.innerHTML = `<div class="dot ${e.ai ? '' : 'off'}"></div><span>Engine:</span> <b title="${esc(e.label)}">${esc(e.label)}</b>`;
}

function shell() {
  const u = state.user;
  app.innerHTML = `
  <div class="scrim" id="scrim"></div>
  <div class="shell">
    <nav class="sidebar" id="sidebar" aria-label="Main">
      <div class="brand"><div class="brand-mark">${icon('shield')}</div><div class="brand-name">Intelli<span>Test</span> AI</div></div>
      <div class="nav">
        <a class="nav-item" data-nav="scanner" href="#/scanner">${icon('scan')}Scanner</a>
        <a class="nav-item" data-nav="dashboard" href="#/dashboard">${icon('dashboard')}Dashboard</a>
        <a class="nav-item" data-nav="history" href="#/history">${icon('history')}History</a>
        <a class="nav-item" data-nav="settings" href="#/settings">${icon('settings')}Settings</a>
      </div>
      <div class="sidebar-foot">
        <a class="engine-pill" id="enginePill" href="#/settings" style="text-decoration:none"></a>
        <div class="user-chip">
          <div class="avatar">${safeUrl(u.avatarUrl) ? `<img src="${esc(safeUrl(u.avatarUrl))}" alt="">` : esc(initials(u.name))}</div>
          <div class="who"><b>${esc(u.name)}</b><span>${esc(u.email)}</span></div>
          <button class="icon-btn" id="logoutBtn" title="Sign out" aria-label="Sign out">${icon('logout')}</button>
        </div>
      </div>
    </nav>
    <div class="main">
      <div class="topbar">
        <button class="icon-btn" id="menuBtn" aria-label="Open menu">${icon('menu')}</button>
        <div class="topbar-title" id="topbarTitle"></div>
      </div>
      <main id="view"></main>
    </div>
  </div>`;
  const sb = document.getElementById('sidebar');
  const scrim = document.getElementById('scrim');
  const menuBtn = document.getElementById('menuBtn');
  const close = () => { sb.classList.remove('open'); scrim.classList.remove('on'); menuBtn.setAttribute('aria-expanded', 'false'); };
  menuBtn.setAttribute('aria-expanded', 'false');
  menuBtn.onclick = () => { sb.classList.add('open'); scrim.classList.add('on'); menuBtn.setAttribute('aria-expanded', 'true'); sb.querySelector('a')?.focus(); };
  sb.addEventListener('keydown', (e) => { if (e.key === 'Escape' && sb.classList.contains('open')) { close(); menuBtn.focus(); } });
  scrim.onclick = close;
  sb.addEventListener('click', (e) => { if (e.target.closest('a')) close(); });
  document.getElementById('logoutBtn').onclick = async (e) => {
    e.currentTarget.disabled = true;
    await post('/auth/logout').catch(() => {});
    signedOut();
  };
  updateEnginePill();
}

async function route() {
  const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
  const [name = 'scanner', ...params] = path.split('/').filter(Boolean).map(decodeURIComponent);
  if (typeof cleanup === 'function') { try { cleanup(); } catch { /* */ } }
  cleanup = null;
  const seq = ++routeSeq;

  if (!state.user) {
    if (name !== 'login' && name !== 'register') { sessionStorageSet('it_after_login', location.hash); location.replace('#/login'); return; }
    cleanup = renderAuth(app, { mode: name, params: new URLSearchParams(query) });
    document.title = 'Sign in — IntelliTest AI';
    return;
  }
  if (name === 'login' || name === 'register') { location.replace(sessionStorageTake('it_after_login') || '#/scanner'); return; }
  const r = ROUTES[name] || ROUTES.scanner;
  if (!document.getElementById('view')) shell();
  document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav === r.nav));
  document.getElementById('topbarTitle').textContent = r.title;
  document.title = `${r.title} — IntelliTest AI`;
  // Fresh container per route: a slow page that resolves after the user navigated away
  // writes into a detached node instead of clobbering the new page.
  const oldView = document.getElementById('view');
  const view = oldView.cloneNode(false);
  oldView.replaceWith(view);
  window.scrollTo(0, 0);
  try {
    const c = await r.render(view, { params });
    if (seq !== routeSeq) { if (typeof c === 'function') { try { c(); } catch { /* */ } } return; }
    cleanup = c;
  } catch (e) {
    if (seq !== routeSeq) return;
    view.innerHTML = `<div class="page"><div class="empty-state">${icon('alert')}<h3>Something went wrong</h3><p>${esc(e.message)}</p></div></div>`;
  }
}

function sessionStorageSet(k, v) { try { sessionStorage.setItem(k, v); } catch { /* */ } }
function sessionStorageTake(k) { try { const v = sessionStorage.getItem(k); sessionStorage.removeItem(k); return v; } catch { return null; } }

/** Forget everything about the previous user and show the sign-in page (logout, account deletion). */
export function signedOut() {
  Object.assign(state, { user: null, settings: null, keys: null, options: null });
  clearScannerDraft(); // the next user must not see this user's selected files
  sessionStorageTake('it_after_login'); // never carry one user's deep link over to the next sign-in
  app.innerHTML = '';
  navigate('#/login');
}

export async function onSignedIn() {
  await refreshSession();
  app.innerHTML = '';
  route();
}

setUnauthorizedHandler(() => {
  if (!state.user) return;
  const here = location.hash;
  Object.assign(state, { user: null, settings: null, keys: null, options: null });
  clearScannerDraft(); // the next user must not see this user's selected files
  toast('Your session expired or was signed out elsewhere — please sign in again.', 'err');
  if (here && !/^#\/(login|register)/.test(here)) sessionStorageSet('it_after_login', here); // come back here after signing in
  app.innerHTML = '';
  navigate('#/login');
});

window.addEventListener('hashchange', () => {
  if (state.user && !document.getElementById('view') && !/^#\/(login|register)/.test(location.hash)) app.innerHTML = '';
  route();
});

(async () => {
  try {
    await refreshSession();
  } catch (e) {
    app.innerHTML = `<div class="boot"><div class="empty-state">${icon('alert')}<h3>Cannot reach the server</h3><p>${esc(e.message)}</p><button class="btn btn-primary btn-sm" onclick="location.reload()">Retry</button></div></div>`;
    return;
  }
  route();
})();
