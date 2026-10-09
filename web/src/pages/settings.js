import { put, del, post } from '../lib/api.js';
import { esc, icon, toast, confirmDialog, applyTheme, fmtTime, initials, safeUrl, modal } from '../lib/ui.js';
import { state, refreshSettings, refreshSession, signedOut } from '../main.js';

const KEY_INFO = {
  anthropic: { title: 'Anthropic (Claude) API key', ph: 'sk-ant-…', help: 'Create one at console.anthropic.com → API keys.' },
  gemini: { title: 'Google Gemini API key', ph: 'AIza…', help: 'Create one at aistudio.google.com → Get API key.' },
  github: { title: 'GitHub personal access token', ph: 'github_pat_… or ghp_…', help: 'Optional. Lets you scan private repos and raises GitHub rate limits. Needs read access to repository contents.' },
};

export async function renderSettings(root) {
  let aboutCleanup = null; // unsubscribes the desktop update-status listener
  await refreshSettings();
  paint();

  function paint() {
    const s = state.settings, k = state.keys, o = state.options, u = state.user;
    const sel = (v) => (s.engine === v ? 'sel' : '');
    root.innerHTML = `<div class="page">
      <div class="page-head"><div><div class="page-title">Settings</div><div class="page-sub">Engine, API keys and account. Keys are encrypted on the server and never sent back to the browser.</div></div></div>
      <div class="settings">

        <div class="card">
          <div class="sect-title">Scanning engine</div>
          ${[['auto', 'Automatic', 'Use Claude if a key is available, otherwise Gemini, otherwise rules only.'],
            ['claude', 'Claude (Anthropic)', 'Five Claude agents review your code. Best accuracy.'],
            ['gemini', 'Gemini (Google)', 'Five Gemini agents review your code.'],
            ['rules', 'Rules only (offline)', 'No AI: rule engine, secret scanner and dependency CVE lookup only. Nothing leaves your machine except package names sent to OSV.dev.']]
            .map(([v, n, d]) => `<label class="engine-opt ${sel(v)}"><input type="radio" name="engine" value="${v}" ${s.engine === v ? 'checked' : ''}><div><div class="eo-name">${n}</div><div class="eo-desc">${d}</div></div></label>`).join('')}
          <div class="grid-2" style="margin-top:8px">
            <div class="field"><label class="field-label" for="claudeModel">Claude model</label>
              <select class="select" id="claudeModel" style="width:100%">${o.claudeModels.map((m) => `<option value="${esc(m.id)}" ${m.id === s.claudeModel ? 'selected' : ''}>${esc(m.label)}</option>`).join('')}</select></div>
            <div class="field"><label class="field-label" for="geminiModel">Gemini model</label>
              <select class="select" id="geminiModel" style="width:100%">${o.geminiModels.map((m) => `<option value="${esc(m.id)}" ${m.id === s.geminiModel ? 'selected' : ''}>${esc(m.label)}</option>`).join('')}</select></div>
            <div class="field"><label class="field-label" for="aiDepth">AI depth (how much code the agents read)</label>
              <select class="select" id="aiDepth" style="width:100%">${o.depths.map((d) => `<option value="${esc(d.id)}" ${d.id === s.aiDepth ? 'selected' : ''}>${esc(d.label)}</option>`).join('')}</select></div>
            <div class="field"><label class="field-label" for="alertThreshold">Alert popup</label>
              <select class="select" id="alertThreshold" style="width:100%">
                <option value="critical" ${s.alertThreshold === 'critical' ? 'selected' : ''}>Critical issues</option>
                <option value="high" ${s.alertThreshold === 'high' ? 'selected' : ''}>High and critical</option>
                <option value="off" ${s.alertThreshold === 'off' ? 'selected' : ''}>Off</option></select></div>
          </div>
          <div class="field" style="margin-top:12px"><span class="field-label">AI agents</span>
            <div class="agent-toggles">${o.agents.map((a) => `<label class="chip-toggle ${s.agents.includes(a.id) ? 'on' : ''}"><input type="checkbox" class="sr-only" data-agent="${esc(a.id)}" ${s.agents.includes(a.id) ? 'checked' : ''}>${esc(a.name)}<span class="dim" style="font-weight:400">${esc(a.role)}</span></label>`).join('')}</div>
          </div>
        </div>

        <div class="card">
          <div class="sect-title">API keys</div>
          ${['anthropic', 'gemini', 'github'].map((p) => {
            const st = k[p];
            return `<div class="set-row" style="flex-direction:column;align-items:stretch">
              <div class="set-info"><h4>${KEY_INFO[p].title}</h4><p>${KEY_INFO[p].help}</p></div>
              <div class="key-row">
                <input class="input mono" type="password" id="key-${p}" aria-label="${KEY_INFO[p].title}" placeholder="${st.user ? `Saved (${esc(st.user.hint)}) — paste to replace` : KEY_INFO[p].ph}" autocomplete="off" spellcheck="false">
                <button class="btn btn-primary btn-sm" data-save="${p}">Save</button>
                ${st.user ? `<button class="btn btn-ghost btn-sm" data-test="${p}">Test</button><button class="btn btn-ghost btn-sm" data-remove="${p}" aria-label="Remove ${KEY_INFO[p].title}" title="Remove key">${icon('trash')}</button>` : ''}
              </div>
              <div class="key-status ${st.user || st.server ? 'ok' : ''}">● ${st.user ? `Your key ${esc(st.user.hint)} saved ${fmtTime(st.user.updatedAt)}` : st.server ? 'Using the server-provided key' : 'Not set'}</div>
            </div>`;
          }).join('')}
        </div>

        <div class="card">
          <div class="sect-title">Account</div>
          <div class="set-row">
            <div style="display:flex;gap:12px;align-items:center;min-width:0">
              <div class="avatar" style="width:40px;height:40px;font-size:14px">${safeUrl(u.avatarUrl) ? `<img src="${esc(safeUrl(u.avatarUrl))}" alt="">` : esc(initials(u.name))}</div>
              <div class="set-info"><h4>${esc(u.name)}</h4><p>${esc(u.email)}</p></div>
            </div>
          </div>
          <div class="set-row">
            <div class="set-info" style="flex:1"><h4>Display name</h4>
              <div class="key-row" style="margin-top:6px"><input class="input" id="name" value="${esc(u.name)}" maxlength="80" aria-label="Display name"><button class="btn btn-ghost btn-sm" id="saveName">Save</button></div></div>
          </div>
          <div class="set-row">
            <div class="set-info"><h4>GitHub</h4><p>${u.github ? `Connected as <b>@${esc(u.github.login)}</b>${/\brepo\b/.test(u.github.scope || '') ? ' with private repo access.' : '. Grant repo access to scan private repositories.'}` : 'Connect GitHub to sign in with it and scan private repositories.'}
              ${k.github?.user ? '<br><span style="color:var(--ok)">● Private repo scanning is already enabled through your personal access token (above).</span>' : ''}</p></div>
            <div class="btn-row">${state.providers.github
              ? (u.github ? `${/\brepo\b/.test(u.github.scope || '') ? '' : '<a class="btn btn-ghost btn-sm" href="/api/auth/github/start?scope=repo">Grant repo access</a>'}<button class="btn btn-ghost btn-sm" id="unlinkGh">Disconnect</button>`
                : '<a class="btn btn-github btn-sm" href="/api/auth/github/start">' + icon('github') + 'Connect</a>')
              : state.githubOAuth?.canConfigure
                ? `<button class="btn btn-ghost btn-sm" id="setupGh">${icon('github')}Set up GitHub sign-in</button>`
                : '<span class="dim" style="font-size:12px">Ask the server admin to enable GitHub sign-in</span>'}</div>
          </div>
          ${state.githubOAuth?.configured && state.githubOAuth?.source === 'app' && state.githubOAuth?.canConfigure ? `<div class="set-row">
            <div class="set-info"><h4>GitHub sign-in app</h4><p>Using OAuth app <span class="mono">${esc(state.githubOAuth.clientId)}</span>. Callback URL: <span class="mono">${esc(state.githubOAuth.callbackUrl)}</span></p></div>
            <div class="btn-row"><button class="btn btn-ghost btn-sm" id="setupGh">Change</button><button class="btn btn-ghost btn-sm" id="removeGhApp">Remove</button></div>
          </div>` : ''}
          <div class="set-row" style="flex-direction:column;align-items:stretch">
            <div class="set-info"><h4>${u.hasPassword ? 'Change password' : 'Set a password'}</h4><p>At least 8 characters with letters and numbers.</p></div>
            <div class="grid-2">
              ${u.hasPassword ? '<input class="input" type="password" id="curPw" aria-label="Current password" placeholder="Current password" autocomplete="current-password">' : ''}
              <input class="input" type="password" id="newPw" aria-label="New password" placeholder="New password" autocomplete="new-password">
            </div>
            <div><button class="btn btn-ghost btn-sm" id="savePw">Update password</button></div>
          </div>
          <div class="set-row">
            <div class="set-info"><h4>Theme</h4><p>Match your system or pick one.</p></div>
            <select class="select" id="theme" aria-label="Theme"><option value="system">System</option><option value="dark">Dark</option><option value="light">Light</option></select>
          </div>
          <div class="set-row">
            <div class="set-info"><h4>Delete account</h4><p>Permanently deletes your account, scans, findings and saved keys.</p></div>
            <button class="btn btn-danger btn-sm" id="delAcct">Delete account</button>
          </div>
        </div>

        <div class="card">
          <div class="sect-title">About &amp; updates</div>
          <div class="set-row">
            <div class="set-info"><h4 id="appVersion">IntelliTest AI</h4>
              <p id="updateInfo">${window.intellitestDesktop
                ? 'The desktop app checks for updates automatically when it starts. You can also check now.'
                : 'You are using the web version — it updates automatically whenever a new version is deployed.'}</p></div>
            ${window.intellitestDesktop ? '<button class="btn btn-ghost btn-sm" id="checkUpdates">Check for updates</button>' : ''}
          </div>
          ${window.intellitestDesktop ? '<div class="upd-status hidden" id="updStatus" role="status" aria-live="polite"></div>' : ''}
        </div>
      </div>
    </div>`;
    wire();
    wireAbout();
  }

  /** Guided set-up of the GitHub OAuth app used for "Sign in with GitHub". */
  async function setupGithubSignIn(prev = {}) {
    const g = state.githubOAuth || {};
    const copyRow = (label, value) => `<div class="field"><span class="field-label">${label}</span>
      <div class="key-row"><input class="input mono" readonly value="${esc(value)}" aria-label="${label}"><button class="btn btn-ghost btn-sm" type="button" data-copyval="${esc(value)}">Copy</button></div></div>`;
    const pending = modal({
      title: 'Set up "Sign in with GitHub"',
      wide: true,
      body: `<ol style="margin:0 0 14px 18px;display:flex;flex-direction:column;gap:6px">
          <li>Open <a href="https://github.com/settings/applications/new" target="_blank" rel="noopener noreferrer">github.com → Settings → Developer settings → OAuth Apps → New OAuth App</a>.</li>
          <li>Application name: <b>IntelliTest AI</b>. Copy the two URLs below into <b>Homepage URL</b> and <b>Authorization callback URL</b>, then click <b>Register application</b>.</li>
          <li>Click <b>Generate a new client secret</b>, then paste the <b>Client ID</b> and the <b>Client secret</b> here.</li>
        </ol>
        <div style="display:flex;flex-direction:column;gap:10px">
          ${copyRow('Homepage URL', g.homepageUrl || location.origin)}
          ${copyRow('Authorization callback URL', g.callbackUrl || `${location.origin}/api/auth/github/callback`)}
          <div class="field"><label class="field-label" for="ghClientId">Client ID</label><input class="input mono" id="ghClientId" placeholder="Ov23li…" autocomplete="off" spellcheck="false" value="${esc(prev.clientId || '')}"></div>
          <div class="field"><label class="field-label" for="ghClientSecret">Client secret</label><input class="input mono" id="ghClientSecret" type="password" placeholder="40-character secret" autocomplete="off" spellcheck="false"></div>
          <p class="hint">The secret is checked with GitHub, then stored encrypted on this computer. ${window.intellitestDesktop ? 'Keep the app on port 47821 (the default) so the callback URL stays the same.' : ''}</p>
        </div>`,
      buttons: [{ label: 'Cancel', value: false }, { label: 'Save & verify', value: true, cls: 'btn-primary' }],
    });
    // The dialog is in the DOM synchronously: keep references to its inputs and wire the copy buttons.
    const idIn = document.getElementById('ghClientId');
    const secretIn = document.getElementById('ghClientSecret');
    document.querySelectorAll('[data-copyval]').forEach((b) => { b.onclick = () => navigator.clipboard?.writeText(b.dataset.copyval).then(() => { b.textContent = 'Copied ✓'; }).catch(() => {}); });
    if (!(await pending)) return;
    const clientId = idIn.value.trim(), clientSecret = secretIn.value.trim();
    if (!clientId || !clientSecret) { toast('Paste both the Client ID and the Client secret.', 'err'); return setupGithubSignIn({ clientId }); }
    toast('Checking with GitHub…', '', 2500);
    try {
      await put('/settings/github-oauth', { clientId, clientSecret });
    } catch (e) {
      toast(e.message, 'err', 8000);
      return setupGithubSignIn({ clientId });
    }
    await refreshSession();
    if (root.isConnected) paint();
    toast('GitHub sign-in is ready. Click "Connect" to link your GitHub account.', 'ok', 7000);
  }

  /** Desktop-only bridge (desktop/preload.cjs): version + manual update check. */
  function wireAbout() {
    aboutCleanup?.(); // paint() re-renders: drop the previous listener first
    aboutCleanup = null;
    const d = window.intellitestDesktop;
    if (!d) return;
    d.getVersion().then((v) => { const el = root.querySelector('#appVersion'); if (el) el.textContent = `IntelliTest AI ${v} (desktop)`; }).catch(() => {});
    const btn = root.querySelector('#checkUpdates');
    const box = root.querySelector('#updStatus');
    const mb = (n) => `${(Number(n || 0) / 1048576).toFixed(1)} MB`;

    // Render the live status (sent by desktop/updater.js) right under the button.
    const show = (s) => {
      if (!s || !box.isConnected) return;
      const phase = s.phase || 'idle';
      btn.disabled = ['checking', 'downloading', 'installing'].includes(phase);
      btn.textContent = phase === 'checking' ? 'Checking…' : 'Check for updates';
      if (phase === 'idle') { box.classList.add('hidden'); return; }
      box.classList.remove('hidden');
      box.dataset.phase = phase;
      const pct = Math.max(0, Math.min(100, Math.round(s.percent || 0)));
      const views = {
        checking: `<div class="upd-line"><div class="spinner"></div><span>Checking for updates…</span></div>`,
        'up-to-date': `<div class="upd-line ok">${icon('check')}<span>You're up to date — version <b>${esc(s.current)}</b> is the latest.</span></div>`,
        available: `<div class="upd-line">${icon('download')}<span><b>Version ${esc(s.version)}</b> is available (you have ${esc(s.current)}).</span>
            <button class="btn btn-primary btn-sm" id="updDownload">Download update</button></div>
            ${s.notes ? `<div class="upd-notes">${esc(s.notes)}</div>` : ''}`,
        downloading: `<div class="upd-line"><div class="spinner"></div><span>Downloading version <b>${esc(s.version || '')}</b>… <b>${pct}%</b></span></div>
            <div class="progress upd-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><div style="width:${pct}%"></div></div>
            <div class="upd-sub">${s.total ? `${mb(s.transferred)} of ${mb(s.total)}` : 'Starting download…'}${s.bytesPerSecond ? ` · ${mb(s.bytesPerSecond)}/s` : ''}</div>`,
        downloaded: `<div class="upd-line ok">${icon('check')}<span>Version <b>${esc(s.version)}</b> is downloaded and ready to install.</span>
            <button class="btn btn-primary btn-sm" id="updInstall">Restart &amp; install</button></div>
            <div class="upd-sub">The app closes, installs the update and opens again. Your scans and settings are kept.</div>`,
        installing: `<div class="upd-line"><div class="spinner"></div><span>Installing version <b>${esc(s.version || '')}</b>… the app will restart.</span></div>`,
        error: `<div class="upd-line err">${icon('alert')}<span>${esc(s.message || 'Update failed.')}</span></div>`,
      };
      box.innerHTML = views[phase] || '';
      box.querySelector('#updDownload')?.addEventListener('click', (e) => { e.currentTarget.disabled = true; d.downloadUpdate().then(show).catch((ex) => toast(ex.message, 'err')); });
      box.querySelector('#updInstall')?.addEventListener('click', (e) => { e.currentTarget.disabled = true; d.installUpdate().then(show).catch((ex) => toast(ex.message, 'err')); });
    };

    btn.onclick = async () => {
      show({ phase: 'checking' });
      try { show(await d.checkForUpdates()); } catch (e) { show({ phase: 'error', message: e.message }); }
    };
    // Show where things stand (e.g. a download started from the start-up dialog) and follow live changes.
    d.getUpdateStatus?.().then(show).catch(() => {});
    const off = d.onUpdateStatus?.(show);
    if (off) aboutCleanup = off;
  }

  /** Save a settings patch. Resolves true on success; on failure shows the error and resolves false. */
  async function saveSettings(patch) {
    let r;
    try { r = await put('/settings', { ...state.settings, ...patch }); } catch (e) { toast(e.message, 'err'); return false; }
    state.settings = r.settings;
    try { await refreshSettings(); } catch { /* saved; the next page load picks up the rest */ }
    toast('Settings saved', 'ok', 1800);
    return true;
  }
  const busyBtn = (b, on, label) => { b.disabled = on; if (on) b.innerHTML = '<div class="spinner"></div>'; else b.textContent = label; };

  function wire() {
    const $ = (s) => root.querySelector(s);
    root.querySelectorAll('input[name="engine"]').forEach((r) => r.addEventListener('change', async () => {
      await saveSettings({ engine: r.value });
      if (root.isConnected) paint(); // on failure this re-renders from the unchanged saved state (reverts the radio)
    }));
    for (const id of ['claudeModel', 'geminiModel', 'aiDepth', 'alertThreshold']) {
      $(`#${id}`).onchange = async (e) => {
        const el = e.target;
        if (!(await saveSettings({ [id]: el.value }))) el.value = state.settings[id]; // revert on failure
      };
    }
    root.querySelectorAll('[data-agent]').forEach((cb) => cb.addEventListener('change', async () => {
      const agents = [...root.querySelectorAll('[data-agent]:checked')].map((x) => x.dataset.agent);
      if (!agents.length) { cb.checked = true; return toast('Keep at least one agent enabled.', 'err'); }
      cb.parentElement.classList.toggle('on', cb.checked);
      if (!(await saveSettings({ agents }))) {
        // Revert the checkbox (and its chip) to the last saved state.
        cb.checked = state.settings.agents.includes(cb.dataset.agent);
        cb.parentElement.classList.toggle('on', cb.checked);
      }
    }));

    root.querySelectorAll('[data-save]').forEach((b) => b.onclick = async () => {
      const p = b.dataset.save;
      const key = $(`#key-${p}`).value.trim();
      if (!key) return toast('Paste a key first.', 'err');
      busyBtn(b, true);
      try { await put(`/settings/keys/${encodeURIComponent(p)}`, { key }); }
      catch (e) { toast(e.message, 'err'); busyBtn(b, false, 'Save'); return; }
      toast('Key verified and saved', 'ok');
      try { await refreshSettings(); } catch (e) { toast(e.message, 'err'); }
      if (root.isConnected) paint();
    });
    root.querySelectorAll('[data-test]').forEach((b) => b.onclick = async () => {
      busyBtn(b, true);
      try { await post(`/settings/keys/${encodeURIComponent(b.dataset.test)}/test`); toast('Key works', 'ok'); } catch (e) { toast(e.message, 'err'); }
      busyBtn(b, false, 'Test');
    });
    root.querySelectorAll('[data-remove]').forEach((b) => b.onclick = async () => {
      if (!(await confirmDialog('Remove key?', 'The saved key will be deleted from the server.', 'Remove'))) return;
      b.disabled = true;
      try { await del(`/settings/keys/${encodeURIComponent(b.dataset.remove)}`); await refreshSettings(); if (root.isConnected) paint(); }
      catch (e) { b.disabled = false; toast(e.message, 'err'); }
    });

    $('#saveName').onclick = async (e) => {
      const b = e.currentTarget;
      const name = $('#name').value.trim();
      if (!name) return toast('Enter a name.', 'err');
      busyBtn(b, true);
      try { await put('/auth/profile', { name }); location.reload(); } // reload refreshes the sidebar user chip
      catch (ex) { toast(ex.message, 'err'); busyBtn(b, false, 'Save'); }
    };
    $('#setupGh')?.addEventListener('click', () => setupGithubSignIn());
    $('#removeGhApp')?.addEventListener('click', async (e) => {
      if (!(await confirmDialog('Remove GitHub sign-in?', 'The "Continue with GitHub" button disappears. Accounts and scans are kept; users who only signed in with GitHub will need to set a password.', 'Remove'))) return;
      e.target.disabled = true;
      try { await del('/settings/github-oauth'); await refreshSession(); if (root.isConnected) paint(); toast('GitHub sign-in removed', 'ok'); }
      catch (ex) { e.target.disabled = false; toast(ex.message, 'err'); }
    });
    $('#unlinkGh')?.addEventListener('click', async () => {
      if (!(await confirmDialog('Disconnect GitHub?', 'You will no longer be able to sign in with GitHub or scan private repos via this connection.', 'Disconnect'))) return;
      try { await del('/auth/github'); await refreshSession(); if (root.isConnected) paint(); } catch (e) { toast(e.message, 'err'); }
    });
    $('#savePw').onclick = async (e) => {
      const b = e.currentTarget;
      const cur = $('#curPw'), next = $('#newPw').value;
      if (cur && !cur.value) return toast('Enter your current password.', 'err');
      if (next.length < 8 || !/[A-Za-z]/.test(next) || !/\d/.test(next)) return toast('New password must be at least 8 characters with letters and numbers.', 'err');
      busyBtn(b, true);
      try {
        // The server signs out other sessions and re-issues this browser's cookie.
        await put('/auth/password', { currentPassword: cur?.value, newPassword: next });
      } catch (ex) { toast(ex.message, 'err'); busyBtn(b, false, 'Update password'); return; }
      toast('Password updated. Other devices were signed out.', 'ok');
      try { await refreshSession(); } catch { /* keep the page; the next request re-checks the session */ }
      if (root.isConnected && state.user) paint();
    };
    const theme = $('#theme');
    theme.value = state.settings.theme || 'system';
    theme.onchange = async () => {
      applyTheme(theme.value);
      if (!(await saveSettings({ theme: theme.value }))) { theme.value = state.settings.theme || 'system'; applyTheme(theme.value); }
    };
    $('#delAcct').onclick = async (e) => {
      const b = e.currentTarget;
      if (!(await confirmDialog('Delete your account?', 'All scans, findings and keys will be permanently deleted. This cannot be undone.', 'Delete account'))) return;
      b.disabled = true;
      try { await del('/auth/account'); } catch (ex) { b.disabled = false; toast(ex.message, 'err'); return; }
      toast('Your account was deleted.', 'ok');
      signedOut();
    };
  }

  return () => aboutCleanup?.();
}
