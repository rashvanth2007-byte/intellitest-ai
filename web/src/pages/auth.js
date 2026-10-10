import { post } from '../lib/api.js';
import { esc, icon } from '../lib/ui.js';
import { state, onSignedIn } from '../main.js';

const OAUTH_ERRORS = {
  github_not_configured: 'GitHub sign-in is not configured on this server.',
  github_denied: 'GitHub sign-in was cancelled.',
  github_state: 'GitHub sign-in expired or was tampered with. Please try again.',
  github_token: 'GitHub did not return an access token. Please try again.',
  github_profile: 'Could not read your GitHub profile.',
  github_email_exists: 'An account with your GitHub email already exists. Sign in with your password, then connect GitHub in Settings.',
  github_already_linked: 'That GitHub account is already connected to a different IntelliTest account.',
  registration_disabled: 'New registrations are disabled on this server.',
};

export function renderAuth(root, { mode, params }) {
  const isRegister = mode === 'register';
  const oauthErr = OAUTH_ERRORS[params.get('error')] || (params.get('error') ? 'Sign-in failed.' : '');
  root.innerHTML = `
  <div class="auth">
    <aside class="auth-hero">
      <div class="brand"><div class="brand-mark">${icon('shield')}</div><div class="brand-name">Intelli<span>Test</span> AI</div></div>
      <div>
        <h1>Find vulnerabilities <span>before attackers do.</span></h1>
        <p>Upload files, a .zip of your project or a GitHub repository. A rule engine, secret scanner, CVE database lookup and five specialised AI agents review the code and tell you exactly what to fix.</p>
      </div>
      <div class="hero-agents">
        ${[['SENTINEL', 'Injection, XSS, SSRF, auth'], ['PHANTOM', 'Runtime & logic bugs'], ['CIPHER', 'Secrets & crypto'], ['NEXUS', 'Dependencies & CVEs'], ['ORACLE', 'API & data exposure']]
          .map(([n, d]) => `<div class="hero-agent"><b>${n}</b><div>${d}</div></div>`).join('')}
      </div>
    </aside>
    <main class="auth-main">
      <form class="auth-card" id="authForm" novalidate>
        <div>
          <h2>${isRegister ? 'Create your account' : 'Welcome back'}</h2>
          <p class="muted" style="font-size:13px;margin-top:4px">${isRegister ? 'Your scans stay private to your account.' : 'Sign in to scan your code.'}</p>
        </div>
        ${oauthErr ? `<div class="form-error">${esc(oauthErr)}</div>` : ''}
        <div class="form-error hidden" id="err" role="alert"></div>
        ${state.providers.github ? `
          <a class="btn btn-github btn-block" href="/api/auth/github/start">${icon('github')}Continue with GitHub</a>
          <div class="divider">or with email</div>` : ''}
        ${isRegister ? `<div class="field"><label class="field-label" for="name">Name</label><input class="input" id="name" autocomplete="name" maxlength="80" placeholder="Ada Lovelace"></div>` : ''}
        <div class="field"><label class="field-label" for="email">Email</label><input class="input" id="email" type="email" autocomplete="email" required placeholder="you@example.com"></div>
        <div class="field">
          <label class="field-label" for="password">Password</label>
          <input class="input" id="password" type="password" autocomplete="${isRegister ? 'new-password' : 'current-password'}" required minlength="8" placeholder="${isRegister ? 'At least 8 characters, letters and numbers' : '••••••••'}">
        </div>
        <button class="btn btn-primary btn-block" id="submitBtn" type="submit">${isRegister ? 'Create account' : 'Sign in'}</button>
        ${state.providers.registration || !isRegister ? `<div class="auth-switch">${isRegister ? 'Already have an account?' : 'New to IntelliTest?'} <button type="button" id="switchBtn">${isRegister ? 'Sign in' : 'Create an account'}</button></div>` : ''}
      </form>
    </main>
  </div>`;

  const form = root.querySelector('#authForm');
  const err = root.querySelector('#err');
  root.querySelector('#switchBtn')?.addEventListener('click', () => { location.hash = isRegister ? '#/login' : '#/register'; });
  root.querySelector('#email').focus();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.classList.add('hidden');
    const email = form.querySelector('#email').value.trim();
    const password = form.querySelector('#password').value;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return showErr('Enter a valid email address.');
    if (isRegister && (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password))) return showErr('Password must be at least 8 characters and contain letters and numbers.');
    const btn = form.querySelector('#submitBtn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div>';
    try {
      await post(isRegister ? '/auth/register' : '/auth/login', { email, password, name: form.querySelector('#name')?.value.trim() || undefined });
      await onSignedIn();
    } catch (ex) {
      showErr(ex.message);
      btn.disabled = false;
      btn.textContent = isRegister ? 'Create account' : 'Sign in';
    }
  });
  function showErr(m) { err.textContent = m; err.classList.remove('hidden'); }
}
