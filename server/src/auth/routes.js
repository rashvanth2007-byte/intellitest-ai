import { Router } from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { config } from '../config.js';
import { getDb, isUniqueViolation } from '../db/index.js';
import { cancel } from '../scan/jobs.js';
import { encrypt, newId, randomToken, safeEqual } from '../util/crypto.js';
import { ah, HttpError, str } from '../util/http.js';
import { setSession, clearSession, ensureCsrf, requireAuth, publicUser } from './session.js';

export const authRouter = Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
});

function validatePassword(pw) {
  const p = str(pw, { min: 8, max: 200, name: 'Password', trim: false });
  if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) throw new HttpError(400, 'Password must contain letters and numbers.');
  return p;
}

async function githubLink(userId) {
  return getDb().get("SELECT login, scope FROM oauth_accounts WHERE user_id = ? AND provider = 'github'", [userId]);
}

authRouter.get('/me', ah(async (req, res) => {
  const csrf = ensureCsrf(req, res);
  const providers = { github: !!(config.github.clientId && config.github.clientSecret), registration: config.allowRegistration };
  if (!req.user) return res.json({ user: null, csrf, providers });
  const gh = await githubLink(req.user.id);
  res.json({ user: publicUser(req.user, { github: gh ? { login: gh.login, scope: gh.scope } : null }), csrf, providers });
}));

authRouter.post('/register', authLimiter, ah(async (req, res) => {
  if (!config.allowRegistration) throw new HttpError(403, 'Registration is disabled on this server.');
  const email = str(req.body?.email, { max: 254, name: 'Email' }).toLowerCase();
  if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Enter a valid email address.');
  const name = str(req.body?.name || email.split('@')[0], { min: 1, max: 80, name: 'Name' });
  const password = validatePassword(req.body?.password);
  const db = getDb();
  if (await db.get('SELECT id FROM users WHERE email = ?', [email])) throw new HttpError(409, 'An account with this email already exists.');
  const user = { id: newId(), email, name, password_hash: await bcrypt.hash(password, 12), created_at: Date.now() };
  try {
    await db.run('INSERT INTO users (id, email, name, password_hash, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)',
      [user.id, user.email, user.name, user.password_hash, user.created_at, user.created_at]);
  } catch (e) {
    // Two registrations for the same email racing past the SELECT above.
    if (isUniqueViolation(e)) throw new HttpError(409, 'An account with this email already exists.');
    throw e;
  }
  setSession(res, user);
  res.status(201).json({ user: publicUser(user, { github: null }) });
}));

// Pre-computed hash so unknown emails take as long as wrong passwords (no user enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password-x', 12);

authRouter.post('/login', authLimiter, ah(async (req, res) => {
  const email = str(req.body?.email, { max: 254, name: 'Email' }).toLowerCase();
  const password = str(req.body?.password, { max: 200, name: 'Password', trim: false });
  const db = getDb();
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
  const ok = await bcrypt.compare(password, user?.password_hash || DUMMY_HASH);
  if (!user || !user.password_hash || !ok) {
    throw new HttpError(401, user && !user.password_hash ? 'This account uses GitHub sign-in.' : 'Incorrect email or password.');
  }
  await db.run('UPDATE users SET last_login_at = ? WHERE id = ?', [Date.now(), user.id]);
  setSession(res, user);
  const gh = await githubLink(user.id);
  res.json({ user: publicUser(user, { github: gh ? { login: gh.login, scope: gh.scope } : null }) });
}));

authRouter.post('/logout', (req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

authRouter.put('/profile', requireAuth, ah(async (req, res) => {
  const name = str(req.body?.name, { min: 1, max: 80, name: 'Name' });
  await getDb().run('UPDATE users SET name = ? WHERE id = ?', [name, req.user.id]);
  res.json({ ok: true });
}));

authRouter.put('/password', requireAuth, authLimiter, ah(async (req, res) => {
  const next = validatePassword(req.body?.newPassword);
  if (req.user.password_hash) {
    const cur = str(req.body?.currentPassword, { max: 200, name: 'Current password', trim: false });
    if (!(await bcrypt.compare(cur, req.user.password_hash))) throw new HttpError(400, 'Current password is incorrect.');
  }
  const db = getDb();
  await db.run('UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?', [await bcrypt.hash(next, 12), req.user.id]);
  // Other devices are signed out; keep this one signed in with a fresh cookie.
  setSession(res, await db.get('SELECT id, session_version FROM users WHERE id = ?', [req.user.id]));
  res.json({ ok: true });
}));

authRouter.delete('/account', requireAuth, ah(async (req, res) => {
  const db = getDb();
  // Stop this user's scans first, otherwise they would try to write findings for a deleted user.
  const active = await db.all("SELECT id FROM scans WHERE user_id = ? AND status IN ('queued','running')", [req.user.id]);
  active.forEach((s) => cancel(s.id));
  await db.tx(async (t) => {
    await t.run('DELETE FROM findings WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM scans WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM api_keys WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM user_settings WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM oauth_accounts WHERE user_id = ?', [req.user.id]);
    await t.run('DELETE FROM users WHERE id = ?', [req.user.id]);
  });
  clearSession(res);
  res.json({ ok: true });
}));

/* ───────────── GitHub OAuth (authorization code flow) ───────────── */
const STATE_COOKIE = 'it_oauth_state';

authRouter.get('/github/start', (req, res) => {
  if (!config.github.clientId) return res.redirect(`${config.appUrl}/#/login?error=github_not_configured`);
  const state = randomToken(24);
  const wantRepo = req.query.scope === 'repo';
  res.cookie(STATE_COOKIE, JSON.stringify({ state, link: !!req.user }), {
    httpOnly: true, sameSite: 'lax', secure: config.cookieSecure, maxAge: 10 * 60 * 1000, path: '/api/auth/github',
  });
  const params = new URLSearchParams({
    client_id: config.github.clientId,
    redirect_uri: `${config.appUrl}/api/auth/github/callback`,
    scope: wantRepo ? 'read:user user:email repo' : 'read:user user:email',
    state,
    allow_signup: 'true',
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

authRouter.get('/github/callback', ah(async (req, res) => {
  const fail = (code) => res.redirect(`${config.appUrl}/#/login?error=${code}`);
  let saved = {};
  try { saved = JSON.parse(req.cookies?.[STATE_COOKIE] || '{}') || {}; } catch { /* ignore */ }
  res.clearCookie(STATE_COOKIE, { path: '/api/auth/github' });
  if (req.query.error) return fail('github_denied');
  if (!saved.state || !safeEqual(saved.state, req.query.state)) return fail('github_state');
  try {
    await githubCallback(req, res, saved, fail);
  } catch (e) {
    // Network failures talking to GitHub, or a duplicate callback racing this one: the browser
    // navigated here, so always answer with a redirect, never a JSON error page.
    console.error('[auth] GitHub callback failed:', e.message);
    if (!res.headersSent) fail(isUniqueViolation(e) ? 'github_already_linked' : 'github_failed');
  }
}));

async function githubCallback(req, res, saved, fail) {
  const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    signal: AbortSignal.timeout(15000),
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: config.github.clientId,
      client_secret: config.github.clientSecret,
      code: String(req.query.code || ''),
      redirect_uri: `${config.appUrl}/api/auth/github/callback`,
    }),
  });
  const tok = await tokenResp.json().catch(() => ({}));
  if (!tok.access_token) return fail('github_token');

  const gh = (p) => fetch(`https://api.github.com${p}`, {
    signal: AbortSignal.timeout(15000),
    headers: { Authorization: `Bearer ${tok.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'IntelliTest-AI' },
  }).then((r) => (r.ok ? r.json() : null));
  const profile = await gh('/user');
  if (!profile?.id) return fail('github_profile');
  let email = profile.email;
  if (!email) {
    const emails = (await gh('/user/emails')) || [];
    email = (emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified))?.email;
  }

  const db = getDb();
  const ghId = String(profile.id);
  const now = Date.now();
  const tokenEnc = encrypt(tok.access_token);
  const link = await db.get("SELECT * FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = ?", [ghId]);
  let user;

  if (link) {
    // Never switch the browser into a different account while the user is trying to link theirs.
    if (saved.link && req.user && link.user_id !== req.user.id) return fail('github_already_linked');
    user = await db.get('SELECT * FROM users WHERE id = ?', [link.user_id]);
    await db.run('UPDATE oauth_accounts SET access_token_enc = ?, scope = ?, login = ? WHERE id = ?', [tokenEnc, tok.scope || '', profile.login, link.id]);
  } else {
    if (saved.link && req.user) {
      user = req.user; // linking GitHub to the signed-in account
    } else if (email) {
      user = await db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
      // Never auto-merge into a password account by email: someone could add that email to their GitHub.
      if (user && user.password_hash) return fail('github_email_exists');
      // A GitHub-only account already bound to another GitHub identity must not be taken over.
      if (user && await db.get("SELECT id FROM oauth_accounts WHERE user_id = ? AND provider = 'github'", [user.id])) return fail('github_email_exists');
    }
    if (!user) {
      if (!config.allowRegistration) return fail('registration_disabled');
      user = {
        id: newId(),
        email: (email || `${profile.login}@users.noreply.github.com`).toLowerCase(),
        name: profile.name || profile.login,
        avatar_url: profile.avatar_url,
        password_hash: null,
        created_at: now,
      };
      await db.run('INSERT INTO users (id, email, name, avatar_url, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?)',
        [user.id, user.email, user.name, user.avatar_url, now, now]);
    }
    await db.run('INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, login, access_token_enc, scope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [newId(), user.id, 'github', ghId, profile.login, tokenEnc, tok.scope || '', now]);
  }
  if (!user) return fail('github_user');
  await db.run('UPDATE users SET last_login_at = ?, avatar_url = COALESCE(avatar_url, ?) WHERE id = ?', [now, profile.avatar_url || null, user.id]);
  setSession(res, user);
  res.redirect(`${config.appUrl}/#/${saved.link ? 'settings' : 'scanner'}`);
}

authRouter.delete('/github', requireAuth, ah(async (req, res) => {
  if (!req.user.password_hash) throw new HttpError(400, 'Set a password first, otherwise you could not sign in again.');
  await getDb().run("DELETE FROM oauth_accounts WHERE user_id = ? AND provider = 'github'", [req.user.id]);
  res.json({ ok: true });
}));
