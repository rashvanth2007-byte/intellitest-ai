import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { randomToken, safeEqual } from '../util/crypto.js';
import { HttpError } from '../util/http.js';

export const SESSION_COOKIE = 'it_session';
export const CSRF_COOKIE = 'it_csrf';

const baseCookie = () => ({ sameSite: 'lax', secure: config.cookieSecure, path: '/' });

export function setSession(res, user) {
  const token = jwt.sign({ sub: user.id, sv: Number(user.session_version || 0) }, config.jwtSecret, { algorithm: 'HS256', expiresIn: `${config.sessionDays}d` });
  res.cookie(SESSION_COOKIE, token, { ...baseCookie(), httpOnly: true, maxAge: config.sessionDays * 864e5 });
}

export function clearSession(res) {
  res.clearCookie(SESSION_COOKIE, { ...baseCookie(), httpOnly: true });
}

/** Ensure a CSRF double-submit cookie exists; returns its value. */
export function ensureCsrf(req, res) {
  let t = req.cookies?.[CSRF_COOKIE];
  if (!t || t.length < 20) {
    t = randomToken(24);
    res.cookie(CSRF_COOKIE, t, { ...baseCookie(), httpOnly: false, maxAge: 30 * 864e5 });
  }
  return t;
}

/** Reject state-changing requests that don't echo the CSRF cookie in a header. */
export function csrfGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const cookie = req.cookies?.[CSRF_COOKIE];
  const header = req.get('x-csrf-token');
  if (!cookie || !header || !safeEqual(cookie, header)) {
    return next(new HttpError(403, 'Invalid or missing CSRF token. Refresh the page and try again.', 'csrf'));
  }
  next();
}

/** Attach req.user if a valid session cookie is present. */
export async function loadUser(req, _res, next) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return next();
  try {
    const { sub, sv } = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
    const user = await getDb().get('SELECT id, email, name, avatar_url, password_hash, created_at, session_version FROM users WHERE id = ?', [sub]);
    // A password change bumps session_version, which invalidates every older session cookie.
    if (user && Number(user.session_version || 0) === Number(sv || 0)) req.user = user;
  } catch { /* expired / tampered -> anonymous */ }
  next();
}

export function requireAuth(req, _res, next) {
  if (!req.user) return next(new HttpError(401, 'Please sign in.', 'auth'));
  next();
}

export function publicUser(u, extra = {}) {
  return { id: u.id, email: u.email, name: u.name, avatarUrl: u.avatar_url || null, hasPassword: !!u.password_hash, createdAt: Number(u.created_at), ...extra };
}
