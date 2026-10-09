export class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Wrap an async route so rejected promises reach the error handler. */
export const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export function str(v, { max = 500, min = 0, name = 'value', trim = true } = {}) {
  if (typeof v !== 'string') throw new HttpError(400, `${name} is required`);
  const s = trim ? v.trim() : v;
  if (s.length < min) throw new HttpError(400, `${name} must be at least ${min} characters`);
  if (s.length > max) throw new HttpError(400, `${name} must be at most ${max} characters`);
  return s;
}

export function parseJson(s, fallback) {
  if (s == null || s === '') return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}
