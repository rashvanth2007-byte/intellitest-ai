import fs from 'node:fs';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { HttpError } from '../util/http.js';

/**
 * Accepts: https://github.com/owner/repo, .../repo.git, .../tree/<branch>/<sub/path>,
 * git@github.com:owner/repo.git, or "owner/repo".
 */
const okName = (n) => /^[\w.-]+$/.test(n) && !/^\.+$/.test(n); // no "." / ".." (would escape the API path)

export function parseGithubUrl(input) {
  const s = String(input || '').trim();
  let m = s.match(/^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/i);
  if (m) return okName(m[1]) && okName(m[2]) ? { owner: m[1], repo: m[2], ref: null, subdir: null } : null;
  m = s.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (m && !s.includes('.') ) return { owner: m[1], repo: m[2], ref: null, subdir: null };
  let u;
  try { u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`); } catch { return null; }
  if (!/^(www\.)?github\.com$/i.test(u.hostname)) return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');
  if (!okName(owner) || !okName(repo)) return null;
  let ref = null, subdir = null;
  if ((parts[2] === 'tree' || parts[2] === 'blob') && parts[3]) {
    try {
      ref = decodeURIComponent(parts[3]);
      subdir = parts.slice(4).map(decodeURIComponent).join('/') || null;
    } catch { return null; } // malformed %-escape
  }
  return { owner, repo, ref, subdir };
}

function ghHeaders(token) {
  const h = { Accept: 'application/vnd.github+json', 'User-Agent': 'IntelliTest-AI', 'X-GitHub-Api-Version': '2022-11-28' };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/** Download the repository zipball to destFile. Returns repo metadata. */
/** fetch() that turns network failures (DNS, offline, reset) into a readable error; aborts pass through. */
async function ghFetch(url, opts) {
  try { return await fetch(url, opts); } catch (e) {
    if (e.name === 'AbortError' || opts.signal?.aborted) throw e;
    throw new HttpError(502, `Could not reach GitHub (${e.cause?.code || e.message}). Check the server's internet connection.`);
  }
}

export async function downloadRepoZip({ owner, repo, ref }, destFile, { token, publicOnly = false, maxBytes, signal }) {
  const metaResp = await ghFetch(`https://api.github.com/repos/${owner}/${repo}`, { headers: ghHeaders(token), signal });
  if (metaResp.status === 404) {
    throw new HttpError(404, token
      ? `Repository ${owner}/${repo} not found, or your GitHub token has no access to it.`
      : `Repository ${owner}/${repo} not found. If it is private, connect GitHub (with repo access) or add a GitHub token in Settings.`);
  }
  if (metaResp.status === 403 || metaResp.status === 429) {
    throw new HttpError(429, 'GitHub API rate limit reached. Sign in with GitHub or add a GitHub token in Settings to raise the limit.');
  }
  if (!metaResp.ok) throw new HttpError(502, `GitHub API error ${metaResp.status}`);
  const meta = await metaResp.json();
  // The operator's server-wide token must never expose their private repos to other users.
  if (meta.private && publicOnly) {
    throw new HttpError(404, `Repository ${owner}/${repo} not found. If it is private, connect GitHub (with repo access) or add your own GitHub token in Settings.`);
  }
  if (meta.size && meta.size * 1024 > maxBytes * 3) {
    throw new HttpError(413, `Repository is too large (${Math.round(meta.size / 1024)} MB). Scan a sub-folder via /tree/<branch>/<path> or upload a zip.`);
  }
  const useRef = ref || meta.default_branch;
  const zipResp = await ghFetch(`https://api.github.com/repos/${owner}/${repo}/zipball/${encodeURIComponent(useRef)}`, {
    headers: ghHeaders(token), redirect: 'follow', signal,
  });
  if (!zipResp.ok || !zipResp.body) throw new HttpError(502, `Could not download ${owner}/${repo}@${useRef} (HTTP ${zipResp.status}).`);
  let got = 0;
  const body = Readable.fromWeb(zipResp.body);
  body.on('data', (c) => { got += c.length; if (got > maxBytes) body.destroy(new Error(`Repository archive is larger than ${Math.round(maxBytes / 1048576)} MB.`)); });
  await pipeline(body, fs.createWriteStream(destFile));
  return { fullName: meta.full_name, ref: useRef, private: !!meta.private, description: meta.description || '', stars: meta.stargazers_count };
}
