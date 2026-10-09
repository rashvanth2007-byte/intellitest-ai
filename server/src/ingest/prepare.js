import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';
import { extractZip } from './zip.js';
import { parseGithubUrl, downloadRepoZip } from './github.js';
import { isIgnoredPath } from './walker.js';
import { HttpError } from '../util/http.js';
import { safeRelPath } from './paths.js';

export { safeRelPath };

/**
 * Materialise a scan source into workDir/src. Returns { srcDir, meta }.
 * source: { kind: 'files'|'zip'|'paste'|'github', ... }
 */
export async function prepareSource(source, workDir, { githubToken, githubTokenShared, signal, onStatus } = {}) {
  // One extraction budget for the whole scan, however many archives it contains.
  const budget = { left: config.limits.unzippedBytes };
  const unzip = async (zip, dest) => {
    if (budget.left <= 0) throw new HttpError(413, `Archives expand to more than ${Math.round(config.limits.unzippedBytes / 1048576)} MB in total.`);
    const r = await extractZip(zip, dest, { maxBytes: budget.left, signal });
    budget.left -= r.bytes;
    return r;
  };
  const srcDir = path.join(workDir, 'src');
  fs.mkdirSync(srcDir, { recursive: true });
  const meta = {};

  if (source.kind === 'paste') {
    const name = safeRelPath(source.filename) || 'snippet.txt';
    fs.writeFileSync(path.join(srcDir, name.split('/').pop()), source.code, 'utf8');
  } else if (source.kind === 'files') {
    for (const f of source.uploads) {
      signal?.throwIfAborted();
      const rel = safeRelPath(f.relPath);
      if (!rel || isIgnoredPath(rel)) continue;
      const lower = rel.toLowerCase();
      if (lower.endsWith('.zip')) {
        // A zip dropped alongside files: extract into a folder named after it.
        onStatus?.(`Extracting ${rel}…`);
        await unzip(f.tmpPath, path.join(srcDir, rel.replace(/\.zip$/i, '')));
        continue;
      }
      const target = path.join(srcDir, rel);
      if (!path.resolve(target).startsWith(path.resolve(srcDir) + path.sep)) continue;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(f.tmpPath, target);
    }
  } else if (source.kind === 'zip') {
    onStatus?.('Extracting archive…');
    const r = await unzip(source.zipPath, srcDir);
    meta.archive = r;
  } else if (source.kind === 'github') {
    const parsed = parseGithubUrl(source.url);
    if (!parsed) throw new HttpError(400, 'Not a valid GitHub repository URL.');
    onStatus?.(`Downloading ${parsed.owner}/${parsed.repo} from GitHub…`);
    const zipFile = path.join(workDir, 'repo.zip');
    const info = await downloadRepoZip(parsed, zipFile, { token: githubToken, publicOnly: githubTokenShared, maxBytes: config.limits.uploadBytes * 2, signal });
    onStatus?.('Extracting repository…');
    await unzip(zipFile, srcDir);
    fs.rmSync(zipFile, { force: true });
    meta.github = { ...info, subdir: parsed.subdir };
    if (parsed.subdir) {
      const sub = path.resolve(srcDir, safeRelPath(parsed.subdir) || '');
      if (!sub.startsWith(path.resolve(srcDir)) || !fs.existsSync(sub)) throw new HttpError(404, `Path "${parsed.subdir}" not found in repository.`);
      return { srcDir: sub, meta };
    }
  } else {
    throw new HttpError(400, 'Unknown source kind');
  }
  return { srcDir, meta };
}
