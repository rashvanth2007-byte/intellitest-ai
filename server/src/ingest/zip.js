import fs from 'node:fs';
import path from 'node:path';
import yauzl from 'yauzl';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { isIgnoredPath } from './walker.js';
import { safeRelPath } from './paths.js';

/**
 * Safely extract a zip archive.
 *  - Zip-slip: every entry must resolve inside destDir.
 *  - Zip-bomb: caps on entry count, total uncompressed bytes (counted while streaming,
 *    not trusted from headers) and per-entry compression ratio.
 *  - Symlinks and absolute paths are skipped; ignored dirs (node_modules, .git…) are skipped.
 *  - stripTopLevel: drop a single shared root folder (GitHub zipballs, "project/..." zips).
 */
export async function extractZip(zipPath, destDir, { maxBytes, maxEntries = 50000, stripTopLevel = true, signal } = {}) {
  fs.mkdirSync(destDir, { recursive: true });
  const root = path.resolve(destDir);
  const zip = await new Promise((res, rej) => yauzl.open(zipPath, { lazyEntries: true, autoClose: true, strictFileNames: false, validateEntrySizes: true }, (e, z) => (e ? rej(e) : res(z))));

  const entries = await new Promise((resolve, reject) => {
    const list = [];
    zip.on('entry', (e) => {
      list.push(e);
      if (list.length > maxEntries) { zip.close(); return reject(new Error(`Archive has more than ${maxEntries} entries.`)); }
      zip.readEntry();
    });
    zip.on('end', () => resolve(list));
    zip.on('error', reject);
    zip.readEntry();
  });

  const names = entries.map((e) => e.fileName.replace(/\\/g, '/'));
  let prefix = '';
  if (stripTopLevel) {
    const firsts = new Set(names.filter(Boolean).map((n) => n.split('/')[0]));
    if (firsts.size === 1 && names.every((n) => n.includes('/') || n.endsWith('/'))) prefix = [...firsts][0] + '/';
  }

  // Re-open to stream contents (lazyEntries list consumed above).
  const zip2 = await new Promise((res, rej) => yauzl.open(zipPath, { lazyEntries: true, autoClose: true, strictFileNames: false, validateEntrySizes: true }, (e, z) => (e ? rej(e) : res(z))));
  let total = 0;
  let written = 0;
  let skipped = 0;

  await new Promise((resolve, reject) => {
    const fail = (err) => { try { zip2.close(); } catch { /* */ } reject(err); };
    zip2.on('error', fail);
    zip2.on('end', resolve);
    zip2.on('entry', async (entry) => {
      try {
        signal?.throwIfAborted();
        let name = entry.fileName.replace(/\\/g, '/');
        if (prefix && name.startsWith(prefix)) name = name.slice(prefix.length);
        const isDir = name.endsWith('/');
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        const isLink = mode === 0o120000;
        if (!name || isDir || isLink || name.includes('\0') || path.isAbsolute(name) || /^[a-zA-Z]:/.test(name) || isIgnoredPath(name)) {
          skipped++; return zip2.readEntry();
        }
        // Windows-safe name: no ':' (alternate data streams), reserved devices (CON, NUL…) or trailing dots.
        const safe = safeRelPath(name);
        if (!safe) { skipped++; return zip2.readEntry(); }
        const target = path.resolve(root, safe);
        if (target !== root && !target.startsWith(root + path.sep)) throw new Error(`Blocked unsafe path in archive: ${name}`);
        if (entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 1000 && entry.uncompressedSize > 10 * 1024 * 1024) {
          throw new Error('Archive rejected: suspicious compression ratio (zip bomb).');
        }
        try {
          fs.mkdirSync(path.dirname(target), { recursive: true });
          if (fs.statSync(target, { throwIfNoEntry: false })?.isDirectory()) throw Object.assign(new Error('is a directory'), { code: 'EISDIR' });
        } catch (e) {
          // "a" as a file and "a/b" in the same archive (or case-only clashes on Windows): skip, don't fail the scan.
          if (['EEXIST', 'ENOTDIR', 'EISDIR'].includes(e.code)) { skipped++; return zip2.readEntry(); }
          throw e;
        }
        const rs = await new Promise((res, rej) => zip2.openReadStream(entry, (e, s) => (e ? rej(e) : res(s))));
        const counter = new Transform({
          transform(chunk, _enc, cb) {
            total += chunk.length;
            if (total > maxBytes) return cb(new Error(`Archive expands to more than ${Math.round(maxBytes / 1048576)} MB.`));
            cb(null, chunk);
          },
        });
        await pipeline(rs, counter, fs.createWriteStream(target, { flags: 'w' }));
        written++;
        zip2.readEntry();
      } catch (e) { fail(e); }
    });
    zip2.readEntry();
  });

  return { files: written, skipped, bytes: total };
}
