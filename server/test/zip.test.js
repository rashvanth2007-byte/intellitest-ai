import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { extractZip } from '../src/ingest/zip.js';

/** Minimal zip writer (stored + deflate) so tests can craft malicious archives. */
function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function makeZip(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const raw = Buffer.from(data);
    const comp = zlib.deflateRawSync(raw);
    const nameBuf = Buffer.from(name);
    const crc = crc32(raw);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(0, 10); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26); lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(0, 12); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);
    offset += 30 + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'it-zip-'));

test('extracts a normal zip and strips a single top-level folder', async () => {
  const dir = tmp();
  const z = path.join(dir, 'a.zip');
  fs.writeFileSync(z, makeZip([{ name: 'proj/src/a.js', data: 'console.log(1)' }, { name: 'proj/node_modules/x/i.js', data: 'x' }]));
  const out = path.join(dir, 'out');
  const r = await extractZip(z, out, { maxBytes: 1e6 });
  assert.equal(r.files, 1);
  assert.ok(fs.existsSync(path.join(out, 'src', 'a.js')));
  assert.ok(!fs.existsSync(path.join(out, 'node_modules')));
});

test('zip-slip entries are not written outside the destination', async () => {
  const dir = tmp();
  const z = path.join(dir, 'evil.zip');
  fs.writeFileSync(z, makeZip([{ name: 'ok.js', data: 'ok' }, { name: '../../evil.js', data: 'pwned' }]));
  const out = path.join(dir, 'out');
  await extractZip(z, out, { maxBytes: 1e6, stripTopLevel: false }).catch(() => {});
  assert.ok(!fs.existsSync(path.join(dir, 'evil.js')));
  assert.ok(!fs.existsSync(path.resolve(out, '../../evil.js')));
});

test('zip bombs exceeding the size cap are rejected', async () => {
  const dir = tmp();
  const z = path.join(dir, 'bomb.zip');
  fs.writeFileSync(z, makeZip([{ name: 'big.txt', data: Buffer.alloc(3 * 1024 * 1024, 'a') }]));
  await assert.rejects(extractZip(z, path.join(dir, 'out'), { maxBytes: 1024 * 1024 }), /more than/);
});

test('Windows-unsafe entry names are sanitised and file/dir clashes are skipped', async () => {
  const dir = tmp();
  const z = path.join(dir, 'win.zip');
  fs.writeFileSync(z, makeZip([
    { name: 'CON', data: 'device' },
    { name: 'app.js:hidden', data: 'ads' },
    { name: 'lib./x.js', data: 'x' },
    { name: 'clash', data: 'file first' },
    { name: 'clash/inner.js', data: 'then a dir' },
  ]));
  const out = path.join(dir, 'out');
  const r = await extractZip(z, out, { maxBytes: 1e6, stripTopLevel: false });
  assert.equal(fs.readFileSync(path.join(out, '_CON'), 'utf8'), 'device');
  assert.equal(fs.readFileSync(path.join(out, 'app.js_hidden'), 'utf8'), 'ads');
  assert.ok(fs.existsSync(path.join(out, 'lib', 'x.js')));
  assert.equal(r.files, 4);
  assert.equal(r.skipped, 1);
});

test('extraction stops when the scan is cancelled', async () => {
  const dir = tmp();
  const z = path.join(dir, 'a.zip');
  fs.writeFileSync(z, makeZip([{ name: 'a.js', data: 'a' }]));
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(extractZip(z, path.join(dir, 'out'), { maxBytes: 1e6, signal: ac.signal }), { name: 'AbortError' });
});
