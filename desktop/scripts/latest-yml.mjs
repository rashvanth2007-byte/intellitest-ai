// Write dist/latest.yml (the electron-updater update manifest) for the built installer,
// so a release can be uploaded by hand on github.com without a token.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const desktop = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(fs.readFileSync(path.join(desktop, 'package.json'), 'utf8'));
const name = `IntelliTest-AI-Setup-${version}.exe`;
const exe = path.join(desktop, 'dist', name);
if (!fs.existsSync(exe)) { console.error(`Missing ${exe} — run "npm run build:win" first.`); process.exit(1); }

const buf = fs.readFileSync(exe);
const sha512 = crypto.createHash('sha512').update(buf).digest('base64');
const yml = [
  `version: ${version}`,
  'files:',
  `  - url: ${name}`,
  `    sha512: ${sha512}`,
  `    size: ${buf.length}`,
  `path: ${name}`,
  `sha512: ${sha512}`,
  `releaseDate: '${new Date().toISOString()}'`,
  '',
].join('\n');
fs.writeFileSync(path.join(desktop, 'dist', 'latest.yml'), yml);
console.log(`Wrote dist/latest.yml for ${name} (${(buf.length / 1048576).toFixed(1)} MB)`);
