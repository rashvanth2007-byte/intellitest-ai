// Bundle the server into a single ESM file and copy the built web UI next to it,
// so the Electron package needs no node_modules at runtime.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const here = path.dirname(fileURLToPath(import.meta.url));
const desktop = path.resolve(here, '..');
const root = path.resolve(desktop, '..');
const out = path.join(desktop, 'app');
const webDist = path.join(root, 'web', 'dist');

if (!fs.existsSync(path.join(webDist, 'index.html'))) {
  console.error('web/dist is missing — run "npm run build" in the repo root first.');
  process.exit(1);
}

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

await build({
  entryPoints: [path.join(root, 'server', 'src', 'app.js')],
  outfile: path.join(out, 'server.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  external: ['pg', 'pg-native', 'electron'], // desktop uses SQLite; pg is only loaded for DATABASE_URL
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  legalComments: 'none',
  logLevel: 'warning',
});

// Auto-updater (electron-updater) bundled too, with electron itself left external.
await build({
  entryPoints: [path.join(desktop, 'updater.js')],
  outfile: path.join(out, 'updater.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  external: ['electron'],
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
  legalComments: 'none',
  logLevel: 'warning',
});

fs.cpSync(webDist, path.join(out, 'web'), { recursive: true });
console.log('Bundled server + web UI into desktop/app');
