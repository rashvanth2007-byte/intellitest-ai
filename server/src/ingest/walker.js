import fs from 'node:fs';
import path from 'node:path';

export const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', '.next', '.nuxt', '.output', 'coverage',
  'vendor', 'bower_components', '__pycache__', '.venv', 'venv', '.tox', '.mypy_cache', '.pytest_cache',
  'target', 'obj', '.gradle', '.idea', '.vscode', '.terraform', 'Pods', '.dart_tool', '.cache',
]);

const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svgz', '.tif', '.tiff', '.psd', '.avif', '.heic',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.wav', '.flac', '.ogg', '.webm',
  '.zip', '.gz', '.tgz', '.rar', '.7z', '.tar', '.bz2', '.xz', '.jar', '.war', '.ear', '.apk', '.aab', '.ipa',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.lib', '.class', '.pyc', '.pyo', '.wasm', '.node',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',
  '.ttf', '.otf', '.woff', '.woff2', '.eot', '.db', '.sqlite', '.sqlite3', '.mdb', '.DS_Store',
]);

const LANG_BY_EXT = {
  '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'js', '.ts': 'js', '.tsx': 'js', '.mts': 'js', '.cts': 'js', '.vue': 'js', '.svelte': 'js',
  '.py': 'py', '.pyw': 'py',
  '.php': 'php', '.phtml': 'php',
  '.java': 'java', '.kt': 'java', '.kts': 'java', '.scala': 'java', '.groovy': 'java', '.gradle': 'java',
  '.go': 'go', '.rb': 'rb', '.erb': 'rb', '.cs': 'cs', '.cshtml': 'cs', '.razor': 'cs',
  '.c': 'c', '.h': 'c', '.cc': 'c', '.cpp': 'c', '.cxx': 'c', '.hpp': 'c', '.hh': 'c', '.m': 'c', '.mm': 'c',
  '.rs': 'rs', '.swift': 'swift', '.dart': 'dart',
  '.sh': 'sh', '.bash': 'sh', '.zsh': 'sh', '.ps1': 'ps', '.psm1': 'ps', '.bat': 'bat', '.cmd': 'bat',
  '.sql': 'sql', '.html': 'html', '.htm': 'html', '.xhtml': 'html', '.jinja': 'html', '.j2': 'html', '.hbs': 'html', '.ejs': 'html',
  '.css': 'css', '.scss': 'css', '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json', '.xml': 'xml', '.toml': 'toml',
  '.ini': 'conf', '.cfg': 'conf', '.conf': 'conf', '.config': 'conf', '.properties': 'conf', '.env': 'env',
  '.tf': 'tf', '.tfvars': 'tf', '.hcl': 'tf', '.txt': 'text', '.md': 'text', '.lock': 'lock', '.pem': 'key', '.key': 'key',
};

export function langOf(rel) {
  const base = path.posix.basename(rel).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) return 'docker';
  if (base === '.env' || base.startsWith('.env.')) return 'env';
  if (base === 'makefile') return 'sh';
  if (base === 'gemfile' || base === 'rakefile') return 'rb';
  if (base === 'id_rsa' || base === 'id_dsa' || base === 'id_ecdsa' || base === 'id_ed25519') return 'key';
  return LANG_BY_EXT[path.posix.extname(base)] || 'other';
}

export function isIgnoredPath(rel) {
  const parts = rel.replace(/\\/g, '/').split('/');
  return parts.slice(0, -1).some((p) => IGNORED_DIRS.has(p)) || parts.includes('..');
}

const MANIFESTS = new Set([
  'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'requirements.txt', 'pipfile.lock',
  'poetry.lock', 'go.mod', 'cargo.lock', 'composer.lock', 'composer.json', 'gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
]);
export const isManifest = (rel) => MANIFESTS.has(path.posix.basename(rel).toLowerCase()) || /requirements[^/]*\.txt$/i.test(rel) || /\.csproj$/i.test(rel);

/** Walk a directory and return analysable text files with their content. */
export function walk(rootDir, { maxFiles, maxFileBytes }) {
  const files = [];
  const skipped = { binary: 0, large: 0, ignored: 0 };
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let ents;
    try { ents = fs.readdirSync(path.join(rootDir, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.ignored++; continue; }
      if (e.isDirectory()) {
        if (IGNORED_DIRS.has(e.name)) { skipped.ignored++; continue; }
        stack.push(r);
        continue;
      }
      if (!e.isFile()) continue;
      if (files.length >= maxFiles) { skipped.ignored++; continue; }
      const ext = path.posix.extname(e.name).toLowerCase();
      if (BINARY_EXT.has(ext)) { skipped.binary++; continue; }
      const abs = path.join(rootDir, r);
      const size = fs.statSync(abs).size;
      const manifest = isManifest(r);
      if (size > (manifest ? 25 * 1024 * 1024 : maxFileBytes)) { skipped.large++; continue; }
      const buf = fs.readFileSync(abs);
      if (buf.subarray(0, 8000).includes(0)) { skipped.binary++; continue; }
      const content = buf.toString('utf8');
      files.push({ path: r, size, lang: langOf(r), manifest, content, minified: isMinified(r, content) });
    }
  }
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped };
}

function isMinified(rel, content) {
  if (/\.min\.(js|css)$/i.test(rel)) return true;
  if (content.length < 5000) return false;
  const lines = content.split('\n');
  return content.length / Math.max(1, lines.length) > 300;
}
