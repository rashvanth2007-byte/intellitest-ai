/**
 * Choose which code the AI agents see. Files are ranked by security relevance and packed into
 * chunks under a character budget, so large projects are covered by priority instead of the
 * prototype's "first 7,000 characters".
 */
export const DEPTHS = {
  quick: { totalChars: 60_000, chunkChars: 60_000, label: 'Quick (~60k chars, 1 pass)' },
  standard: { totalChars: 180_000, chunkChars: 90_000, label: 'Standard (~180k chars)' },
  deep: { totalChars: 600_000, chunkChars: 150_000, label: 'Deep (~600k chars)' },
};

const CODE_LANGS = new Set(['js', 'py', 'php', 'java', 'go', 'rb', 'cs', 'c', 'rs', 'swift', 'dart', 'sh', 'ps', 'bat', 'sql', 'html', 'docker', 'yaml', 'tf', 'conf', 'env', 'xml']);
const HOT_NAMES = /(auth|login|signin|signup|register|session|token|jwt|oauth|password|admin|user|account|payment|checkout|upload|download|file|api|route|controller|handler|view|server|app|main|index|middleware|db|database|query|model|config|settings|security|crypto|webhook|graphql|resolver|exec|shell)/i;
const LOW_VALUE = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|mocks?|docs?|examples?|samples?|migrations?|locales?|i18n|assets|static\/vendor|public\/vendor)(\/|$)|\.(?:test|spec|stories|d)\.\w+$|\.(?:min|bundle)\.\w+$/i;

export function rankFiles(files, ruleFindings) {
  const hits = new Map();
  for (const f of ruleFindings) hits.set(f.file, (hits.get(f.file) || 0) + ({ critical: 8, high: 5, medium: 3, low: 1 }[f.severity] || 1));
  return files
    .filter((f) => CODE_LANGS.has(f.lang) && !f.minified && !f.manifest && f.content.trim())
    .map((f) => {
      let s = 10 + (hits.get(f.path) || 0) * 3;
      if (HOT_NAMES.test(f.path)) s += 12;
      if (LOW_VALUE.test(f.path)) s -= 15;
      if (['docker', 'yaml', 'tf', 'env', 'conf'].includes(f.lang)) s += 4;
      if (f.path.split('/').length <= 2) s += 3; // top-level entry points
      if (f.content.length > 60_000) s -= 5;
      return { f, s };
    })
    .sort((a, b) => b.s - a.s || a.f.path.localeCompare(b.f.path))
    .map((x) => x.f);
}

export function buildChunks(files, ruleFindings, depth = 'standard') {
  const cfg = DEPTHS[depth] || DEPTHS.standard;
  const ranked = rankFiles(files, ruleFindings);
  const chunks = [];
  let cur = { files: [], chars: 0 };
  let used = 0;
  let included = 0;
  const partial = [];

  for (const f of ranked) {
    if (used >= cfg.totalChars) break;
    const lines = f.content.split(/\r?\n/);
    let size = f.content.length + lines.length * 6 + f.path.length + 30;
    let entry = { path: f.path, content: f.content };
    const room = Math.min(cfg.chunkChars, cfg.totalChars - used);
    if (size > room) {
      // Too big: keep the first part of the file that fits.
      if (room < 4000) continue;
      let acc = 0, to = 0;
      while (to < lines.length && acc + lines[to].length + 8 < room - 200) { acc += lines[to].length + 8; to++; }
      if (to < 20) continue;
      entry = { path: f.path, content: f.content, from: 1, to };
      size = acc + 200;
      partial.push(f.path);
    }
    if (cur.chars + size > cfg.chunkChars && cur.files.length) { chunks.push(cur); cur = { files: [], chars: 0 }; }
    cur.files.push(entry);
    cur.chars += size;
    used += size;
    included++;
  }
  if (cur.files.length) chunks.push(cur);
  return { chunks, included, eligible: ranked.length, partial, chars: used };
}
