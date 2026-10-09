import { snippetAt } from '../engines/rules/index.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const DEFAULT_CVSS = { critical: 9.3, high: 7.5, medium: 5.3, low: 3.1 };
const SEV_ALIASES = { crit: 'critical', severe: 'critical', important: 'high', moderate: 'medium', med: 'medium', warning: 'medium', minor: 'low', info: 'low', informational: 'low', note: 'low' };

const sevFromCvss = (n) => (n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low');
const clip = (s, n) => (s == null ? '' : String(s).replace(/\u0000/g, '').trim().slice(0, n));

export function normSeverity(s, cvss) {
  const v = String(s || '').toLowerCase().trim();
  if (SEVERITIES.includes(v)) return v;
  if (SEV_ALIASES[v]) return SEV_ALIASES[v];
  if (Number.isFinite(cvss)) return sevFromCvss(cvss);
  return 'medium';
}

export function normCvss(v, severity) {
  const n = typeof v === 'number' ? v : parseFloat(String(v ?? '').replace(',', '.'));
  if (!Number.isFinite(n) || n <= 0) return severity ? DEFAULT_CVSS[severity] : null;
  return Math.round(Math.min(10, Math.max(0.1, n)) * 10) / 10;
}

function normCwe(c) {
  const m = String(c || '').match(/(\d{1,5})/);
  return m ? `CWE-${m[1]}` : null;
}

/** Find the scanned file an AI-reported path refers to (models sometimes add ./ or drop folders). */
function resolveFile(p, fileMap) {
  if (!p) return null;
  let s = String(p).replace(/\\/g, '/').replace(/^\.?\//, '').replace(/:\d+$/, '').trim();
  if (fileMap.has(s)) return s;
  const cands = [...fileMap.keys()].filter((k) => k.endsWith('/' + s) || s.endsWith('/' + k));
  return cands.length === 1 ? cands[0] : null;
}

/**
 * Validate + clean one finding. Returns null if an AI finding points at a file that was not scanned
 * (hallucination guard).
 */
export function normalizeFinding(raw, fileMap) {
  const cvssIn = typeof raw.cvss === 'number' ? raw.cvss : parseFloat(raw.cvss);
  const severity = normSeverity(raw.severity, cvssIn);
  const cvss = normCvss(raw.cvss, severity);
  let file = raw.file || raw.location || null;
  let line = parseInt(raw.line, 10);
  if (typeof file === 'string' && !Number.isFinite(line)) {
    const m = file.match(/:(\d+)$/);
    if (m) line = parseInt(m[1], 10);
  }
  const resolved = resolveFile(file, fileMap);
  if (raw.engine === 'ai') {
    if (!resolved) return null;
    file = resolved;
  } else if (resolved) file = resolved;

  const f = fileMap.get(file);
  const fromAi = raw.engine === 'ai';
  // Snippets are always rebuilt from the real file for AI findings; model-supplied ones are untrusted.
  let snippet = fromAi ? null : raw.snippet || null;
  if (f) {
    const lines = f.content.split(/\r?\n/);
    if (!Number.isFinite(line) || line < 1 || line > lines.length) line = null;
    if (!snippet && line) snippet = snippetAt(lines, line);
  } else if (!Number.isFinite(line)) line = null;

  return {
    engine: raw.engine,
    engines: [raw.engine],
    agent: raw.agent || 'sentinel',
    ruleId: raw.ruleId || null,
    severity,
    cvss,
    cwe: normCwe(raw.cwe),
    owasp: fromAi ? null : raw.owasp || null,
    category: clip(raw.category, 120) || 'Security issue',
    title: clip(raw.title, 200) || 'Unnamed issue',
    file: file ? clip(file, 500) : null,
    line,
    snippet,
    description: clip(raw.description, 4000),
    impact: clip(raw.impact, 2000),
    recommendation: clip(raw.recommendation, 4000),
    confidence: ['high', 'medium', 'low'].includes(raw.confidence) ? raw.confidence : 'medium',
    extra: fromAi ? null : raw.extra || null,
  };
}

/** Merge duplicates reported by several engines/agents for the same place and weakness. */
export function dedupe(findings) {
  const out = [];
  const sorted = [...findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (b.cvss || 0) - (a.cvss || 0));
  for (const f of sorted) {
    const dup = out.find((o) => o.file === f.file && f.file && (
      (o.ruleId && o.ruleId === f.ruleId && o.line === f.line && f.engine !== 'deps') ||
      (o.engine === 'deps' && f.engine === 'deps' && o.ruleId === f.ruleId && o.extra?.package === f.extra?.package) ||
      (f.engine !== 'deps' && o.engine !== 'deps' && o.line != null && f.line != null && Math.abs(o.line - f.line) <= 2 &&
        ((o.cwe && o.cwe === f.cwe) || o.category.toLowerCase() === f.category.toLowerCase()))
    ));
    if (!dup) { out.push({ ...f, engines: [...f.engines] }); continue; }
    for (const e of f.engines) if (!dup.engines.includes(e)) dup.engines.push(e);
    const static_ = dup.engines.some((e) => e !== 'ai');
    if (static_ && dup.engines.includes('ai')) dup.confidence = 'high';
    // Prefer the richer AI explanation when the AI confirms a rule hit.
    if (f.engine === 'ai' && dup.engine !== 'ai' && f.description.length > dup.description.length) {
      dup.description = f.description;
      if (f.recommendation) dup.recommendation = f.recommendation;
      if (f.impact) dup.impact = f.impact;
    }
  }
  return out;
}

export function countBySeverity(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

/** 0-100 security score and letter grade. */
export function scoreOf(findings) {
  const w = { critical: 20, high: 8, medium: 3, low: 0.5 };
  const cw = { high: 1, medium: 0.8, low: 0.4 };
  const p = findings.reduce((s, f) => s + w[f.severity] * (cw[f.confidence] ?? 0.8), 0);
  let score = Math.round(100 * Math.exp(-p / 60));
  if (findings.some((f) => f.severity === 'critical' && f.confidence !== 'low')) score = Math.min(score, 59);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F';
  return { score, grade };
}

export const sortFindings = (list) => [...list].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (b.cvss || 0) - (a.cvss || 0) || String(a.file).localeCompare(String(b.file)) || (a.line || 0) - (b.line || 0));
