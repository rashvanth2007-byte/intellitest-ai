import { HttpError } from '../util/http.js';

const SEV_HEX = { critical: '#E11D48', high: '#EA580C', medium: '#CA8A04', low: '#059669' };
const AGENT_NAMES = { sentinel: 'SENTINEL', phantom: 'PHANTOM', cipher: 'CIPHER', nexus: 'NEXUS', oracle: 'ORACLE' };
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

export function renderReport(scan, fmt) {
  switch (fmt) {
    case 'json': return { body: JSON.stringify(toJson(scan), null, 2), type: 'application/json; charset=utf-8', ext: 'json' };
    case 'sarif': return { body: JSON.stringify(toSarif(scan), null, 2), type: 'application/sarif+json; charset=utf-8', ext: 'sarif' };
    case 'csv': return { body: toCsv(scan), type: 'text/csv; charset=utf-8', ext: 'csv' };
    case 'html': return { body: toHtml(scan), type: 'text/html; charset=utf-8', ext: 'html' };
    default: throw new HttpError(400, 'Unknown report format');
  }
}

function toJson(scan) {
  return {
    tool: { name: 'IntelliTest AI', version: '1.0.0' },
    scan: {
      id: scan.id, label: scan.label, source: scan.sourceKind, sourceRef: scan.sourceRef, engine: scan.engine, model: scan.aiModel,
      startedAt: new Date(scan.createdAt).toISOString(), finishedAt: scan.finishedAt ? new Date(scan.finishedAt).toISOString() : null,
      filesScanned: scan.filesScanned, linesScanned: scan.linesScanned, score: scan.score, grade: scan.grade, warnings: scan.warnings,
    },
    summary: { ...scan.counts, total: scan.total },
    findings: scan.findings.map(({ id, ...f }) => f),
  };
}

function toSarif(scan) {
  const rules = new Map();
  const results = [];
  const level = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
  for (const f of scan.findings) {
    const ruleId = f.ruleId || `${f.agent}-${(f.cwe || f.category).toLowerCase().replace(/\W+/g, '-')}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.category.replace(/\W+/g, ''),
        shortDescription: { text: f.title.slice(0, 200) },
        fullDescription: { text: f.description.slice(0, 1000) || f.title },
        help: { text: f.recommendation || 'See description.' },
        properties: { tags: ['security', f.cwe, f.owasp].filter(Boolean), 'security-severity': String(f.cvss ?? '') },
      });
    }
    const r = {
      ruleId,
      level: level[f.severity],
      message: { text: `${f.title}${f.description ? ` — ${f.description}` : ''}`.slice(0, 2000) },
      properties: { severity: f.severity, cvss: f.cvss, confidence: f.confidence, engines: f.engines, agent: f.agent },
    };
    if (f.file) {
      r.locations = [{ physicalLocation: { artifactLocation: { uri: f.file }, ...(f.line ? { region: { startLine: f.line } } : {}) } }];
    }
    results.push(r);
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'IntelliTest AI', version: '1.0.0', informationUri: 'https://github.com/', rules: [...rules.values()] } },
      results,
    }],
  };
}

function toCsv(scan) {
  const cols = ['severity', 'cvss', 'title', 'category', 'cwe', 'owasp', 'file', 'line', 'agent', 'engines', 'confidence', 'description', 'recommendation'];
  const cell = (v) => {
    let s = Array.isArray(v) ? v.join('+') : String(v ?? '');
    if (/^\s*[=+\-@]/.test(s) || /^[\t\r]/.test(s)) s = `'${s}`; // neutralise spreadsheet formula injection
    return `"${s.replace(/"/g, '""')}"`;
  };
  return '﻿' + [cols.join(','), ...scan.findings.map((f) => cols.map((c) => cell(f[c])).join(','))].join('\r\n');
}

function toHtml(scan) {
  const c = scan.counts;
  const rows = scan.findings.map((f, i) => `
    <section class="f ${f.severity}">
      <header><span class="sev">${f.severity.toUpperCase()}</span><h3>${i + 1}. ${esc(f.title)}</h3><span class="cvss">CVSS ${f.cvss ?? '–'}</span></header>
      <div class="meta">${f.file ? `<code>${esc(f.file)}${f.line ? `:${f.line}` : ''}</code>` : ''} ${f.cwe ? `<span>${esc(f.cwe)}</span>` : ''} ${f.owasp ? `<span>OWASP ${esc(f.owasp)}</span>` : ''}
        <span>${esc(AGENT_NAMES[f.agent] || f.agent)}</span><span>${esc(f.engines.join(' + '))}</span><span>confidence: ${esc(f.confidence)}</span></div>
      ${f.snippet ? `<pre>${f.snippet.map((s) => `<span class="${s.n === f.line ? 'hl' : ''}">${String(s.n).padStart(5)}  ${esc(s.t)}</span>`).join('\n')}</pre>` : ''}
      <p><b>Description.</b> ${esc(f.description)}</p>
      ${f.impact ? `<p><b>Impact.</b> ${esc(f.impact)}</p>` : ''}
      ${f.recommendation ? `<p class="fix"><b>Fix.</b> ${esc(f.recommendation)}</p>` : ''}
      ${/^https?:\/\//i.test(f.extra?.url || '') ? `<p><a href="${esc(f.extra.url)}" rel="noopener noreferrer">${esc(f.extra.advisory || f.extra.url)}</a></p>` : ''}
    </section>`).join('');
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntelliTest AI report — ${esc(scan.label)}</title>
<style>
:root{--bg:#fff;--fg:#0f172a;--mid:#475569;--line:#e2e8f0;--card:#f8fafc}
@media (prefers-color-scheme:dark){:root{--bg:#0A0E17;--fg:#E7ECF3;--mid:#8B97AA;--line:#202B3D;--card:#131B29}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px;font-size:24px}.sub{color:var(--mid);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:22px 0}
.k{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.k b{display:block;font-size:24px}.k small{color:var(--mid);text-transform:uppercase;font-size:10px;letter-spacing:.5px}
.f{border:1px solid var(--line);border-left:4px solid;border-radius:8px;padding:14px 16px;margin:12px 0;break-inside:avoid;background:var(--card)}
.f.critical{border-left-color:${SEV_HEX.critical}}.f.high{border-left-color:${SEV_HEX.high}}.f.medium{border-left-color:${SEV_HEX.medium}}.f.low{border-left-color:${SEV_HEX.low}}
.f header{display:flex;gap:10px;align-items:center}.f h3{margin:0;font-size:15px;flex:1}.sev{font:700 10px monospace;padding:2px 7px;border-radius:10px;border:1px solid currentColor}
.critical .sev{color:${SEV_HEX.critical}}.high .sev{color:${SEV_HEX.high}}.medium .sev{color:${SEV_HEX.medium}}.low .sev{color:${SEV_HEX.low}}
.cvss{font:600 12px monospace;color:var(--mid)}.meta{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0;font-size:12px;color:var(--mid)}.meta code{color:var(--fg)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow:auto;font-size:12px;margin:8px 0}pre .hl{background:rgba(225,29,72,.15);display:inline-block;min-width:100%}
p{margin:6px 0}.fix{background:rgba(5,150,105,.08);border:1px solid rgba(5,150,105,.25);border-radius:6px;padding:8px 10px}
.warn{font-size:12px;color:var(--mid)}@media print{body{background:#fff;color:#000}.f{background:#fff}}
</style></head><body><div class="wrap">
<h1>IntelliTest AI — Security Report</h1>
<div class="sub">${esc(scan.label)} · ${new Date(scan.createdAt).toLocaleString()} · ${scan.filesScanned} files / ${scan.linesScanned} lines · engine: ${esc(scan.engine || 'rules')}${scan.aiModel ? ` (${esc(scan.aiModel)})` : ''}</div>
<div class="grid">
  <div class="k"><small>Grade</small><b>${esc(scan.grade || '–')} <span style="font-size:14px;color:var(--mid)">${scan.score ?? ''}/100</span></b></div>
  ${['critical', 'high', 'medium', 'low'].map((s) => `<div class="k"><small>${s}</small><b style="color:${SEV_HEX[s]}">${c[s] || 0}</b></div>`).join('')}
  <div class="k"><small>Total</small><b>${scan.total}</b></div>
</div>
${scan.warnings?.length ? `<div class="warn">${scan.warnings.map((w) => `⚠ ${esc(w)}`).join('<br>')}</div>` : ''}
${rows || '<p>No issues found.</p>'}
<p class="sub" style="margin-top:28px">Automated analysis may contain false positives or miss issues. Review findings before acting on them.</p>
</div></body></html>`;
}
