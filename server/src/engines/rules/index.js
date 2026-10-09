import { RULES, FILE_CHECKS } from './catalog.js';

const MAX_PER_RULE_PER_FILE = 5;
const MAX_LINE_LEN = 1500;
const TEXTY = new Set(['text', 'lock', 'json', 'css']);

const isTestPath = (p) => /(^|\/)(tests?|__tests__|spec|specs|fixtures?|examples?|samples?|mocks?|testdata|e2e|cypress)(\/|$)|[._-](test|spec)\.\w+$/i.test(p);
const isCommentLine = (l) => /^\s*(?:\/\/|#(?!!)|\*|\/\*|<!--|--\s|;|REM\s)/i.test(l);

export function snippetAt(lines, lineNo, ctx = 2) {
  const start = Math.max(1, lineNo - ctx);
  const end = Math.min(lines.length, lineNo + ctx);
  const out = [];
  for (let i = start; i <= end; i++) out.push({ n: i, t: (lines[i - 1] || '').slice(0, 300) });
  return out;
}

function applies(rule, lang) {
  return rule.langs.includes('*') ? !TEXTY.has(lang) : rule.langs.includes(lang);
}

/** Run the line rules and file checks over all files. */
export function runRules(files) {
  const findings = [];
  for (const f of files) {
    if (f.minified || f.manifest && f.lang === 'json') continue;
    const lines = f.content.split(/\r?\n/);
    const testFile = isTestPath(f.path);

    for (const rule of RULES) {
      if (!applies(rule, f.lang)) continue;
      if (rule.unlessFile && rule.unlessFile.test(f.content)) continue;
      let hits = 0, extra = 0;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > MAX_LINE_LEN || isCommentLine(line)) continue;
        if (!rule.pattern.test(line)) continue;
        if (rule.requires && !rule.requires.test(line)) continue;
        if (rule.unless && rule.unless.test(line)) continue;
        if (rule.skip && rule.skip(lines, i)) continue;
        if (hits >= MAX_PER_RULE_PER_FILE) { extra++; continue; }
        hits++;
        findings.push(mk(rule, f, i + 1, lines, testFile));
      }
      if (extra) {
        const last = findings[findings.length - 1];
        last.description += ` (${extra} more occurrence${extra > 1 ? 's' : ''} of this pattern in the same file.)`;
      }
    }

    for (const chk of FILE_CHECKS) {
      if (!chk.langs.includes(f.lang)) continue;
      if (!chk.test(f.content, f)) continue;
      findings.push(mk(chk, f, chk.line(lines), lines, testFile));
    }
  }
  return findings;
}

function mk(rule, f, line, lines, testFile) {
  let severity = rule.severity;
  // Findings inside tests/fixtures are usually not exploitable in production — downgrade one level.
  if (testFile) severity = { critical: 'high', high: 'medium', medium: 'low', low: 'low' }[severity];
  return {
    engine: 'rules',
    ruleId: rule.id,
    agent: rule.agent,
    severity,
    cvss: testFile ? Math.max(0.1, rule.cvss - 2) : rule.cvss,
    cwe: rule.cwe,
    owasp: rule.owasp,
    category: rule.category,
    title: rule.title,
    file: f.path,
    line,
    snippet: snippetAt(lines, line),
    description: rule.description,
    impact: rule.impact,
    recommendation: rule.fix,
    confidence: testFile ? 'low' : 'medium',
  };
}
