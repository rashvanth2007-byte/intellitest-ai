import { snippetAt } from './rules/index.js';

/** Provider-specific secret patterns (high precision). */
const PROVIDERS = [
  ['aws-access-key', 'AWS access key ID', /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/, 'critical'],
  ['aws-secret-key', 'AWS secret access key', /aws.{0,25}(?:secret|sk).{0,25}["'`=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/i, 'critical'],
  ['github-token', 'GitHub token', /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/, 'critical'],
  ['github-pat', 'GitHub fine-grained token', /\b(github_pat_[A-Za-z0-9_]{60,255})\b/, 'critical'],
  ['gitlab-token', 'GitLab personal access token', /\b(glpat-[A-Za-z0-9_-]{20,})\b/, 'critical'],
  ['slack-token', 'Slack token', /\b(xox[baprse]-[0-9A-Za-z-]{10,})\b/, 'high'],
  ['slack-webhook', 'Slack webhook URL', /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/, 'high'],
  ['stripe-live', 'Stripe live secret key', /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/, 'critical'],
  ['stripe-test', 'Stripe test secret key', /\b(sk_test_[0-9a-zA-Z]{20,})\b/, 'low'],
  ['google-api-key', 'Google API key', /\b(AIza[0-9A-Za-z_-]{35})\b/, 'high'],
  ['google-oauth-secret', 'Google OAuth client secret', /\b(GOCSPX-[A-Za-z0-9_-]{28})\b/, 'high'],
  ['gcp-service-account', 'GCP service account key', /"type"\s*:\s*"(service_account)"/, 'critical'],
  ['anthropic-key', 'Anthropic API key', /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,})\b/, 'critical'],
  ['openai-key', 'OpenAI API key', /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b|\b(sk-proj-[A-Za-z0-9_-]{60,})\b/, 'critical'],
  ['huggingface-token', 'Hugging Face token', /\b(hf_[A-Za-z]{34,})\b/, 'high'],
  ['sendgrid-key', 'SendGrid API key', /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/, 'high'],
  ['mailgun-key', 'Mailgun API key', /\b(key-[0-9a-zA-Z]{32})\b/, 'high'],
  ['twilio-key', 'Twilio API key', /\b(SK[0-9a-fA-F]{32})\b/, 'high'],
  ['npm-token', 'npm access token', /\b(npm_[A-Za-z0-9]{36})\b/, 'critical'],
  ['pypi-token', 'PyPI API token', /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/, 'critical'],
  ['discord-token', 'Discord bot token', /\b([MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38})\b/, 'high'],
  ['discord-webhook', 'Discord webhook URL', /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{60,})/, 'medium'],
  ['telegram-token', 'Telegram bot token', /\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b/, 'high'],
  ['shopify-token', 'Shopify access token', /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/, 'high'],
  ['square-token', 'Square access token', /\b(EAAA[a-zA-Z0-9_-]{60})\b/, 'high'],
  ['azure-storage', 'Azure storage connection string', /(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,})/, 'critical'],
  ['firebase-db-secret', 'Firebase legacy secret', /firebase.{0,30}["']([A-Za-z0-9]{40})["']/i, 'high'],
  ['private-key', 'Private key', /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/, 'critical'],
  ['jwt-literal', 'Hardcoded JSON Web Token', /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/, 'medium'],
  ['db-uri-password', 'Database URL with embedded password', /\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver):\/\/[^:\s'"/@]+:[^@\s'"]{3,}@[^\s'"]+)/, 'high'],
];

const GENERIC = /(?:^|[\s{,;(["'`])((?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|token))["'`]?\s*(?:[:=]|=>|:=)\s*["'`]([^"'`\s]{6,200})["'`]/i;
const PLACEHOLDER = /^(?:x+|\*+|\.+|-+|_+|0+|1234\w*|password\d*|secret|changeme|change[-_]?me|example\w*|sample\w*|test\w*|dummy\w*|fake\w*|placeholder|your[-_\w]*|<.*>|\{.*\}|\$\{.*\}|\$\w+|%\w+%|null|none|undefined|true|false|todo|tbd|redacted|xxx.*|\.\.\.|process\.env.*|os\.environ.*)$/i;

function entropy(s) {
  const m = new Map();
  for (const ch of s) m.set(ch, (m.get(ch) || 0) + 1);
  let e = 0;
  for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}

/** Never reveal more than a short prefix (and, for long values, 2 trailing chars) of a secret. */
export function mask(v) {
  const s = String(v);
  if (s.length <= 8) return '•'.repeat(s.length);
  if (s.length < 20) return `${s.slice(0, 2)}${'•'.repeat(s.length - 2)}`;
  return `${s.slice(0, 4)}${'•'.repeat(Math.min(12, s.length - 6))}${s.slice(-2)}`;
}

// Values that are identifiers / digests / sample data rather than credentials (generic detector only).
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMPTY_DIGESTS = new Set([
  'd41d8cd98f00b204e9800998ecf8427e', // md5('')
  'da39a3ee5e6b4b0d3255bfef95601890afd80709', // sha1('')
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // sha256('')
]);
const HEX_DIGEST =/^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$/i;
const SAMPLEISH = /EXAMPLE|xxxx|\.\.\.|sample|dummy|placeholder|changeme|abcdef|123456|qwerty|asdfgh|lorem/i;
const NOT_A_SECRET = /^(?:[\w.-]+\.(?:lock|json|js|ts|py|txt|ya?ml|toml|xml|html|pem|key|crt|cer|p12|pfx|jks|env)|(?:https?:)?\/\/[^@\s]*|\.{0,2}\/[\w./-]*|[a-z0-9_-]+(?:\/[a-z0-9_.-]+)+|(?:Bearer|Basic|Token)\s?)$/;
// Base64 runs (key bodies) inside a private-key snippet.
const B64_RUN = /[A-Za-z0-9+/]{20,}={0,2}/g;

const isExampleFile = (p) => /\.(?:example|sample|template|dist)(?:\.|$)|(^|\/)(?:docs?|examples?|samples?)\//i.test(p) || /(?:test|spec|fixture|mock)/i.test(p);

/** Replace every known secret value in a string. */
export function maskAll(text, values) {
  let s = String(text ?? '');
  for (const v of values) if (v && s.includes(v)) s = s.split(v).join(mask(v));
  return s;
}

/** Returns findings; `.values` holds the raw secret strings so callers can redact them elsewhere. */
export function runSecrets(files) {
  const out = [];
  const seen = new Set();
  const values = new Set();
  for (const f of files) {
    if (f.minified || f.lang === 'lock' || /(?:package-lock|yarn\.lock|pnpm-lock|poetry\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|go\.sum)$/i.test(f.path)) continue;
    const lines = f.content.split(/\r?\n/);
    const example = isExampleFile(f.path);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4000) continue;
      let matched = false;
      for (const [id, name, re, sev] of PROVIDERS) {
        const m = line.match(re);
        if (!m) continue;
        const value = m[1] || m[2] || m[0];
        if (PLACEHOLDER.test(value) || /EXAMPLE|xxxx|\.\.\./i.test(value)) continue;
        // Per file: the same leaked token must be removed from every file, and fixed-text values such as a
        // private-key header or "service_account" would otherwise only be reported once per project.
        const key = `${id}|${f.path}|${value}${id === 'private-key' || id === 'gcp-service-account' ? `|${i}` : ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        values.add(value);
        matched = true;
        out.push(finding({ id, name, sev: example && sev !== 'critical' ? 'low' : sev, f, line: i + 1, lines, value, provider: true }));
      }
      if (matched) continue;
      const g = line.match(GENERIC);
      if (g) {
        const value = g[2];
        if (PLACEHOLDER.test(value) || /^[a-z_]+$/i.test(value) && value.length < 12) continue;
        if (/^\$(?:2[abxy]?|argon2\w*|scrypt|pbkdf2[\w-]*)\$/.test(value)) continue; // password hashes, not credentials
        if (UUID.test(value) || SAMPLEISH.test(value) || NOT_A_SECRET.test(value) || EMPTY_DIGESTS.has(value.toLowerCase())) continue;
        // Bare hex strings are often digests/IDs but some vendors (e.g. Datadog) use hex API keys: report quietly.
        const hexOnly = HEX_DIGEST.test(value);
        if (/^(?:sha(?:1|256|384|512)|md5)-[A-Za-z0-9+/=]+$/.test(value) || /^data:[\w/+.-]+;base64,/.test(value)) continue; // SRI / data URI
        if (/process\.env|os\.environ|getenv|ENV\[|config\.|settings\.|\$\{|\{\{/.test(line)) continue;
        if (entropy(value) < 3.0) continue;
        const key = `generic|${f.path}|${value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        values.add(value);
        const fnd = finding({ id: 'hardcoded-credential', name: `Hardcoded credential (${g[1]})`, sev: example || hexOnly ? 'low' : 'high', f, line: i + 1, lines, value, provider: false });
        if (hexOnly) fnd.confidence = 'low';
        out.push(fnd);
      }
    }
  }
  // A snippet's context lines can contain *other* secrets — redact all of them everywhere.
  // Private keys: only the BEGIN header is the matched "value"; the key body sits on the following lines
  // (or later on the same line in JSON "\n"-joined form), so mask every base64 run in those snippets.
  for (const f of out) {
    const keyish = f.ruleId === 'secret-private-key' || f.ruleId === 'secret-gcp-service-account';
    f.snippet = f.snippet.map((l) => {
      let t = maskAll(l.t, values);
      if (keyish) t = t.replace(B64_RUN, (m) => mask(m));
      return { n: l.n, t };
    });
  }
  out.values = [...values];
  return out;
}

function finding({ id, name, sev, f, line, lines, value, provider }) {
  const snippet = snippetAt(lines, line);
  const cvss = { critical: 9.1, high: 7.5, medium: 5.3, low: 3.1 }[sev];
  return {
    engine: 'secrets',
    ruleId: `secret-${id}`,
    agent: 'cipher',
    severity: sev,
    cvss,
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    category: 'Hardcoded Secret',
    title: `${name} exposed in source`,
    file: f.path,
    line,
    snippet,
    description: `${provider ? 'A credential matching the format of a' : 'A literal that looks like a'} ${name.replace(/^Hardcoded credential/, 'credential')} is committed in the code (value: ${mask(value)}).`,
    impact: 'Anyone who can read the repository, build artifacts or client bundle can use this credential to access the associated service or data.',
    recommendation: 'Revoke/rotate this credential now, remove it from the code and git history (git filter-repo / BFG), and load it from an environment variable or secret manager.',
    confidence: provider ? 'high' : 'medium',
  };
}
