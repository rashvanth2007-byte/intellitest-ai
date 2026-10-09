/**
 * Dependency vulnerability scanning: parse lockfiles/manifests, query OSV.dev (aggregates GitHub
 * Security Advisories, PyPA, RustSec, Go vulndb, etc.) and turn advisories into findings.
 */
import path from 'node:path';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

/* ───────────────────────── manifest parsers ───────────────────────── */
const cleanVer = (v) => {
  const m = String(v || '').match(/\d+(?:\.\d+){0,3}(?:[-+.][0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
};

// Only registry versions can be looked up (skips file:, link:, git URLs, workspace "0.0.0-use.local", …).
const isRegistryVersion = (v) => /^\d+\.\d+/.test(String(v || '')) && !/-use\.local$/.test(v);

function addDep(list, eco, name, version, file, exact = true, dev = false) {
  if (!name || !version) return;
  list.push({ ecosystem: eco, name, version, file, exact, dev });
}

/** npm alias "npm:real-name@1.2.3" → { name: 'real-name', version: '1.2.3' }. */
function npmAlias(name, version) {
  const m = String(version || '').match(/^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/);
  return m ? { name: m[1], version: m[2] } : { name, version };
}

/** Name part of a yarn spec: "@scope/x@npm:^1.0.0" → "@scope/x"; aliases resolve to the real package. */
function yarnSpecName(spec) {
  const alias = spec.match(/^(?:@[^/@]+\/)?[^@]+@npm:((?:@[^/@]+\/)?[^@]+)@/);
  if (alias) return alias[1];
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  return at > 0 ? spec.slice(0, at) : spec;
}

const parsers = {
  'package-lock.json': (c, file, out) => {
    const j = JSON.parse(c);
    if (j.packages) {
      for (const [k, v] of Object.entries(j.packages)) {
        // '' is the root project; keys without node_modules/ are workspace sources, not installed packages.
        if (!k || !k.includes('node_modules/') || !v?.version || v.link) continue;
        const name = v.name || k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);
        if (isRegistryVersion(v.version)) addDep(out, 'npm', name, v.version, file, true, !!(v.dev || v.devOptional));
      }
    } else if (j.dependencies) {
      // lockfile v1: nested "dependencies" trees; aliases appear as version "npm:real@1.2.3".
      const walkDeps = (deps) => {
        for (const [n, v] of Object.entries(deps || {})) {
          const a = npmAlias(n, v?.version);
          if (isRegistryVersion(a.version)) addDep(out, 'npm', a.name, a.version, file, true, !!v.dev);
          walkDeps(v?.dependencies);
        }
      };
      walkDeps(j.dependencies);
    }
  },
  'yarn.lock': (c, file, out) => {
    // Handles yarn v1 (`version "1.2.3"`) and berry (`version: 1.2.3` + `resolution: "pkg@npm:1.2.3"`).
    let block = null;
    const flush = () => {
      if (!block || !block.version) return;
      let name = block.name;
      if (block.resolution) {
        const r = block.resolution.match(/^((?:@[^/@]+\/)?[^@]+)@([a-z]+):/);
        if (r && !['npm', 'patch'].includes(r[2])) return; // workspace:, link:, portal:, file:, git…
        if (r) name = r[1];
      }
      if (name && isRegistryVersion(block.version)) addDep(out, 'npm', name, block.version, file);
    };
    for (const line of c.split(/\r?\n/)) {
      if (/^\S/.test(line) && line.trimEnd().endsWith(':') && !line.startsWith('#')) {
        flush();
        const specs = line.trimEnd().slice(0, -1).split(/,\s*/).map((s) => s.replace(/^"|"$/g, ''));
        block = specs[0] === '__metadata' || specs.some((s) => /@(?:file|link|workspace|portal):/.test(s))
          ? null
          : { name: yarnSpecName(specs[0]), version: null, resolution: null };
      } else if (block) {
        const v = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
        if (v) block.version = v[1];
        const r = line.match(/^\s+resolution:?\s+"?([^"\s]+)"?/);
        if (r) block.resolution = r[1];
      }
    }
    flush();
  },
  'pnpm-lock.yaml': (c, file, out) => {
    // v5: "  /name/1.2.3_peer@x:"  v6: "  /name@1.2.3(peer@x):"  v9: "  name@1.2.3:" / "  '@scope/n@1.2.3(peer)':"
    const re = /^ {2}['"]?\/?((?:@[^/@\s]+\/)?[^/@\s'"]+)[@/](\d[^:('"\s_]*)/gm;
    let m;
    while ((m = re.exec(c))) addDep(out, 'npm', m[1], m[2], file);
  },
  'package.json': (c, file, out, ctx) => {
    if (ctx.hasLock.npm) return;
    const j = JSON.parse(c);
    for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [n, v] of Object.entries(j[sec] || {})) {
        if (typeof v !== 'string' || /^(?:file:|link:|workspace:|portal:|git|http|github:|[\w-]+\/[\w.-]+$)/.test(v)) continue;
        const a = npmAlias(n, v);
        addDep(out, 'npm', a.name, cleanVer(a.version), file, false, sec === 'devDependencies');
      }
    }
  },
  'requirements.txt': (c, file, out, ctx) => {
    for (const raw of c.split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      if (!line || line.startsWith('-')) continue;
      const m = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([\w.*+!-]+)?/);
      if (!m) continue;
      if (m[2] === '==' && m[3] && !m[3].includes('*')) addDep(out, 'PyPI', m[1], m[3], file);
      else if (m[3]) addDep(out, 'PyPI', m[1], cleanVer(m[3]), file, false);
      else ctx.unpinned.push({ file, name: m[1] });
    }
  },
  'Pipfile.lock': (c, file, out) => {
    const j = JSON.parse(c);
    for (const sec of ['default', 'develop']) for (const [n, v] of Object.entries(j[sec] || {})) addDep(out, 'PyPI', n, cleanVer(v.version), file, true, sec === 'develop');
  },
  'poetry.lock': (c, file, out) => {
    for (const block of c.split(/^\[\[package\]\]\s*$/m).slice(1)) {
      const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
      const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
      // Poetry < 1.5 marks dev packages with category = "dev".
      addDep(out, 'PyPI', name, version, file, true, /^category\s*=\s*"dev"/m.test(block.split(/^\[/m)[0]));
    }
  },
  'go.mod': (c, file, out) => {
    // Only `require` lines / blocks — not replace/exclude/retract (their left-hand modules are not used as-is).
    let block = null;
    for (const raw of c.split(/\r?\n/)) {
      const line = raw.replace(/\/\/.*$/, '').trim();
      if (!line) continue;
      if (block) { if (line === ')') { block = null; continue; } }
      else {
        const open = line.match(/^(require|replace|exclude|retract)\s*\($/);
        if (open) { block = open[1]; continue; }
      }
      const directive = block || line.split(/\s+/)[0];
      if (directive !== 'require') continue;
      const m = (block ? line : line.replace(/^require\s+/, '')).match(/^([\w.~-]+\.[\w.~-]+\/\S+|[\w.~-]+\.[\w.~-]+)\s+v(\d[\w.+-]*)$/);
      if (m) addDep(out, 'Go', m[1], m[2].replace(/\+incompatible$/, ''), file);
    }
  },
  'Cargo.lock': (c, file, out) => {
    const re = /\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
    let m;
    while ((m = re.exec(c))) addDep(out, 'crates.io', m[1], m[2], file);
  },
  'composer.lock': (c, file, out) => {
    const j = JSON.parse(c);
    for (const p of j.packages || []) addDep(out, 'Packagist', p.name, cleanVer(p.version), file);
    for (const p of j['packages-dev'] || []) addDep(out, 'Packagist', p.name, cleanVer(p.version), file, true, true);
  },
  'Gemfile.lock': (c, file, out) => {
    let inSpecs = false;
    for (const line of c.split(/\r?\n/)) {
      if (/^\s{2}specs:/.test(line)) { inSpecs = true; continue; }
      if (/^\S/.test(line)) inSpecs = false;
      // Platform gems look like "nokogiri (1.10.0-x86_64-linux)".
      const m = inSpecs && line.match(/^\s{4}([\w.-]+) \((\d[\w.]*)(?:-[\w-]+)?\)/);
      if (m) addDep(out, 'RubyGems', m[1], m[2], file);
    }
  },
  'pom.xml': (c, file, out) => {
    const props = {};
    for (const m of c.matchAll(/<([\w.-]+)>([^<${}]+)<\/\1>/g)) props[m[1]] = m[2].trim();
    for (const m of c.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
      const g = m[1].match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
      const a = m[1].match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
      let v = m[1].match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
      if (v && /^\$\{(.+)\}$/.test(v)) v = props[v.slice(2, -1)];
      // Skip unresolved properties and version ranges such as [1.0,2.0).
      if (g && a && v && !v.includes('$') && !/^[[(]/.test(v)) addDep(out, 'Maven', `${g}:${a}`, v, file);
    }
  },
  'build.gradle': (c, file, out) => {
    const CONF = String.raw`(?:\w*[iI]mplementation|\w*[aA]pi|\w*[cC]ompile(?:Only)?|\w*[rR]untime(?:Only)?|annotationProcessor|kapt|ksp|classpath)`;
    for (const m of c.matchAll(new RegExp(String.raw`\b${CONF}\s*\(?\s*(?:platform\s*\(\s*)?["']([\w.-]+):([\w.-]+):([\w.-]+)(?:@\w+)?["']`, 'g'))) addDep(out, 'Maven', `${m[1]}:${m[2]}`, m[3], file);
    // Map notation: implementation group: 'g', name: 'a', version: 'v'
    for (const m of c.matchAll(new RegExp(String.raw`\b${CONF}\s*\(?\s*group\s*[:=]\s*["']([\w.-]+)["']\s*,\s*name\s*[:=]\s*["']([\w.-]+)["']\s*,\s*version\s*[:=]\s*["']([\w.-]+)["']`, 'g'))) addDep(out, 'Maven', `${m[1]}:${m[2]}`, m[3], file);
  },
  '.csproj': (c, file, out) => {
    // Attributes in any order, or <Version> as a child element.
    for (const m of c.matchAll(/<PackageReference\b([^>]*?)(\/>|>([\s\S]*?)<\/PackageReference>)/gi)) {
      const name = m[1].match(/\bInclude\s*=\s*"([^"]+)"/i)?.[1];
      const ver = m[1].match(/\bVersion\s*=\s*"([^"]+)"/i)?.[1] || m[3]?.match(/<Version>\s*([^<]+?)\s*<\/Version>/i)?.[1];
      if (name && ver && !/^[[(]/.test(ver)) addDep(out, 'NuGet', name, cleanVer(ver), file);
    }
  },
};

function parserFor(rel) {
  const base = path.posix.basename(rel);
  if (base === 'npm-shrinkwrap.json') return parsers['package-lock.json'];
  if (/^requirements[^/]*\.txt$/i.test(base)) return parsers['requirements.txt'];
  if (base === 'build.gradle.kts') return parsers['build.gradle'];
  if (/\.csproj$/i.test(base)) return parsers['.csproj'];
  return parsers[base] || null;
}

export function collectDependencies(files) {
  const deps = [];
  const ctx = { hasLock: { npm: false }, unpinned: [], errors: [] };
  const dirsWithLock = new Set(files.filter((f) => /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$/.test(f.path)).map((f) => path.posix.dirname(f.path)));
  const manifests = files.filter((f) => parserFor(f.path));
  const missingLock = [];
  for (const f of manifests) {
    const p = parserFor(f.path);
    ctx.hasLock.npm = dirsWithLock.has(path.posix.dirname(f.path));
    if (path.posix.basename(f.path) === 'package.json' && !ctx.hasLock.npm && /"(?:dev)?[dD]ependencies"\s*:\s*\{\s*"/.test(f.content)) missingLock.push(f.path);
    try { p(f.content, f.path, deps, ctx); } catch (e) { ctx.errors.push(`${f.path}: ${e.message}`); }
  }
  // De-duplicate identical package versions (lockfiles list many).
  const uniq = new Map();
  for (const d of deps) {
    const k = `${d.ecosystem}|${d.name}|${d.version}`;
    const prev = uniq.get(k);
    // A package is "dev only" only if every occurrence is dev.
    if (!prev) uniq.set(k, d);
    else uniq.set(k, { ...(d.exact && !prev.exact ? d : prev), dev: prev.dev && d.dev });
  }
  return { deps: [...uniq.values()], unpinned: ctx.unpinned, missingLock, errors: ctx.errors, manifests: manifests.map((m) => m.path) };
}

/* ───────────────────────── CVSS v3 base score ───────────────────────── */
export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector).split('/').slice(1).map((p) => p.split(':')));
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  // All eight base metrics must be present with legal values (a missing A: or an "X" would yield 0 / NaN).
  const LEGAL = { AV: 'NALP', AC: 'LH', PR: 'NLH', UI: 'NR', S: 'UC', C: 'HLN', I: 'HLN', A: 'HLN' };
  for (const [k, ok] of Object.entries(LEGAL)) if (!m[k] || m[k].length !== 1 || !ok.includes(m[k])) return null;
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR * W.UI[m.UI];
  if (!(impact > 0)) return 0;
  const roundUp = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

const sevFromScore = (s) => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low');
const SEV_TEXT = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
const DEFAULT_CVSS = { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0 };

function severityOf(v) {
  for (const s of v.severity || []) {
    if (s.type === 'CVSS_V3' && /^CVSS:3/.test(s.score)) {
      const n = cvss3Score(s.score);
      if (n != null) return { severity: sevFromScore(n), cvss: n, vector: s.score };
    }
  }
  const txt = SEV_TEXT[String(v.database_specific?.severity || v.affected?.[0]?.database_specific?.severity || '').toUpperCase()];
  if (txt) return { severity: txt, cvss: DEFAULT_CVSS[txt] };
  return { severity: 'medium', cvss: 5.0 };
}

function fixedVersions(v, dep) {
  const fixed = new Set();
  for (const a of v.affected || []) {
    if (a.package?.name && a.package.name.toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed];
}

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) return reject(signal.reason ?? Object.assign(new Error('Aborted'), { name: 'AbortError' }));
  const t = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
  const onAbort = () => { clearTimeout(t); reject(signal.reason ?? Object.assign(new Error('Aborted'), { name: 'AbortError' })); };
  signal?.addEventListener('abort', onAbort, { once: true });
});

/**
 * fetch with retries on network errors, 429 and 5xx (OSV rate-limits bursts). Returns the final Response
 * (which may still be !ok, e.g. 404) or throws the last network error. Aborts are never retried.
 */
export async function fetchRetry(url, init = {}, { retries = 2, baseDelay = 500, fetchImpl = fetch } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await fetchImpl(url, init);
      if ((r.status === 429 || r.status >= 500) && attempt < retries) {
        const ra = Number(r.headers?.get?.('retry-after'));
        await sleep(Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 10_000) : baseDelay * 2 ** attempt, init.signal);
        continue;
      }
      return r;
    } catch (e) {
      if (e?.name === 'AbortError' || init.signal?.aborted || attempt >= retries) throw e;
      await sleep(baseDelay * 2 ** attempt, init.signal);
    }
  }
}

async function postJson(url, body, signal, fetchImpl, baseDelay) {
  const r = await fetchRetry(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal }, { fetchImpl, baseDelay });
  if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
  return r.json();
}

async function mapLimit(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

/** Look up vulnerabilities for dependencies. Returns { findings, warnings, stats }. */
export async function runDeps(files, { enabled = true, signal, fetchImpl = fetch, retryDelay = 500 } = {}) {
  const { deps, unpinned, missingLock, errors, manifests } = collectDependencies(files);
  const findings = [];
  const warnings = errors.map((e) => `Could not parse ${e}`);
  const lineOf = (file, name) => {
    const f = files.find((x) => x.path === file);
    if (!f) return 1;
    const lines = f.content.split(/\r?\n/);
    for (const needle of [`"node_modules/${name}"`, `"${name}"`, `${name}@`, `${name}==`, name]) {
      const idx = lines.findIndex((l) => l.includes(needle));
      if (idx >= 0) return idx + 1;
    }
    return 1;
  };

  for (const file of missingLock) {
    findings.push({
      engine: 'deps', ruleId: 'deps-missing-lockfile', agent: 'nexus', severity: 'low', cvss: 3.1, cwe: 'CWE-1357', owasp: 'A06:2021',
      category: 'Supply Chain', title: 'No lockfile for npm dependencies', file, line: 1,
      description: 'package.json declares dependencies but no package-lock.json / yarn.lock / pnpm-lock.yaml is present, so installs resolve to whatever versions are newest at install time.',
      impact: 'Non-reproducible builds; a compromised or vulnerable new release can slip in silently.',
      recommendation: 'Commit the lockfile and install with npm ci / yarn --frozen-lockfile in CI.', confidence: 'high',
    });
  }
  if (unpinned.length) {
    const byFile = Object.groupBy ? Object.groupBy(unpinned, (u) => u.file) : unpinned.reduce((a, u) => ((a[u.file] ||= []).push(u), a), {});
    for (const [file, list] of Object.entries(byFile)) {
      findings.push({
        engine: 'deps', ruleId: 'deps-unpinned', agent: 'nexus', severity: 'low', cvss: 3.1, cwe: 'CWE-1104', owasp: 'A06:2021',
        category: 'Supply Chain', title: `${list.length} unpinned Python requirement${list.length > 1 ? 's' : ''}`, file, line: lineOf(file, list[0].name),
        description: `These packages have no version pin: ${list.slice(0, 15).map((u) => u.name).join(', ')}${list.length > 15 ? '…' : ''}.`,
        impact: 'Builds may pull different (possibly vulnerable or malicious) versions over time.',
        recommendation: 'Pin exact versions (pip freeze / pip-compile) and use hashes (--require-hashes).', confidence: 'high',
      });
    }
  }

  const stats = { manifests: manifests.length, packages: deps.length, vulnerable: 0, advisories: 0 };
  if (!deps.length) return { findings, warnings, stats };
  if (!enabled) { warnings.push('Dependency CVE lookup is disabled (OSV_ENABLED=false).'); return { findings, warnings, stats }; }

  try {
    const batches = [];
    for (let i = 0; i < deps.length; i += 900) batches.push(deps.slice(i, i + 900));
    const hits = []; // { dep, ids }
    for (const batch of batches) {
      const resp = await postJson(OSV_BATCH, { queries: batch.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }, signal, fetchImpl, retryDelay);
      (resp.results || []).forEach((r, i) => { if (r?.vulns?.length) hits.push({ dep: batch[i], ids: r.vulns.map((v) => v.id).filter(Boolean) }); });
    }
    const ids = [...new Set(hits.flatMap((h) => h.ids))].slice(0, 400);
    const details = new Map();
    const missing = new Set();
    await mapLimit(ids, 8, async (id) => {
      try {
        const r = await fetchRetry(OSV_VULN + encodeURIComponent(id), { signal }, { fetchImpl, baseDelay: retryDelay });
        if (r.ok) details.set(id, await r.json());
        else missing.add(id);
      } catch (e) {
        if (e?.name === 'AbortError' || signal?.aborted) throw e;
        missing.add(id);
      }
    });
    stats.vulnerable = hits.length;
    stats.advisories = details.size;
    const totalIds = new Set(hits.flatMap((h) => h.ids)).size;
    if (missing.size || totalIds > ids.length) {
      warnings.push(`Details for ${missing.size + totalIds - ids.length} advisory record(s) could not be fetched from OSV; they are reported with default severity — see the advisory links.`);
    }

    for (const { dep, ids: vids } of hits) {
      // Collapse aliases (GHSA + CVE describing the same issue).
      const seenAlias = new Set();
      // Records with details first, so their aliases suppress a detail-less duplicate (GHSA vs CVE id).
      for (const id of [...vids].sort((a, b) => Number(details.has(b)) - Number(details.has(a)))) {
        const v = details.get(id);
        if (!v) {
          // Never drop a known hit just because the detail lookup failed: emit a minimal finding instead.
          if (seenAlias.has(id)) continue;
          seenAlias.add(id);
          const severity = dep.dev ? 'low' : 'medium';
          findings.push({
            engine: 'deps', ruleId: id, agent: 'nexus', severity, cvss: 5.0, cwe: 'CWE-1395', owasp: 'A06:2021',
            category: 'Vulnerable Dependency',
            title: `${dep.name}@${dep.version}${dep.dev ? ' (dev)' : ''}: known vulnerability ${id}`.slice(0, 200),
            file: dep.file, line: lineOf(dep.file, dep.name),
            description: `OSV.dev lists ${id} as affecting ${dep.name} ${dep.version}, but the advisory details could not be retrieved during this scan, so the severity shown is a default. See https://osv.dev/vulnerability/${id}.`,
            impact: `Applications using ${dep.ecosystem} package ${dep.name} ${dep.version} are affected by ${id}.`,
            recommendation: `Review https://osv.dev/vulnerability/${id} and upgrade ${dep.name} to a fixed version (then regenerate the lockfile).`,
            confidence: dep.exact ? 'high' : 'medium',
            extra: { advisory: id, cve: id.startsWith('CVE-') ? id : null, aliases: [id], vector: null, ecosystem: dep.ecosystem, package: dep.name, version: dep.version, dev: !!dep.dev, fixed: [], url: `https://osv.dev/vulnerability/${id}`, detailsUnavailable: true },
          });
          continue;
        }
        const aliases = [id, ...(v.aliases || [])];
        if (aliases.some((a) => seenAlias.has(a))) continue;
        aliases.forEach((a) => seenAlias.add(a));
        const sv = severityOf(v);
        const { cvss, vector } = sv;
        // Dev-only packages don't ship to production: lower the priority one level.
        const severity = dep.dev ? { critical: 'high', high: 'medium', medium: 'low', low: 'low' }[sv.severity] : sv.severity;
        const fixes = fixedVersions(v, dep);
        const cve = aliases.find((a) => a.startsWith('CVE-'));
        const cwe = v.database_specific?.cwe_ids?.[0] || 'CWE-1395';
        findings.push({
          engine: 'deps', ruleId: id, agent: 'nexus', severity, cvss, cwe, owasp: 'A06:2021',
          category: 'Vulnerable Dependency',
          title: `${dep.name}@${dep.version}${dep.dev ? ' (dev)' : ''}: ${v.summary || cve || id}`.slice(0, 200),
          file: dep.file, line: lineOf(dep.file, dep.name),
          description: `${(v.details || v.summary || 'Known vulnerability.').replace(/\s+/g, ' ').slice(0, 900)}${dep.exact ? '' : ' (Version inferred from a range in the manifest — confirm with your lockfile.)'}${dep.dev ? ' This is a development-only dependency, so it does not ship to production; severity was lowered one level.' : ''}`,
          impact: `Applications using ${dep.ecosystem} package ${dep.name} ${dep.version} are affected by ${[cve, id].filter(Boolean).filter((x, i, a) => a.indexOf(x) === i).join(' / ')}.`,
          recommendation: fixes.length
            ? `Upgrade ${dep.name} to ${fixes.join(' or ')} or later (then regenerate the lockfile).`
            : `No fixed version is published yet. Consider replacing ${dep.name} or mitigating per the advisory.`,
          confidence: dep.exact ? 'high' : 'medium',
          extra: { advisory: id, cve: cve || null, aliases, vector: vector || null, ecosystem: dep.ecosystem, package: dep.name, version: dep.version, dev: !!dep.dev, fixed: fixes, url: `https://osv.dev/vulnerability/${id}` },
        });
      }
    }
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    warnings.push(`Dependency CVE lookup unavailable (${e.message}). Check your internet connection; ${deps.length} packages were not checked.`);
  }
  return { findings, warnings, stats };
}
