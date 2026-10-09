import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runRules } from '../src/engines/rules/index.js';
import { runSecrets } from '../src/engines/secrets.js';
import { collectDependencies, cvss3Score } from '../src/engines/deps.js';
import { parseGithubUrl } from '../src/ingest/github.js';
import { langOf } from '../src/ingest/walker.js';
import { normalizeFinding, dedupe, scoreOf } from '../src/scan/normalize.js';
import { extractJson, salvageTruncated, parseClaudeResponse, parseGeminiResponse, geminiHttpError, classifyAnthropicError, testKey, AiError } from '../src/engines/ai/providers.js';
import { runAgents } from '../src/engines/ai/agents.js';
import { buildChunks } from '../src/engines/ai/chunker.js';
import { runDeps, fetchRetry } from '../src/engines/deps.js';
import { RULES } from '../src/engines/rules/catalog.js';
import Anthropic from '@anthropic-ai/sdk';

const file = (path, content) => ({ path, content, lang: langOf(path), size: content.length, manifest: false, minified: false });
const ids = (findings) => new Set(findings.map((f) => f.ruleId));

/* [rule id, file name, vulnerable line, safe line] */
const CASES = [
  ['sql-concat', 'db.js', 'db.query("SELECT * FROM users WHERE id = " + req.params.id);', 'db.query("SELECT * FROM users WHERE id = ?", [id]);'],
  ['sql-template', 'db.js', 'db.query(`SELECT * FROM users WHERE name = \'${name}\'`);', 'db.query("SELECT 1");'],
  ['py-sql-format', 'app.py', 'cur.execute("SELECT * FROM t WHERE id = %s" % uid)', 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))'],
  ['php-sqli', 'x.php', '$r = mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET["id"]);', '$stmt = $pdo->prepare("SELECT * FROM u WHERE id=?");'],
  ['nosql-injection', 'a.js', 'const u = await User.findOne(req.body);', 'const u = await User.findOne({ email: String(req.body.email) });'],
  ['js-cmd-injection', 'a.js', 'exec(`ping -c 1 ${req.query.host}`);', 'const m = /x/.exec(str);'],
  ['py-cmd-injection', 'a.py', 'os.system("ping " + host)', 'subprocess.run(["ping", host])'],
  ['code-eval-js', 'a.js', 'const r = eval(req.body.expr);', 'const r = JSON.parse(body);'],
  ['code-eval-py', 'a.py', 'result = eval(user_input)', 'result = ast.literal_eval(user_input)'],
  ['path-traversal-js', 'a.js', 'res.sendFile(path.join(__dirname, req.query.file));', 'res.sendFile(path.join(__dirname, "index.html"));'],
  ['ssrf-js', 'a.js', 'const r = await fetch(req.query.url);', 'const r = await fetch("https://api.example.com");'],
  ['xss-dom', 'a.js', 'el.innerHTML = userComment;', 'el.textContent = userComment;'],
  ['deserialization', 'a.py', 'obj = pickle.loads(data)', 'obj = json.loads(data)'],
  ['py-yaml-load', 'a.py', 'cfg = yaml.load(fh)', 'cfg = yaml.load(fh, Loader=yaml.SafeLoader)'],
  ['weak-hash', 'a.js', 'crypto.createHash("md5").update(x)', 'crypto.createHash("sha256").update(x)'],
  ['weak-cipher', 'A.java', 'Cipher c = Cipher.getInstance("DES");', 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'],
  ['insecure-random', 'a.js', 'const token = Math.random().toString(36);', 'const n = Math.random() * width;'],
  ['tls-verify-off', 'a.py', 'requests.get(url, verify=False)', 'requests.get(url)'],
  ['jwt-weak', 'a.js', 'jwt.verify(t, key, { algorithms: ["none"] })', 'jwt.verify(t, key, { algorithms: ["HS256"] })'],
  ['debug-enabled', 'a.py', 'app.run(debug=True)', 'app.run(debug=False)'],
  ['cors-wildcard', 'a.js', "res.setHeader('Access-Control-Allow-Origin', '*');", "res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');"],
  ['c-unsafe-func', 'a.c', 'strcpy(buf, input);', 'strncpy(buf, input, sizeof(buf) - 1);'],
  ['gha-script-injection', 'ci.yml', '      run: echo "${{ github.event.pull_request.title }}"', '      run: echo "$TITLE"'],
  ['k8s-privileged', 'pod.yaml', '        privileged: true', '        privileged: false'],
  ['tf-open-ingress', 'main.tf', '  cidr_blocks = ["0.0.0.0/0"]', '  cidr_blocks = ["10.0.0.0/8"]'],
  ['curl-pipe-shell', 'install.sh', 'curl -fsSL https://x.sh | bash', 'curl -fsSLo x.sh https://x.sh'],
  ['open-redirect', 'a.js', 'res.redirect(req.query.next);', 'res.redirect("/home");'],
  ['mass-assignment', 'a.js', 'await User.create(req.body);', 'await User.create({ name: req.body.name });'],
  ['nosql-where', 'dao.js', 'col.find({ $where: `this.userId == ${id}` });', 'col.find({ userId: parseInt(id, 10) });'],
  ['ssrf-js', 'r.js', 'needle.get(url + req.query.symbol, cb);', 'needle.get("https://api.example.com/x", cb);'],
  ['js-loose-auth-compare', 'a.js', 'if (user.password == password) {', 'const invalidPasswordError = new Error("Invalid password");'],
  ['csrf-disabled', 'Sec.java', 'http.csrf().disable();', 'http.csrf(Customizer.withDefaults());'],
];

for (const [id, name, bad, good] of CASES) {
  test(`rule ${id} fires on vulnerable code and not on the safe variant`, () => {
    assert.ok(ids(runRules([file(`src/${name}`, bad)])).has(id), `expected ${id} on: ${bad}`);
    assert.ok(!ids(runRules([file(`src/${name}`, good)])).has(id), `unexpected ${id} on: ${good}`);
  });
}

test('file checks: Dockerfile without USER and committed .env', () => {
  const r = runRules([file('Dockerfile', 'FROM node:22\nCOPY . .\nCMD ["node","x.js"]'), file('.env', 'DB_PASSWORD=hunter2hunter')]);
  assert.ok(ids(r).has('docker-root-user'));
  assert.ok(ids(r).has('env-file-committed'));
  const ok = runRules([file('Dockerfile', 'FROM node:22\nUSER node\nCMD ["node","x.js"]'), file('.env.example', 'DB_PASSWORD=')]);
  assert.ok(!ids(ok).has('docker-root-user'));
  assert.ok(!ids(ok).has('env-file-committed'));
});

test('findings in test folders are downgraded', () => {
  const [f] = runRules([file('test/db.test.js', 'db.query("SELECT * FROM u WHERE id = " + id);')]).filter((x) => x.ruleId === 'sql-concat');
  assert.equal(f.severity, 'high');
  assert.equal(f.confidence, 'low');
});

test('secrets: provider tokens detected and masked, placeholders ignored', () => {
  const ghToken = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
  const r = runSecrets([file('config.js', `const AWS = "AKIAIOSFODNN7ABCDEFG";\nconst gh = "${ghToken}";\nconst password = "changeme";\nconst api_key = "Zx9#kL2$mQ8!vB4@";`)]);
  const rid = ids(r);
  assert.ok(rid.has('secret-aws-access-key'));
  assert.ok(rid.has('secret-github-token'));
  assert.ok(rid.has('secret-hardcoded-credential'));
  assert.equal(r.filter((f) => f.ruleId === 'secret-hardcoded-credential').length, 1, 'changeme must be ignored');
  for (const f of r) assert.ok(!JSON.stringify(f).includes(ghToken), 'raw secret must not appear in finding');
});

test('dependency parsing: npm lock v3, requirements, go.mod, pom', () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/a/node_modules/minimist': { version: '0.0.8' } } });
  const { deps, unpinned } = collectDependencies([
    { ...file('package-lock.json', lock), manifest: true },
    { ...file('requirements.txt', 'django==3.2.0\nflask\nrequests>=2.0'), manifest: true },
    { ...file('go.mod', 'module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n)'), manifest: true },
    { ...file('pom.xml', '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>'), manifest: true },
  ]);
  const has = (eco, n, v) => deps.some((d) => d.ecosystem === eco && d.name === n && d.version === v);
  assert.ok(has('npm', 'lodash', '4.17.15'));
  assert.ok(has('npm', 'minimist', '0.0.8'));
  assert.ok(has('PyPI', 'django', '3.2.0'));
  assert.ok(has('Go', 'github.com/gin-gonic/gin', '1.6.0'));
  assert.ok(has('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'));
  assert.deepEqual(unpinned.map((u) => u.name), ['flask']);
});

test('CVSS v3.1 base score', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('GitHub URL parsing', () => {
  assert.deepEqual(parseGithubUrl('https://github.com/OWASP/NodeGoat'), { owner: 'OWASP', repo: 'NodeGoat', ref: null, subdir: null });
  assert.deepEqual(parseGithubUrl('github.com/a/b.git'), { owner: 'a', repo: 'b', ref: null, subdir: null });
  assert.deepEqual(parseGithubUrl('https://github.com/a/b/tree/dev/src/api'), { owner: 'a', repo: 'b', ref: 'dev', subdir: 'src/api' });
  assert.deepEqual(parseGithubUrl('git@github.com:a/b.git'), { owner: 'a', repo: 'b', ref: null, subdir: null });
  assert.equal(parseGithubUrl('https://gitlab.com/a/b'), null);
  assert.equal(parseGithubUrl('https://evil.com/github.com/a/b'), null);
  assert.equal(parseGithubUrl('git@github.com:../user'), null);
  assert.equal(parseGithubUrl('https://github.com/a/b/tree/%E0%A4%A/src'), null); // malformed escape must not throw
});

test('normalize: severity casing, string CVSS, hallucinated files dropped', () => {
  const fm = new Map([['src/a.js', file('src/a.js', 'line1\nline2\nline3')]]);
  const n = normalizeFinding({ engine: 'ai', severity: 'HIGH', cvss: '7.9', title: 't', file: './src/a.js', line: '2', category: 'X' }, fm);
  assert.equal(n.severity, 'high');
  assert.equal(n.cvss, 7.9);
  assert.equal(n.file, 'src/a.js');
  assert.equal(n.line, 2);
  assert.ok(n.snippet.length);
  assert.equal(normalizeFinding({ engine: 'ai', severity: 'low', title: 't', file: 'nope.js', line: 1 }, fm), null);
  assert.equal(normalizeFinding({ engine: 'ai', severity: 'bogus', cvss: 9.5, title: 't', file: 'src/a.js', line: 99 }, fm).severity, 'critical');
});

test('dedupe merges rule + AI findings on the same line and raises confidence', () => {
  const base = { file: 'a.js', line: 10, cwe: 'CWE-89', category: 'SQL Injection', title: 't', description: 'd', impact: '', recommendation: '', severity: 'critical', cvss: 9.8, confidence: 'medium' };
  const out = dedupe([{ ...base, engine: 'rules', engines: ['rules'] }, { ...base, line: 11, engine: 'ai', engines: ['ai'], description: 'longer AI description' }]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].engines.sort(), ['ai', 'rules']);
  assert.equal(out[0].confidence, 'high');
});

test('score and grade', () => {
  assert.deepEqual(scoreOf([]), { score: 100, grade: 'A' });
  assert.ok(scoreOf([{ severity: 'critical', confidence: 'high' }]).score <= 59);
});

test('extractJson handles fences and trailing text with braces', () => {
  assert.deepEqual(extractJson('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(extractJson('Here: {"a":"}"} and {"b":2}'), { a: '}' });
});

test('chunker covers whole small projects and prioritises security-relevant files', () => {
  const files = [file('README.md', '# hi'), file('src/auth/login.js', 'x\n'.repeat(50)), file('src/util/colors.js', 'y\n'.repeat(50))];
  const { chunks, included } = buildChunks(files, [], 'quick');
  assert.equal(included, 2);
  assert.equal(chunks[0].files[0].path, 'src/auth/login.js');
});

/* ───────────── rule false positives / negatives (deep check) ───────────── */
const fires = (name, content) => ids(runRules([file(`src/${name}`, content)]));

/* [file, code that must NOT trigger ruleId, ruleId] */
const SAFE_IDIOMS = [
  ['a.js', 'console.log(`SELECT * FROM users took ${ms}ms`);', 'sql-template'],
  ['a.ts', 'await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;', 'sql-template'],
  ['a.py', 'print(f"Select an option from {menu}")', 'sql-template'],
  ['a.js', "label.text = 'Select a file from your computer'.toUpperCase();", 'sql-concat'],
  ['a.js', 'const sql = "SELECT * FROM users WHERE email = $1".trim();', 'sql-concat'],
  ['a.js', 'logger.info("SELECT * FROM users WHERE id = " + id);', 'sql-concat'],
  ['a.js', 'el.innerHTML = "";', 'xss-dom'],
  ['a.js', 'el.innerHTML = `<span class="spinner"></span>`;', 'xss-dom'],
  ['a.js', 'res.send(`Hello ${escapeHtml(req.query.name)}`);', 'xss-server'],
  ['a.php', 'echo htmlspecialchars($_GET["q"], ENT_QUOTES);', 'xss-server'],
  ['A.java', 'throw new IllegalStateException(ex.getMessage());', 'stack-trace-leak'],
  ['a.js', 'res.status(400).json({ error: error.message });', 'stack-trace-leak'],
  ['a.js', 'const x = Math.random() * tokens.length;', 'insecure-random'],
  ['a.js', 'const delay = Math.random() * 1000; // session retry backoff', 'insecure-random'],
  ['a.py', 'delay = random.random() * 2  # token bucket jitter', 'insecure-random'],
  ['a.js', 'const client = new Client({ debug: true, url });', 'debug-enabled'],
  ['a.js', 'const total = (a+b)*c / 2;', 'regex-dos'],
  ['a.js', String.raw`const re = /^([\w-]+\.)+[\w-]+$/;`, 'regex-dos'],
  ['A.cs', 'catch (OperationCanceledException) { }', 'empty-catch'],
  ['admin.js', 'router.use(requireAdmin);\nrouter.get("/admin/users", async (req, res) => {});', 'missing-auth-admin'],
  ['a.js', 'router.get("/administrator-docs", (req, res) => res.render("x"));', 'missing-auth-admin'],
  ['A.java', 'f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);', 'cleartext-url'],
  ['a.js', 'const api = "http://api:3000/v1";', 'cleartext-url'],
  ['a.js', 'const m = "http://metadata.google.internal/computeMetadata";', 'cleartext-url'],
  ['a.js', 'console.log(`User ${user.id} reset password`);', 'sensitive-logging'],
  ['a.go', 'log.Printf("token refreshed for %s", user)', 'sensitive-logging'],
  ['a.js', 'res.redirect("/posts/" + req.params.id);', 'open-redirect'],
  ['a.jsx', '<a href={url}\n   target="_blank"\n   rel="noopener noreferrer">x</a>', 'html-target-blank'],
  ['Dockerfile', 'FROM node:22-alpine AS build\nRUN npm ci\nFROM build AS test\nUSER node', 'docker-latest'],
  ['pod.yaml', 'capabilities:\n  drop:\n    - NET_RAW\n    - SYS_ADMIN', 'k8s-privileged'],
  ['a.js', 'window.addEventListener("message", (event) => {\n  if (event.origin !== "https://a.com") return;\n});', 'postmessage-wildcard'],
  ['mail.js', 'nodemailer.createTransport({\n  host: "smtp.x.com",\n  port: 587,\n  secure: false,\n});', 'insecure-cookie'],
  ['a.py', 'cfg = yaml.load(fh, yaml.SafeLoader)', 'py-yaml-load'],
];
for (const [name, code, id] of SAFE_IDIOMS) {
  test(`no false positive: ${id} on ${JSON.stringify(code).slice(0, 60)}`, () => {
    assert.ok(!fires(name, code).has(id));
  });
}

/* [file, vulnerable code, ruleId that must fire] */
const VULN_VARIANTS = [
  ['a.js', `const q = "DELETE FROM sessions WHERE token = '" + token + "'";`, 'sql-concat'],
  ['A.java', `stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");`, 'sql-concat'],
  ['a.js', 'const q = "select * from users where id = " + id;', 'sql-concat'],
  ['a.php', '$q = "SELECT * FROM users WHERE id = " . $id;', 'sql-concat'],
  ['a.ts', 'await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);', 'sql-template'],
  ['a.js', 'res.status(500).json({ error: err.message });', 'stack-trace-leak'],
  ['a.js', 'res.status(500).json({ error: err.stack });', 'stack-trace-leak'],
  ['a.py', 'return jsonify(error=str(e)), 500', 'stack-trace-leak'],
  ['A.java', 'return ResponseEntity.status(500).body(e.getMessage());', 'stack-trace-leak'],
  ['a.js', String.raw`const re = /^(\w+\s?)*$/;`, 'regex-dos'],
  ['a.js', 'const re = new RegExp("^(a+)+$");', 'regex-dos'],
  ['a.js', 'const csrfToken = Math.random().toString(36);', 'insecure-random'],
  ['a.php', '$token = md5(uniqid(rand(), true));', 'insecure-random'],
  ['a.php', "ini_set('display_errors', '1');", 'debug-enabled'],
  ['a.py', 'DEBUG = "True"', 'debug-enabled'],
  ['settings.yaml', 'debug: true', 'debug-enabled'],
  ['a.js', 'const hash = crypto.createHash("md5").update(password).digest("hex");', 'weak-password-hash'],
  ['a.js', 'console.log("token", token);', 'sensitive-logging'],
  ['a.py', 'logging.debug("pw %s", user.password)', 'sensitive-logging'],
  ['a.js', 'res.redirect(`/${req.query.next}`);', 'open-redirect'],
  ['a.jsx', '<a href={url}\n   target="_blank">x</a>', 'html-target-blank'],
  ['pod.yaml', 'capabilities:\n  add:\n    - SYS_ADMIN', 'k8s-privileged'],
  ['app.js', 'app.use(session({ cookie: { secure: false } }));', 'insecure-cookie'],
  ['a.js', 'app.get("/admin", (req, res) => {', 'missing-auth-admin'],
  ['a.js', 'const api = "http://api.payments.com/v1";', 'cleartext-url'],
];
for (const [name, code, id] of VULN_VARIANTS) {
  test(`detects ${id} variant: ${JSON.stringify(code).slice(0, 60)}`, () => {
    assert.ok(fires(name, code).has(id), [...fires(name, code)].join(','));
  });
}

test('rule regexes stay fast on 1500-char adversarial lines (no catastrophic backtracking)', () => {
  const seeds = [' ', '"', "'", '`', 'a', '(', '{', '$', '.', String.fromCharCode(92), '" + ', 'SELECT ', 'SELECT a FROM ', '${', 'f"', '$"', '(a+)', 'http://', 'catch(', 'password'];
  const lines = [];
  for (const a of seeds) for (const b of seeds) lines.push((a + b.repeat(Math.ceil(1500 / b.length))).slice(0, 1500));
  lines.push('f"' + 'SELECT a FROM '.repeat(106));
  for (const r of RULES) {
    for (const re of [r.pattern, r.requires, r.unless].filter(Boolean)) {
      for (const l of lines) {
        const t = performance.now();
        re.test(l);
        const ms = performance.now() - t;
        assert.ok(ms < 50, `${r.id} took ${ms.toFixed(1)}ms on ${JSON.stringify(l.slice(0, 20))}`);
      }
    }
  }
});

/* ───────────── secrets ───────────── */
test('secrets: no false positives on UUIDs, digests, data URIs, SRI hashes and sample values', () => {
  const safe = [
    'const token = "550e8400-e29b-41d4-a716-446655440000";',
    'const secret = "d41d8cd98f00b204e9800998ecf8427e";',
    'const api_key = "AKIAIOSFODNN7EXAMPLE";',
    'const token = "abcdefghijklmnopqrstuvwxyz";',
    'const secret_file = "server.pem"; const token = "yarn.lock";',
    'const img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";',
    '"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXGOVq/1ZbNxdqzTUc2GbgdzsVWpw=="',
  ];
  for (const line of safe) assert.equal(runSecrets([file('src/a.js', line)]).length, 0, line);
  // A bare hex value under a credential name is still reported, but quietly.
  const [hex] = runSecrets([file('src/a.js', 'const api_key = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";')]);
  assert.equal(hex.severity, 'low');
  assert.equal(hex.confidence, 'low');
});

test('secrets: masking never reveals most of a short value', () => {
  const [f] = runSecrets([file('src/a.js', 'const password = "Zq9!xW2@kL";')]);
  assert.ok(f, 'expected a finding');
  assert.ok(!JSON.stringify(f).includes('9!xW2@kL'));
  assert.ok(!JSON.stringify(f).includes('Zq9!'));
});

test('secrets: private key bodies are masked in snippets and every key file is reported', () => {
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7';
  const pem = `-----BEGIN PRIVATE KEY-----\n${body}\n${body}x\n-----END PRIVATE KEY-----`;
  const r = runSecrets([file('certs/a.pem', pem), file('certs/b.pem', pem)]);
  assert.equal(r.filter((f) => f.ruleId === 'secret-private-key').length, 2);
  assert.ok(!JSON.stringify(r).includes(body.slice(0, 24)));
});

/* ───────────── dependency parsers ───────────── */
const depsOf = (path, content) => collectDependencies([{ ...file(path, content), manifest: true }]).deps.map((d) => `${d.ecosystem}:${d.name}@${d.version}${d.dev ? ':dev' : ''}`).sort();

test('deps: yarn berry lockfile (metadata, aliases, workspaces)', () => {
  const lock = '__metadata:\n  version: 6\n  cacheKey: 8\n\n"@babel/core@npm:^7.0.0, @babel/core@npm:^7.12.3":\n  version: 7.20.0\n  resolution: "@babel/core@npm:7.20.0"\n\n"lodash@npm:^4.17.15":\n  version: 4.17.15\n  resolution: "lodash@npm:4.17.15"\n\n"root@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "root@workspace:."\n\n"strip-ansi-cjs@npm:strip-ansi@^6.0.1":\n  version: 6.0.1\n  resolution: "strip-ansi@npm:6.0.1"\n';
  assert.deepEqual(depsOf('yarn.lock', lock), ['npm:@babel/core@7.20.0', 'npm:lodash@4.17.15', 'npm:strip-ansi@6.0.1']);
});

test('deps: yarn v1 lockfile with scoped packages and npm aliases', () => {
  const lock = '# yarn lockfile v1\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.12.13"\n\nlodash@^4.17.15:\n  version "4.17.15"\n\n"string-width-cjs@npm:string-width@^4.2.0":\n  version "4.2.3"\n';
  assert.deepEqual(depsOf('yarn.lock', lock), ['npm:@babel/code-frame@7.12.13', 'npm:lodash@4.17.15', 'npm:string-width@4.2.3']);
});

test('deps: pnpm v5, v6 and v9 package keys (peer suffixes stripped)', () => {
  assert.deepEqual(depsOf('pnpm-lock.yaml', 'lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.15:\n    dev: false\n\n  /@babel/core/7.20.0:\n    dev: true\n\n  /debug/4.3.4_supports-color@8.1.1:\n    dev: false\n'),
    ['npm:@babel/core@7.20.0', 'npm:debug@4.3.4', 'npm:lodash@4.17.15']);
  assert.deepEqual(depsOf('pnpm-lock.yaml', "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.15:\n    resolution: {}\n\n  /@babel/core@7.20.0(supports-color@8.1.1):\n    dev: true\n"),
    ['npm:@babel/core@7.20.0', 'npm:lodash@4.17.15']);
  assert.deepEqual(depsOf('pnpm-lock.yaml', "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.15\n        version: 4.17.15\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {}\n\n  '@babel/core@7.20.0':\n    resolution: {}\n\nsnapshots:\n\n  '@babel/core@7.20.0(supports-color@8.1.1)':\n    dependencies:\n      debug: 4.3.4\n"),
    ['npm:@babel/core@7.20.0', 'npm:lodash@4.17.15']);
});

test('deps: npm lock v1 nested + aliases, v3 skips workspaces and file: deps', () => {
  const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { '@babel/core': { version: '7.1.0', dev: true, dependencies: { debug: { version: '2.6.8' } } }, local: { version: 'file:../local' }, aliased: { version: 'npm:lodash@4.17.10' } } });
  assert.deepEqual(depsOf('package-lock.json', v1), ['npm:@babel/core@7.1.0:dev', 'npm:debug@2.6.8', 'npm:lodash@4.17.10']);
  const v3 = JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'root', version: '1.0.0' }, 'packages/web': { name: 'web', version: '0.1.0' }, 'node_modules/web': { resolved: 'packages/web', link: true }, 'node_modules/a/node_modules/@scope/b': { version: '1.2.3' } } });
  assert.deepEqual(depsOf('package-lock.json', v3), ['npm:@scope/b@1.2.3']);
});

test('deps: Gemfile.lock platform gems, csproj attribute order, gradle configurations, poetry dev, go.mod replace', () => {
  assert.deepEqual(depsOf('Gemfile.lock', 'GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n    rails (6.0.0)\n\nPLATFORMS\n  ruby\n'), ['RubyGems:nokogiri@1.10.0', 'RubyGems:rails@6.0.0']);
  assert.deepEqual(depsOf('App.csproj', '<Project><ItemGroup>\n<PackageReference Version="1.0.0" Include="Reversed" />\n<PackageReference Include="Multi">\n  <Version>2.0.0</Version>\n</PackageReference>\n</ItemGroup></Project>'), ['NuGet:Multi@2.0.0', 'NuGet:Reversed@1.0.0']);
  assert.deepEqual(depsOf('build.gradle', "dependencies {\n  annotationProcessor 'org.projectlombok:lombok:1.18.20'\n  testImplementation group: 'junit', name: 'junit', version: '4.12'\n}"), ['Maven:junit:junit@4.12', 'Maven:org.projectlombok:lombok@1.18.20']);
  assert.deepEqual(depsOf('poetry.lock', '[[package]]\r\nname = "pytest"\r\nversion = "7.0.0"\r\ncategory = "dev"\r\n'), ['PyPI:pytest@7.0.0:dev']);
  assert.deepEqual(depsOf('go.mod', 'module x\n\nrequire github.com/a/b v1.2.3\n\nreplace (\n\tgithub.com/c/d v1.0.0 => github.com/e/f v1.0.1\n)\n\nexclude github.com/g/h v1.0.0\n'), ['Go:github.com/a/b@1.2.3']);
});

test('CVSS: more known vectors; incomplete / invalid vectors give null instead of 0 or NaN', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H'), 9.9);
  assert.equal(cvss3Score('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), 1.6);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'), null);
  assert.equal(cvss3Score('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), null);
  assert.equal(cvss3Score('garbage'), null);
});

/* ───────────── OSV lookup resilience (mocked network) ───────────── */
const lockFile = { ...file('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.15' } } })), manifest: true };
const jsonRes = (status, body) => ({ ok: status >= 200 && status < 300, status, headers: new Headers(), json: async () => body });

test('OSV: failed advisory detail fetches are retried, then reported with defaults instead of dropped', async () => {
  const calls = {};
  const fetchImpl = async (url) => {
    if (url.endsWith('/querybatch')) return jsonRes(200, { results: [{ vulns: [{ id: 'GHSA-ok' }, { id: 'GHSA-flaky' }, { id: 'GHSA-down' }] }] });
    const id = url.split('/').pop();
    calls[id] = (calls[id] || 0) + 1;
    if (id === 'GHSA-ok') return jsonRes(200, { id, summary: 'ok', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] });
    if (id === 'GHSA-flaky' && calls[id] < 2) return jsonRes(429, {});
    if (id === 'GHSA-flaky') return jsonRes(200, { id, summary: 'flaky' });
    throw new TypeError('fetch failed');
  };
  const r = await runDeps([lockFile], { fetchImpl, retryDelay: 1 });
  assert.deepEqual(r.findings.map((f) => f.ruleId).sort(), ['GHSA-down', 'GHSA-flaky', 'GHSA-ok']);
  assert.equal(calls['GHSA-flaky'], 2);
  assert.equal(calls['GHSA-down'], 3); // 1 try + 2 retries
  const down = r.findings.find((f) => f.ruleId === 'GHSA-down');
  assert.equal(down.extra.url, 'https://osv.dev/vulnerability/GHSA-down');
  assert.equal(down.severity, 'medium');
  assert.ok(r.warnings.some((w) => /1 advisory/.test(w)));
});

test('OSV: offline batch lookup yields a warning, not an exception', async () => {
  const r = await runDeps([lockFile], { fetchImpl: async () => { throw new TypeError('fetch failed'); }, retryDelay: 1 });
  assert.equal(r.findings.length, 0);
  assert.match(r.warnings[0], /unavailable/);
});

test('fetchRetry does not retry 404 and honours abort', async () => {
  let n = 0;
  const r = await fetchRetry('x', {}, { fetchImpl: async () => { n++; return jsonRes(404, {}); }, baseDelay: 1 });
  assert.equal(r.status, 404);
  assert.equal(n, 1);
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(fetchRetry('x', { signal: ac.signal }, { fetchImpl: async () => { throw Object.assign(new Error('a'), { name: 'AbortError' }); }, baseDelay: 1 }), { name: 'AbortError' });
});

/* ───────────── AI providers / agents ───────────── */
test('extractJson skips brace-y prose before the real object and rejects non-JSON', () => {
  assert.deepEqual(extractJson('Using {placeholders} here. Result: {"summary":"s","vulnerabilities":[]}'), { summary: 's', vulnerabilities: [] });
  assert.throws(() => extractJson('no json at all'), (e) => e instanceof AiError && e.retryable);
});

test('max_tokens responses keep the complete findings; refusals are declined; empty is retryable', () => {
  const cut = '{"summary":"x","vulnerabilities":[{"title":"a","line":1},{"title":"b","line":2},{"title":"c","li';
  assert.deepEqual(salvageTruncated(cut).vulnerabilities.map((v) => v.title), ['a', 'b']);
  const r = parseClaudeResponse({ stop_reason: 'max_tokens', content: [{ type: 'text', text: cut }], usage: { input_tokens: 5, output_tokens: 7 } });
  assert.equal(r.truncated, true);
  assert.equal(r.json.vulnerabilities.length, 2);
  assert.throws(() => parseClaudeResponse({ stop_reason: 'refusal', content: [] }), (e) => e.declined === true);
  assert.throws(() => parseClaudeResponse({ stop_reason: 'end_turn', content: [] }), (e) => e.retryable === true && !e.fatal);
  assert.throws(() => parseGeminiResponse({ candidates: [{ finishReason: 'RECITATION', content: { parts: [] } }] }), (e) => e.declined === true);
  assert.equal(parseGeminiResponse({ candidates: [{ finishReason: 'MAX_TOKENS', content: { parts: [{ text: cut }] } }] }).json.vulnerabilities.length, 2);
});

test('Anthropic / Gemini errors map to clean messages and the right retry/fatal class', () => {
  const body = { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } };
  const auth = classifyAnthropicError(new Anthropic.AuthenticationError(401, body, `401 ${JSON.stringify(body)}`, new Headers()), 'm');
  assert.ok(auth.fatal && !/\{/.test(auth.message));
  const overloaded = classifyAnthropicError(new Anthropic.InternalServerError(529, { type: 'error', error: { type: 'overloaded_error' } }, '529', new Headers()));
  assert.ok(overloaded.retryable && !overloaded.fatal);
  const tooLong = classifyAnthropicError(new Anthropic.BadRequestError(400, { error: { message: 'prompt is too long' } }, '400', new Headers()));
  assert.ok(!tooLong.fatal);
  assert.ok(geminiHttpError(400, JSON.stringify({ error: { message: 'API key not valid. Please pass a valid API key.' } })).fatal);
  assert.ok(geminiHttpError(503, '').retryable);
});

test('testKey reports a clean message for invalid keys (no raw JSON)', async () => {
  const body = { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' }, request_id: 'req_1' };
  const anthropicClient = { models: { retrieve: async () => { throw new Anthropic.AuthenticationError(401, body, `401 ${JSON.stringify(body)}`, new Headers()); } } };
  await assert.rejects(testKey('anthropic', 'k', null, { anthropicClient }), { message: 'The API key is invalid.' });
  await assert.rejects(testKey('gemini', 'k', null, { fetchImpl: async () => jsonRes(400, {}) }), { message: 'The API key is invalid.' });
  await assert.rejects(testKey('github', 'k', null, { fetchImpl: async () => jsonRes(401, {}) }), { message: 'The token is invalid.' });
  await assert.rejects(testKey('github', 'k', null, { fetchImpl: async () => { throw new TypeError('fetch failed'); } }), /Could not reach GitHub/);
  assert.equal(await testKey('gemini', 'k', null, { fetchImpl: async () => jsonRes(200, {}) }), true);
});

test('runAgents: one declined/malformed chunk does not abort the scan; usage never becomes NaN', async () => {
  const chunks = [{ files: [{ path: 'a.js', content: 'x' }] }];
  let n = 0;
  const callImpl = async () => {
    n++;
    if (n === 1) return { json: { summary: '', vulnerabilities: [{ title: 't', file: 'a.js', line: 1 }, null] }, usage: { input_tokens: 10, output_tokens: undefined, cache_read_input_tokens: null } };
    if (n === 2) throw Object.assign(new AiError('Claude declined to analyse this chunk.', { declined: true }), { usage: { input_tokens: 3, output_tokens: 1 } });
    if (n === 3) throw new AiError('Model returned malformed JSON', { retryable: true });
    return { json: { vulnerabilities: 'oops' }, usage: { promptTokenCount: 20, cachedContentTokenCount: 5, candidatesTokenCount: 'x' } };
  };
  const r = await runAgents({ chunks, provider: 'anthropic', apiKey: 'k', model: 'm', callImpl, retryBaseMs: 1 });
  assert.equal(r.findings.length, 1);
  for (const v of Object.values(r.usage)) assert.ok(Number.isFinite(v));
  assert.ok(r.usage.input >= 13);
  assert.ok(r.warnings.some((w) => /declined/.test(w)));
});

test('runAgents: a fatal configuration error stops the AI stage', async () => {
  const chunks = [{ files: [{ path: 'a.js', content: 'x' }] }];
  const callImpl = async () => { throw new AiError('The Anthropic API key is invalid.', { fatal: true }); };
  await assert.rejects(runAgents({ chunks, provider: 'anthropic', apiKey: 'k', model: 'm', callImpl, retryBaseMs: 1 }), /invalid/);
});
