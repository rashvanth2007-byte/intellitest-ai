/**
 * Fix-suggestion library for the "How to fix" panel on each finding.
 * getFix(finding) -> { steps: string[], example?: { lang, code }, commands?: string[] }
 * Chosen by CWE (and rule id for a few special cases), with code examples in the file's language.
 */

const LANG_BY_EXT = {
  js: 'js', mjs: 'js', cjs: 'js', jsx: 'js', ts: 'js', tsx: 'js', vue: 'js', svelte: 'js',
  py: 'py', php: 'php', java: 'java', kt: 'java', scala: 'java', go: 'go', rb: 'rb', cs: 'cs',
  c: 'c', h: 'c', cc: 'c', cpp: 'c', hpp: 'c', html: 'html', htm: 'html', ejs: 'html', hbs: 'html', jinja: 'html', j2: 'html',
  yml: 'yaml', yaml: 'yaml', tf: 'tf', sh: 'sh', bash: 'sh',
};
const LANG_NAME = { js: 'JavaScript / TypeScript', py: 'Python', php: 'PHP', java: 'Java', go: 'Go', rb: 'Ruby', cs: 'C#', c: 'C / C++', html: 'HTML / templates', yaml: 'YAML', tf: 'Terraform', sh: 'Shell', docker: 'Dockerfile' };

export function langOfFile(file) {
  const base = String(file || '').split('/').pop().toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.')) return 'docker';
  return LANG_BY_EXT[base.split('.').pop()] || null;
}
export const langName = (l) => LANG_NAME[l] || l;

const FIXES = {
  sqli: {
    cwes: ['CWE-89'],
    steps: [
      'Never build SQL by concatenating or interpolating variables into the query text.',
      'Use parameterized queries / prepared statements: put placeholders (?, $1, %s, :name) in the SQL and pass values separately.',
      'If table or column names must be dynamic, pick them from a fixed allow-list — placeholders only work for values.',
      'Run the database user with the minimum privileges it needs.',
    ],
    examples: {
      js: `// Parameterized query (mysql2 / pg / better-sqlite3)
const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
// pg:  await pool.query('SELECT * FROM users WHERE id = $1', [id]);`,
      py: `cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# Django ORM: User.objects.filter(id=user_id)`,
      php: `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_GET['id']]);
$user = $stmt->fetch();`,
      java: `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, Integer.parseInt(id));
ResultSet rs = ps.executeQuery();`,
      go: `row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)`,
      cs: `var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
cmd.Parameters.AddWithValue("@id", id);`,
      rb: `User.where("email = ?", params[:email])
# or: User.where(email: params[:email])`,
    },
  },
  nosqli: {
    cwes: ['CWE-943'],
    steps: [
      'Do not pass request objects straight into query filters — build the filter from individual, type-checked fields.',
      'Cast values to the expected type (String(...), Number(...)) so objects like {"$ne": null} are rejected.',
      'Never use $where / mapReduce / $function with user input.',
      'Add schema validation (zod, joi, mongoose schemas) and express-mongo-sanitize.',
    ],
    examples: {
      js: `const email = String(req.body.email);
const user = await User.findOne({ email });          // not findOne(req.body)
// instead of { $where: \`this.userId == \${id}\` }:
const items = await col.find({ userId: parseInt(id, 10) }).toArray();`,
    },
  },
  cmdi: {
    cwes: ['CWE-78'],
    steps: [
      'Avoid running a shell. Call the program directly with an argument array.',
      'Validate inputs against an allow-list (e.g. hostnames: /^[a-z0-9.-]+$/i).',
      'Never pass user input to exec(), system(), os.system(), shell=True or "sh -c".',
      'Prefer a library API over shelling out (e.g. use a DNS/ping library instead of calling ping).',
    ],
    examples: {
      js: `import { execFile } from 'node:child_process';
if (!/^[a-z0-9.-]+$/i.test(host)) throw new Error('invalid host');
execFile('ping', ['-c', '1', host], (err, stdout) => { /* ... */ });`,
      py: `import subprocess, re
if not re.fullmatch(r"[a-zA-Z0-9.-]+", host): raise ValueError("invalid host")
subprocess.run(["ping", "-c", "1", host], check=True, shell=False)`,
      php: `$host = $_GET['host'];
if (!preg_match('/^[a-z0-9.-]+$/i', $host)) exit('invalid host');
$out = shell_exec('ping -c 1 ' . escapeshellarg($host));`,
      java: `new ProcessBuilder("ping", "-c", "1", host).start();  // no shell, fixed executable`,
      go: `cmd := exec.Command("ping", "-c", "1", host) // not exec.Command("sh", "-c", ...)`,
      c: `char *argv[] = {"ping", "-c", "1", host, NULL};
execvp("ping", argv);   /* instead of system() */`,
    },
  },
  codeinj: {
    cwes: ['CWE-95', 'CWE-98', 'CWE-1336'],
    steps: [
      'Remove eval(), new Function(), exec() and similar APIs on any data that can come from a user.',
      'To read data, use a parser (JSON.parse, ast.literal_eval, Number()).',
      'To choose behaviour dynamically, use a lookup table of allowed functions/templates.',
      'Render templates only from files, passing user data as variables.',
    ],
    examples: {
      js: `const preTax = Number(req.body.preTax);       // instead of eval(req.body.preTax)
if (!Number.isFinite(preTax)) return res.status(400).send('Invalid number');
const handlers = { add, remove };               // instead of eval(name + '()')
handlers[action]?.();`,
      py: `import ast, json
value = ast.literal_eval(user_input)   # literals only, no code
data = json.loads(body)
return render_template("page.html", name=name)   # not render_template_string(user_text)`,
      php: `$page = $_GET['page'];
$allowed = ['home' => 'home.php', 'about' => 'about.php'];
include $allowed[$page] ?? 'home.php';   // never include $_GET[...] directly`,
    },
  },
  xss: {
    cwes: ['CWE-79'],
    steps: [
      'Treat all user data as text, never as HTML.',
      'In the browser use textContent / framework bindings instead of innerHTML, document.write or dangerouslySetInnerHTML.',
      'If you must render user HTML, sanitize it with DOMPurify (browser) or a server-side sanitizer.',
      'Keep template auto-escaping on; avoid |safe, {{{ }}}, <%- %>, raw() and html_safe on user data.',
      'Add a Content-Security-Policy header as a second line of defence.',
    ],
    examples: {
      js: `el.textContent = userComment;                       // safe
// when HTML is really needed:
el.innerHTML = DOMPurify.sanitize(userHtml);
// React: <div>{comment}</div> instead of dangerouslySetInnerHTML`,
      html: `<!-- Jinja / Django / Twig: keep auto-escaping -->
<p>{{ comment }}</p>          <!-- not {{ comment|safe }} -->
<!-- EJS: <%= comment %> (escaped), not <%- comment %> -->`,
      php: `echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');`,
      py: `from markupsafe import escape
return f"<p>Hello {escape(name)}</p>"   # or render a template with autoescape on`,
    },
  },
  traversal: {
    cwes: ['CWE-22'],
    steps: [
      'Do not build file paths from user input. Map IDs to files on the server instead.',
      'If a filename is needed, strip directories (basename / secure_filename) and resolve it inside a fixed base folder.',
      'After resolving, verify the final path still starts with the base folder.',
    ],
    examples: {
      js: `import path from 'node:path';
const base = path.resolve('uploads');
const target = path.resolve(base, path.basename(req.query.file));
if (!target.startsWith(base + path.sep)) return res.status(400).end();
res.sendFile(target);`,
      py: `from werkzeug.utils import secure_filename
base = os.path.realpath("uploads")
target = os.path.realpath(os.path.join(base, secure_filename(name)))
if not target.startswith(base + os.sep): abort(400)
return send_file(target)`,
    },
  },
  ssrf: {
    cwes: ['CWE-918'],
    steps: [
      'Do not let users choose arbitrary URLs for the server to fetch.',
      'Only allow specific hosts (an allow-list) and https.',
      'Resolve the hostname and block private, loopback and link-local ranges (10.x, 127.x, 169.254.x, 192.168.x, ::1).',
      'Disable automatic redirects or re-check every redirect target.',
    ],
    examples: {
      js: `const ALLOWED = new Set(['api.example.com']);
const url = new URL(\`https://api.example.com/quote?symbol=\${encodeURIComponent(req.query.symbol)}\`);
if (!ALLOWED.has(url.hostname)) return res.status(400).end();
const r = await fetch(url, { redirect: 'error' });`,
      py: `from urllib.parse import urlparse
u = urlparse(user_url)
if u.scheme != "https" or u.hostname not in {"api.example.com"}: abort(400)
requests.get(user_url, allow_redirects=False, timeout=5)`,
    },
  },
  redirect: {
    cwes: ['CWE-601'],
    steps: [
      'Only redirect to relative paths inside your own site, or to an allow-list of URLs.',
      'Reject values starting with // or containing a scheme (http:, javascript:).',
    ],
    examples: {
      js: `const next = String(req.query.next || '/');
const safe = next.startsWith('/') && !next.startsWith('//') ? next : '/';
res.redirect(safe);`,
      py: `from django.utils.http import url_has_allowed_host_and_scheme
target = request.GET.get("next", "/")
if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}): target = "/"
return redirect(target)`,
    },
  },
  deser: {
    cwes: ['CWE-502'],
    steps: [
      'Never deserialize untrusted bytes with native serializers (pickle, Java ObjectInputStream, BinaryFormatter, PHP unserialize, Marshal).',
      'Exchange data as JSON and validate it against a schema.',
      'For YAML use the safe loader (yaml.safe_load / YAML.safe_load).',
    ],
    examples: {
      py: `data = json.loads(request.data)          # instead of pickle.loads(...)
config = yaml.safe_load(fh)               # instead of yaml.load(fh)`,
      js: `const obj = JSON.parse(body);            // instead of node-serialize unserialize()`,
      java: `MyDto dto = new ObjectMapper().readValue(json, MyDto.class);   // instead of ObjectInputStream`,
      cs: `var dto = JsonSerializer.Deserialize<MyDto>(json);   // instead of BinaryFormatter`,
      php: `$data = json_decode($_POST['data'], true);   // instead of unserialize()`,
      rb: `data = JSON.parse(params[:data])   # instead of Marshal.load / YAML.load`,
    },
  },
  xxe: {
    cwes: ['CWE-611'],
    steps: ['Disable DOCTYPE declarations and external entity resolution in the XML parser.', 'In Python use the defusedxml package.'],
    examples: {
      java: `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");`,
      py: `import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_bytes)`,
      cs: `var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };`,
    },
  },
  weakhash: {
    cwes: ['CWE-328', 'CWE-916'],
    steps: [
      'For passwords use a slow, salted algorithm: bcrypt (cost ≥ 12), scrypt or Argon2id.',
      'For integrity checks use SHA-256 or stronger.',
      'Re-hash existing passwords on the user\'s next successful login.',
    ],
    examples: {
      js: `import bcrypt from 'bcryptjs';
const hash = await bcrypt.hash(password, 12);
const ok = await bcrypt.compare(password, hash);
// integrity: crypto.createHash('sha256').update(data).digest('hex')`,
      py: `from argon2 import PasswordHasher
ph = PasswordHasher()
h = ph.hash(password); ph.verify(h, password)
# integrity: hashlib.sha256(data).hexdigest()`,
      php: `$hash = password_hash($password, PASSWORD_DEFAULT);
if (password_verify($password, $hash)) { /* ok */ }`,
      java: `String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
MessageDigest.getInstance("SHA-256");   // for integrity, not passwords`,
    },
  },
  weakcipher: {
    cwes: ['CWE-327', 'CWE-329'],
    steps: ['Use AES-256-GCM (or ChaCha20-Poly1305) with a new random nonce for every message.', 'Never use DES, 3DES, RC4, Blowfish or ECB mode.', 'Keep keys out of source code.'],
    examples: {
      js: `const iv = crypto.randomBytes(12);
const c = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
const tag = c.getAuthTag();   // store iv + tag + ct`,
      java: `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));`,
      py: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, data, None)`,
    },
  },
  random: {
    cwes: ['CWE-338'],
    steps: ['Use the cryptographically secure generator for tokens, passwords, OTPs and IDs.'],
    examples: {
      js: `const token = crypto.randomBytes(32).toString('hex');   // or crypto.randomUUID()`,
      py: `import secrets
token = secrets.token_urlsafe(32)`,
      java: `SecureRandom rnd = new SecureRandom(); byte[] b = new byte[32]; rnd.nextBytes(b);`,
      php: `$token = bin2hex(random_bytes(32));`,
      go: `b := make([]byte, 32); _, _ = crypto_rand.Read(b)   // import crypto_rand "crypto/rand"`,
    },
  },
  tls: {
    cwes: ['CWE-295'],
    steps: ['Turn certificate verification back on.', 'For internal/self-signed services, trust your own CA bundle instead of disabling checks.'],
    examples: {
      js: `const agent = new https.Agent({ ca: fs.readFileSync('internal-ca.pem') });   // keep rejectUnauthorized: true`,
      py: `requests.get(url, verify="/path/to/internal-ca.pem")   # never verify=False`,
      go: `tlsConfig := &tls.Config{RootCAs: pool}   // remove InsecureSkipVerify: true`,
    },
  },
  jwt: {
    cwes: ['CWE-347'],
    steps: ['Always verify the signature with an explicit algorithm allow-list.', 'Never accept alg "none" or decode without verifying.', 'Keep expiry checks on.'],
    examples: {
      js: `const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });`,
      py: `payload = jwt.decode(token, SECRET, algorithms=["HS256"])   # verification is on by default`,
    },
  },
  secret: {
    cwes: ['CWE-798', 'CWE-321', 'CWE-538'],
    steps: [
      'Treat the exposed value as compromised: revoke / rotate it at the provider right now.',
      'Remove it from the code and from git history (git filter-repo or BFG), then force-push.',
      'Load secrets from environment variables or a secret manager; commit only a .env.example with empty values.',
      'Add .env and key files to .gitignore and enable secret scanning / pre-commit hooks (gitleaks).',
    ],
    examples: {
      js: `// .env (not committed):  API_KEY=...
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error('API_KEY is not set');`,
      py: `import os
API_KEY = os.environ["API_KEY"]
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`,
      php: `$apiKey = getenv('API_KEY');`,
      java: `String apiKey = System.getenv("API_KEY");`,
      docker: `# pass at runtime instead of ENV in the image
docker run -e API_KEY="$API_KEY" myimage
# or BuildKit:  RUN --mount=type=secret,id=api_key ...`,
    },
  },
  debug: {
    cwes: ['CWE-489'],
    steps: ['Turn debug mode off in production.', 'Drive it from an environment variable that defaults to off.'],
    examples: {
      py: `app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
# Django: DEBUG = os.environ.get("DJANGO_DEBUG") == "1"`,
      js: `const debug = process.env.NODE_ENV !== 'production';`,
      php: `ini_set('display_errors', '0');   // APP_DEBUG=false in production .env`,
    },
  },
  cookie: {
    cwes: ['CWE-614'],
    steps: ['Set HttpOnly, Secure and SameSite on session cookies.'],
    examples: {
      js: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });`,
      py: `SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"`,
    },
  },
  cors: {
    cwes: ['CWE-942'],
    steps: ['List the exact origins that may call the API.', 'Never combine a wildcard or reflected origin with credentials.'],
    examples: {
      js: `app.use(cors({ origin: ['https://app.example.com'], credentials: true }));`,
      py: `CORS_ALLOWED_ORIGINS = ["https://app.example.com"]   # django-cors-headers`,
      java: `@CrossOrigin(origins = "https://app.example.com")`,
    },
  },
  csrf: {
    cwes: ['CWE-352'],
    steps: ['Re-enable CSRF protection for cookie-authenticated, state-changing requests.', 'Also set SameSite=Lax/Strict on session cookies.'],
    examples: {
      java: `http.csrf(Customizer.withDefaults());   // instead of csrf().disable()`,
      py: `# remove @csrf_exempt and send the token: {% csrf_token %} in forms`,
      rb: `protect_from_forgery with: :exception`,
    },
  },
  exposure: {
    cwes: ['CWE-209', 'CWE-532', 'CWE-200', 'CWE-922'],
    steps: [
      'Log full errors on the server only; send users a generic message with a request/correlation ID.',
      'Redact passwords, tokens and personal data before logging.',
      'Keep session tokens in HttpOnly cookies rather than localStorage.',
    ],
    examples: {
      js: `app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  logger.error({ id, err });                         // details stay in the server log
  res.status(500).json({ error: 'Internal error', id });
});`,
      py: `logger.exception("payment failed id=%s", request_id)
return jsonify(error="Internal error", id=request_id), 500`,
    },
  },
  massassign: {
    cwes: ['CWE-915'],
    steps: ['Copy only the fields a user is allowed to set (allow-list), or validate with a strict schema.'],
    examples: {
      js: `const { name, email } = req.body;               // not User.create(req.body)
await User.create({ name, email });`,
      rb: `params.require(:user).permit(:name, :email)`,
      py: `class UserSerializer(serializers.ModelSerializer):
    class Meta: model = User; fields = ["name", "email"]`,
    },
  },
  authz: {
    cwes: ['CWE-306', 'CWE-284'],
    steps: ['Require authentication and an authorization (role/ownership) check on every privileged route.', 'Deny by default; add checks as middleware so they cannot be forgotten.'],
    examples: {
      js: `router.post('/admin/users', requireAuth, requireRole('admin'), createUser);`,
      tf: `ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]   # not 0.0.0.0/0
}`,
    },
  },
  proto: {
    cwes: ['CWE-1321'],
    steps: ['Reject the keys __proto__, constructor and prototype.', 'Use Map or Object.create(null) for user-keyed data, and validate input with a schema.'],
    examples: {
      js: `const BAD = new Set(['__proto__', 'constructor', 'prototype']);
if (BAD.has(key)) throw new Error('invalid key');
const store = new Map(); store.set(key, value);`,
    },
  },
  memory: {
    cwes: ['CWE-120', 'CWE-134'],
    steps: ['Use bounded functions that take the destination size.', 'Always pass a literal format string to printf-family functions.'],
    examples: {
      c: `snprintf(buf, sizeof buf, "%s", input);      /* instead of strcpy/sprintf */
fgets(line, sizeof line, stdin);             /* instead of gets */
printf("%s", user_text);                     /* instead of printf(user_text) */`,
    },
  },
  container: {
    cwes: ['CWE-250', 'CWE-732'],
    steps: ['Run processes as an unprivileged user.', 'Drop privileges/capabilities and avoid world-writable permissions.'],
    examples: {
      docker: `FROM node:22-alpine
WORKDIR /app
COPY --chown=node:node . .
USER node
CMD ["node", "server.js"]`,
      yaml: `securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  privileged: false
  capabilities: { drop: ["ALL"] }`,
      sh: `chmod 750 /srv/app && chmod 640 /srv/app/config.yml   # not 777`,
    },
  },
  supply: {
    cwes: ['CWE-494', 'CWE-1104', 'CWE-1357', 'CWE-353', 'CWE-829'],
    steps: [
      'Pin versions (lockfiles, image digests) and verify downloads with checksums or signatures.',
      'Commit your lockfile and install with npm ci / pip install --require-hashes.',
      'Add Subresource Integrity to third-party scripts.',
    ],
    examples: {
      html: `<script src="https://cdn.example.com/lib.min.js"
        integrity="sha384-..." crossorigin="anonymous"></script>`,
      sh: `curl -fsSLo install.sh https://example.com/install.sh
echo "<sha256>  install.sh" | sha256sum -c - && bash install.sh`,
      docker: `FROM node:22.11-alpine@sha256:<digest>`,
      yaml: `# GitHub Actions: pass untrusted values through env, not inline \${{ }}
env:
  TITLE: \${{ github.event.pull_request.title }}
run: echo "$TITLE"`,
    },
  },
  redos: {
    cwes: ['CWE-1333'],
    steps: ['Remove nested quantifiers like (a+)+ or (.*)*.', 'Limit input length before matching, or use a linear-time engine (RE2).'],
    examples: { js: `const re = /^[0-9]+#$/;            // instead of /([0-9]+)+#/
if (input.length > 100) throw new Error('too long');` },
  },
  errors: {
    cwes: ['CWE-390', 'CWE-396', 'CWE-617'],
    steps: ['Handle or log errors instead of swallowing them.', 'Use explicit checks (not assert) for security decisions.'],
    examples: {
      js: `try { await save(); } catch (err) { logger.error({ err }, 'save failed'); throw err; }`,
      py: `if not user.is_admin:
    raise PermissionDenied()      # not: assert user.is_admin`,
    },
  },
  compare: {
    cwes: ['CWE-697'],
    steps: ['Compare secrets with a constant-time function and strict types.'],
    examples: {
      js: `const ok = a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));`,
      php: `if (hash_equals($expected, $provided)) { /* ok */ }   // not ==`,
    },
  },
  transport: {
    cwes: ['CWE-319', 'CWE-1022', 'CWE-1327'],
    steps: ['Use https:// for every external URL and resource.', 'Add rel="noopener noreferrer" to target="_blank" links.', 'Bind development servers to 127.0.0.1.'],
    examples: {
      html: `<a href="https://example.com" target="_blank" rel="noopener noreferrer">Docs</a>
<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>`,
      js: `const API = 'https://api.example.com';`,
    },
  },
};

const BY_CWE = new Map();
for (const [k, v] of Object.entries(FIXES)) for (const c of v.cwes) BY_CWE.set(c, k);

const CATEGORY_HINTS = [
  [/sql/i, 'sqli'], [/nosql/i, 'nosqli'], [/command/i, 'cmdi'], [/code injection|template injection|file inclusion/i, 'codeinj'],
  [/xss|cross-site scripting/i, 'xss'], [/traversal/i, 'traversal'], [/ssrf|request forgery/i, 'ssrf'], [/redirect/i, 'redirect'],
  [/deserial/i, 'deser'], [/xml|xxe/i, 'xxe'], [/secret|credential|key/i, 'secret'], [/crypt|hash/i, 'weakhash'],
  [/random/i, 'random'], [/certificate|tls|ssl/i, 'tls'], [/cors/i, 'cors'], [/csrf/i, 'csrf'], [/auth|access control/i, 'authz'],
  [/exposure|disclosure|logging|leak/i, 'exposure'], [/supply|ci\/cd/i, 'supply'], [/container/i, 'container'],
];

const UPGRADE = {
  npm: (p, v) => [`npm install ${p}@${v}`, 'npm audit fix   # then re-run the tests'],
  PyPI: (p, v) => [`pip install "${p}>=${v}"`, `# and pin it in requirements.txt:  ${p}==${v}`],
  Go: (p, v) => [`go get ${p}@v${v.replace(/^v/, '')}`, 'go mod tidy'],
  'crates.io': (p, v) => [`cargo update -p ${p} --precise ${v}`],
  Packagist: (p, v) => [`composer require ${p}:^${v}`],
  RubyGems: (p, v) => [`bundle update ${p}   # Gemfile: gem "${p}", ">= ${v}"`],
  Maven: (p, v) => [`<!-- pom.xml -->  <version>${v}</version>  <!-- for ${p} -->`],
  NuGet: (p, v) => [`dotnet add package ${p} --version ${v}`],
};

/** Build the suggestion panel content for a finding. */
export function getFix(f) {
  // Vulnerable dependency: concrete upgrade commands.
  if (f.extra?.package) {
    const { package: pkg, version, ecosystem, fixed = [] } = f.extra;
    const target = fixed[fixed.length - 1] || fixed[0];
    return {
      steps: target
        ? [`Upgrade ${pkg} from ${version} to ${target} or later.`, 'Regenerate the lockfile and commit it.', 'Re-run your tests and this scan to confirm the advisory is gone.']
        : [`No fixed version of ${pkg} is published yet.`, 'Check the advisory for a workaround, replace the package, or restrict the vulnerable feature.', 'Watch the advisory for a patched release.'],
      commands: target && UPGRADE[ecosystem] ? UPGRADE[ecosystem](pkg, target) : [],
    };
  }
  const key = BY_CWE.get(f.cwe) || CATEGORY_HINTS.find(([re]) => re.test(`${f.category} ${f.title}`))?.[1];
  const entry = key ? FIXES[key] : null;
  if (!entry) return { steps: [] };
  const lang = langOfFile(f.file);
  const exLang = entry.examples?.[lang] ? lang : Object.keys(entry.examples || {})[0];
  return {
    steps: entry.steps,
    example: exLang ? { lang: exLang, sameLanguage: exLang === lang, code: entry.examples[exLang] } : null,
  };
}
