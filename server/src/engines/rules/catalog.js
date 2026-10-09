/**
 * Offline static-analysis rules. Each rule is matched line-by-line (pattern) and/or per file (fileCheck).
 *
 *   langs:       languages the rule applies to ('*' = all text files)
 *   pattern:     RegExp tested against each line
 *   requires:    optional RegExp that must also match the same line
 *   unless:      optional RegExp — skip the line if it matches
 *   unlessFile:  optional RegExp — skip the whole file if it matches (e.g. a mitigation is present)
 *   skip:        optional (lines, i) => boolean — context check on neighbouring lines (i is 0-based)
 *   agent:       which IntelliTest agent the finding is attributed to
 */
// SQL verb phrase, case-sensitive (all-caps or all-lowercase keywords) so English prose such as
// "Select a file from your computer" is not mistaken for SQL. `q` is the backreference of the
// opening quote, so the keyword run cannot cross the end of the string literal.
const SQL_VERB_CS = (q) => String.raw`(?:(?:SELECT|select)\s(?:(?!${q})[^\n])*?\s(?:FROM|from)\s|(?:INSERT|insert)\s+(?:INTO|into)\s|(?:UPDATE|update)\s+[\w.\[\]"\x60]+\s+(?:SET|set)\s|(?:DELETE|delete)\s+(?:FROM|from)\s)`;
// Lines that only log / print / translate text that happens to mention SQL.
const LOG_CALL = /^\s*(?:console\.\w+|(?:this\.)?(?:log|logger|logging|_logger|LOG|LOGGER)\.\w+|print|println|puts|System\.(?:out|err)\.print\w*|fmt\.Print\w*|Debug\.Log\w*)\s*\(|\bthrow\s+new\s+\w*(?:Error|Exception)\s*\(|\braise\s+\w+(?:Error|Exception)\s*\(/;
const USER_INPUT_JS = String.raw`req\.(?:query|params|body|headers|cookies)|request\.(?:query|params|body)|ctx\.(?:query|params|request\.body)`;
const SEC_TARGET = /(?:token|secret|password|passw?d|pwd|otp|nonce|salt|session_?id|sid|csrf\w*|api_?key|secret_?key|(?:reset|verification|verify|invite|auth|otp|confirm)_?code|\bpin)["'\]]?\s*(?:[:=]|\+=|=>)(?!=)|(?:function|def|func)\s+\w*(?:token|secret|password|otp|nonce|salt|session|csrf|key)\w*\s*\(/i;

/** Text of lines [i - before, i + after] joined, clamped to the file. */
const around = (lines, i, before, after) => lines.slice(Math.max(0, i - before), i + after + 1).join('\n');

export const RULES = [
  /* ═════════════ Injection (SENTINEL) ═════════════ */
  {
    id: 'sql-concat', agent: 'sentinel', langs: ['*'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SQL query built with string concatenation',
    // A string literal that starts with a SQL verb (and may itself contain the other quote kind, e.g.
    // "... name = '" + name) followed by a concatenation operator: JS/Java/C#/Python/Go `+`, PHP `.`.
    // `.trim()` / `.format(` style method calls are not concatenation.
    pattern: new RegExp(String.raw`(["'\x60])\s*${SQL_VERB_CS('\\1')}(?:(?!\1)[^\\\n]|\\.)*\1\s*(?:\+(?![+=])|\.\s*\$|\.\s+[a-zA-Z_])`),
    unless: new RegExp(String.raw`\?\s*["'\x60]\s*\+\s*["'\x60]|placeholder|LIMIT\s*["']\s*\+\s*\d|${LOG_CALL.source}`, 'i'),
    description: 'A SQL statement is assembled by concatenating variables into the query string. If any part comes from user input an attacker can change the query structure.',
    impact: 'Read, modify or delete arbitrary database data; authentication bypass; in some databases remote code execution.',
    fix: 'Use parameterized queries / prepared statements, e.g. db.query("SELECT * FROM users WHERE id = ?", [id]). Never concatenate input into SQL.',
  },
  {
    id: 'sql-template', agent: 'sentinel', langs: ['js', 'cs', 'java', 'py', 'rb', 'go', 'php', 'other'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SQL query built with string interpolation',
    pattern: new RegExp(String.raw`(?:\x60[^\x60]*${SQL_VERB_CS('\\x60')}[^\x60]*\$\{|\b[fF][rR]?["'][^"']*${SQL_VERB_CS('["\']')}[^"']*\{|\$@?"[^"]*${SQL_VERB_CS('"')}[^"]*\{|"[^"]*${SQL_VERB_CS('"')}[^"]*#\{)`),
    // Tagged templates (sql`...`, Prisma.sql`...`, prisma.$queryRaw`...`) bind ${} values as parameters.
    unless: new RegExp(String.raw`sql\x60|Prisma\.sql|\bsql\s*\(|\$(?:queryRaw|executeRaw)\s*\x60|${LOG_CALL.source}`),
    description: 'Variables are interpolated directly into a SQL string (template literal, f-string, C# $"" or Ruby #{}).',
    impact: 'SQL injection: data theft, data tampering, authentication bypass.',
    fix: 'Pass values as bound parameters instead of interpolating them (e.g. cursor.execute("... WHERE id = %s", (id,)) or a query builder / ORM).',
  },
  {
    id: 'py-sql-format', agent: 'sentinel', langs: ['py'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SQL query formatted with % or .format()',
    pattern: /\.(?:execute|executemany|raw)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(?:%|\.format\s*\()/i,
    description: 'The SQL text is built with Python string formatting before being sent to the database driver.',
    impact: 'SQL injection.',
    fix: 'Use the driver\'s parameter binding: cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,)).',
  },
  {
    id: 'php-sqli', agent: 'sentinel', langs: ['php'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SQL query uses request data directly',
    pattern: /(?:mysql_query|mysqli_query|pg_query|->query|->exec|sqlsrv_query)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/i,
    description: 'Superglobal request data ($_GET, $_POST…) flows straight into a SQL query.',
    impact: 'Full database compromise.',
    fix: 'Use PDO / mysqli prepared statements with bound parameters.',
  },
  {
    id: 'nosql-injection', agent: 'sentinel', langs: ['js'], severity: 'high', cvss: 8.1, cwe: 'CWE-943', owasp: 'A03:2021',
    category: 'NoSQL Injection', title: 'Query object taken directly from request',
    pattern: new RegExp(String.raw`\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|where)\s*\(\s*(?:${USER_INPUT_JS})\b`),
    description: 'A MongoDB-style filter is built from the raw request object. Attackers can send operators such as {"$ne": null} or {"$where": ...}.',
    impact: 'Authentication bypass and unauthorized data access.',
    fix: 'Pick and validate individual fields (e.g. { email: String(req.body.email) }) and use express-mongo-sanitize or schema validation.',
  },
  {
    id: 'nosql-where', agent: 'sentinel', langs: ['js', 'py', 'php'], severity: 'high', cvss: 8.1, cwe: 'CWE-943', owasp: 'A03:2021',
    category: 'NoSQL Injection', title: 'MongoDB $where / mapReduce with dynamic JavaScript',
    pattern: /["']?\$where["']?\s*[:=]>?\s*(?:`[^`]*\$\{|["'][^"']*["']\s*[+.]|[a-zA-Z_$][\w$.]*\s*[,}])/,
    description: '$where executes a JavaScript expression inside the database. Building it from variables lets attackers inject arbitrary JS (e.g. "1; while(true){}" or "0 || 1==1").',
    impact: 'Data exfiltration across users and denial of service of the database.',
    fix: 'Never use $where with input. Replace with standard query operators, e.g. { userId: parseInt(id, 10) }.',
  },
  {
    id: 'js-cmd-injection', agent: 'sentinel', langs: ['js'], severity: 'critical', cvss: 9.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'Shell command built from variables',
    pattern: /(?:(?<![.\w$])|\b(?:child_process|cp|childProcess|shell)\.)(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[a-zA-Z_$][\w$.]*\s*[,)])/,
    unless: /\b(?:regex|re|pattern|rx)\.exec\(|\/\.exec\(|RegExp/,
    description: 'child_process.exec runs its argument through a shell. Concatenated or interpolated values can inject extra commands (; && | `…`).',
    impact: 'Remote code execution on the server.',
    fix: 'Use execFile/spawn with an argument array and no shell, and validate inputs against an allow-list.',
  },
  {
    id: 'js-spawn-shell', agent: 'sentinel', langs: ['js'], severity: 'high', cvss: 8.1, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'Process spawned with shell: true',
    pattern: /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^)]*shell\s*:\s*true/,
    description: 'With shell: true the command line is interpreted by a shell, re-enabling injection through arguments.',
    impact: 'Command injection if any argument is attacker controlled.',
    fix: 'Remove shell: true and pass arguments as an array.',
  },
  {
    id: 'py-cmd-injection', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 8.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'Shell command execution',
    pattern: /\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bcommands\.getoutput\(/,
    description: 'os.system / os.popen / subprocess with shell=True execute through a shell.',
    impact: 'Remote code execution if the command contains user input.',
    fix: 'Use subprocess.run([...args], shell=False) with an argument list; validate inputs; use shlex.quote only as a last resort.',
  },
  {
    id: 'php-cmd-injection', agent: 'sentinel', langs: ['php'], severity: 'critical', cvss: 9.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'Shell command uses request data',
    pattern: /\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i,
    description: 'Request parameters are passed to a shell execution function.',
    impact: 'Remote code execution.',
    fix: 'Avoid shell calls; if unavoidable use escapeshellarg() on each argument and an allow-list of values.',
  },
  {
    id: 'java-runtime-exec', agent: 'sentinel', langs: ['java'], severity: 'high', cvss: 8.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'Runtime.exec with dynamic command',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:[a-zA-Z_]\w*\s*\)|"[^"]*"\s*\+)/,
    description: 'A command string built at runtime is executed; with a single string, Java tokenises it and may pass it to a shell wrapper.',
    impact: 'Command injection / remote code execution.',
    fix: 'Use ProcessBuilder with a fixed executable and a validated argument list.',
  },
  {
    id: 'go-cmd-shell', agent: 'sentinel', langs: ['go'], severity: 'high', cvss: 8.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'exec.Command invokes a shell with -c',
    pattern: /exec\.Command(?:Context)?\s*\([^)]*"(?:sh|bash|\/bin\/sh|\/bin\/bash|cmd|cmd\.exe|powershell)"\s*,\s*"(?:-c|\/c|-Command)"/i,
    description: 'Running a shell with -c and a dynamic string allows injection of extra commands.',
    impact: 'Command injection.',
    fix: 'Call the target binary directly: exec.Command("git", "clone", url).',
  },
  {
    id: 'go-sqli', agent: 'sentinel', langs: ['go'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SQL built with fmt.Sprintf',
    pattern: /\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\([^)]*fmt\.Sprintf\(/,
    description: 'fmt.Sprintf is used to assemble a SQL statement passed to database/sql.',
    impact: 'SQL injection.',
    fix: 'Use placeholders: db.Query("SELECT * FROM users WHERE id = $1", id).',
  },
  {
    id: 'cs-sqli', agent: 'sentinel', langs: ['cs'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'SqlCommand with concatenated SQL',
    pattern: /new\s+(?:Sql|OleDb|Odbc|MySql|Npgsql)Command\s*\([^)]*(?:"\s*\+|\+\s*"|\$")|\.(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*(?:\$"|"[^"]*"\s*\+)/,
    description: 'ADO.NET / EF raw SQL is built with string concatenation or interpolation.',
    impact: 'SQL injection.',
    fix: 'Use SqlParameter objects or FromSqlInterpolated / ExecuteSqlInterpolated.',
  },
  {
    id: 'rb-sqli', agent: 'sentinel', langs: ['rb'], severity: 'critical', cvss: 9.8, cwe: 'CWE-89', owasp: 'A03:2021',
    category: 'SQL Injection', title: 'ActiveRecord query with string interpolation',
    pattern: /\.(?:where|find_by_sql|order|joins|select|having|group|pluck|exists\?)\s*\(\s*["'][^"']*#\{/,
    description: 'Interpolating values into ActiveRecord SQL fragments bypasses escaping.',
    impact: 'SQL injection.',
    fix: 'Use hash conditions or placeholders: User.where("email = ?", email).',
  },
  {
    id: 'code-eval-js', agent: 'sentinel', langs: ['js'], severity: 'high', cvss: 8.1, cwe: 'CWE-95', owasp: 'A03:2021',
    category: 'Code Injection', title: 'Dynamic code evaluation (eval / new Function)',
    pattern: /(?<![.\w$])eval\s*\(|new\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["'`]|vm\.runIn(?:New|This)?Context\s*\(|vm\.compileFunction\s*\(/,
    description: 'Strings are executed as JavaScript. If any part is influenced by users this is arbitrary code execution (server) or XSS (browser).',
    impact: 'Remote code execution / cross-site scripting.',
    fix: 'Remove eval-style APIs; use JSON.parse for data and explicit dispatch tables for behaviour.',
  },
  {
    id: 'code-eval-py', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 8.1, cwe: 'CWE-95', owasp: 'A03:2021',
    category: 'Code Injection', title: 'Dynamic code evaluation (eval / exec)',
    pattern: /(?<![.\w])(?:eval|exec)\s*\((?!\s*\))/,
    unless: /literal_eval|\.exec\(|re\.|cursor/,
    description: 'eval()/exec() run arbitrary Python code.',
    impact: 'Remote code execution if input reaches the call.',
    fix: 'Use ast.literal_eval for literals, json.loads for data, or explicit mappings.',
  },
  {
    id: 'php-code-injection', agent: 'sentinel', langs: ['php'], severity: 'critical', cvss: 9.8, cwe: 'CWE-95', owasp: 'A03:2021',
    category: 'Code Injection', title: 'eval/assert/create_function or /e regex',
    pattern: /\b(?:eval|assert|create_function)\s*\(\s*[^)]*\$|preg_replace\s*\(\s*["'](.).*\1[a-z]*e[a-z]*["']/i,
    description: 'PHP code is evaluated from a dynamic string.',
    impact: 'Remote code execution.',
    fix: 'Remove eval/assert on strings; use preg_replace_callback instead of the /e modifier.',
  },
  {
    id: 'rb-code-injection', agent: 'sentinel', langs: ['rb'], severity: 'critical', cvss: 9.8, cwe: 'CWE-95', owasp: 'A03:2021',
    category: 'Code Injection', title: 'eval / send / constantize on params',
    pattern: /\b(?:eval|instance_eval|class_eval|send|public_send|constantize|system|exec|spawn)\s*\(?\s*[^)\n]*params\[/,
    description: 'Request parameters are used for dynamic code execution, dynamic method dispatch or shell commands.',
    impact: 'Remote code execution.',
    fix: 'Map params onto an allow-list of permitted methods/classes; never eval user input.',
  },
  {
    id: 'php-file-inclusion', agent: 'sentinel', langs: ['php'], severity: 'critical', cvss: 9.8, cwe: 'CWE-98', owasp: 'A03:2021',
    category: 'File Inclusion', title: 'include/require with request data',
    pattern: /\b(?:include|require)(?:_once)?\s*\(?\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i,
    description: 'A file path from the request is passed to include/require (LFI/RFI).',
    impact: 'Source disclosure, local file read and remote code execution.',
    fix: 'Map request values to a fixed allow-list of templates.',
  },
  {
    id: 'path-traversal-js', agent: 'sentinel', langs: ['js'], severity: 'high', cvss: 7.5, cwe: 'CWE-22', owasp: 'A01:2021',
    category: 'Path Traversal', title: 'File system access with request-controlled path',
    pattern: new RegExp(String.raw`(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|unlinkSync|readdir|sendFile|download|rm|rmSync|path\.join|path\.resolve)\s*\([^)]*(?:${USER_INPUT_JS})`),
    description: 'A path built from request data reaches a file system API. Sequences like ../../etc/passwd escape the intended directory.',
    impact: 'Arbitrary file read / overwrite / deletion.',
    fix: 'Resolve the path and verify it stays inside a base directory (path.resolve(base, p).startsWith(base + path.sep)); prefer IDs mapped to files.',
  },
  {
    id: 'path-traversal-py', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 7.5, cwe: 'CWE-22', owasp: 'A01:2021',
    category: 'Path Traversal', title: 'File opened with request-controlled path',
    pattern: /(?:open|send_file|send_from_directory|os\.path\.join|FileResponse)\s*\([^)]*request\.(?:args|form|values|GET|POST|files|json)/,
    description: 'File paths derived from request data can contain ../ sequences.',
    impact: 'Arbitrary file read/write.',
    fix: 'Use werkzeug.utils.secure_filename and verify the resolved path is within an allowed directory.',
  },
  {
    id: 'ssrf-js', agent: 'sentinel', langs: ['js'], severity: 'high', cvss: 8.6, cwe: 'CWE-918', owasp: 'A10:2021',
    category: 'Server-Side Request Forgery', title: 'Outbound request to a user-supplied URL',
    pattern: new RegExp(String.raw`(?<![\w$])(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got(?:\.\w+)?|needle(?:\.\w+)?|superagent\.get|request(?:\.get)?|https?\.(?:get|request))\s*\(\s*[^,)]*(?:${USER_INPUT_JS})`),
    description: 'The server fetches a URL supplied by the client. Attackers can target internal services or cloud metadata (169.254.169.254).',
    impact: 'Access to internal network, credential theft from metadata endpoints.',
    fix: 'Allow-list destination hosts, block private/link-local IP ranges after DNS resolution, disable redirects.',
  },
  {
    id: 'ssrf-py', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 8.6, cwe: 'CWE-918', owasp: 'A10:2021',
    category: 'Server-Side Request Forgery', title: 'Outbound request to a user-supplied URL',
    pattern: /(?:requests|httpx)\.(?:get|post|put|request|head)\s*\(\s*request\.(?:args|form|values|GET|POST|json)|urlopen\s*\(\s*request\./,
    description: 'A URL from the request is fetched by the server.',
    impact: 'Internal network access / SSRF.',
    fix: 'Validate against an allow-list of hosts and block private address ranges.',
  },
  {
    id: 'open-redirect', agent: 'sentinel', langs: ['js', 'py', 'php', 'rb', 'java', 'cs'], severity: 'medium', cvss: 6.1, cwe: 'CWE-601', owasp: 'A01:2021',
    category: 'Open Redirect', title: 'Redirect to a user-controlled URL',
    pattern: /(?:res\.redirect|redirect|Redirect|sendRedirect|header\s*\(\s*["']Location:)\s*\(?[^;\n]*(?:req\.(?:query|params|body)|request\.(?:args|GET|query|params)|\$_(?:GET|REQUEST)|params\[|getParameter\()/,
    // Redirects to a fixed same-site path with a parameter appended (res.redirect("/posts/" + req.params.id)) stay on-site.
    unless: /(?:redirect|Redirect|sendRedirect)\s*\(\s*(?:\d{3}\s*,\s*)?(?:["'\x60]|f["'])\/(?![\/\\$])|url_for\s*\(/,
    description: 'The redirect target comes from request input.',
    impact: 'Phishing: users are sent to attacker sites from a trusted domain; OAuth token theft.',
    fix: 'Only redirect to relative paths or an allow-list of URLs.',
  },
  {
    id: 'xss-dom', agent: 'sentinel', langs: ['js', 'html'], severity: 'medium', cvss: 6.1, cwe: 'CWE-79', owasp: 'A03:2021',
    category: 'Cross-Site Scripting', title: 'HTML sink assigned from dynamic data',
    pattern: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)(?!\s*["'][^"'`$]*["']\s*;?\s*$)(?!\s*`[^`$]*`\s*;?\s*$)|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML|\bv-html\s*=|\[innerHTML\]\s*=|bypassSecurityTrust\w*\(/,
    unless: /DOMPurify\.sanitize|sanitizeHtml|escapeHtml|\besc\(/,
    description: 'Dynamic content is written into the DOM as HTML. Unless every value is escaped or sanitized this enables XSS.',
    impact: 'Session hijacking, account takeover, defacement.',
    fix: 'Use textContent / framework data binding, or sanitize with DOMPurify before inserting HTML.',
  },
  {
    id: 'xss-server', agent: 'sentinel', langs: ['js', 'php', 'py'], severity: 'high', cvss: 7.4, cwe: 'CWE-79', owasp: 'A03:2021',
    category: 'Cross-Site Scripting', title: 'Request data written into the response unescaped',
    pattern: /res\.(?:send|write|end)\s*\([^)]*(?:req\.(?:query|params|body))|\becho\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)|print\s+[^;]*\$_(?:GET|POST|REQUEST)|(?:make_response|HttpResponse)\s*\([^)]*request\.(?:args|GET|POST|form)/,
    unless: /escape|htmlspecialchars|htmlentities|sanitize|DOMPurify|encodeURIComponent|\besc\s*\(|\bintval\s*\(|\bNumber\s*\(|parseInt\s*\(|\bint\s*\(/i,
    description: 'Reflected user input is sent back as HTML without encoding.',
    impact: 'Reflected XSS.',
    fix: 'HTML-encode output (htmlspecialchars, template auto-escaping) or return JSON with the correct Content-Type.',
  },
  {
    id: 'template-unescaped', agent: 'sentinel', langs: ['html', 'py', 'js', 'rb'], severity: 'medium', cvss: 6.1, cwe: 'CWE-79', owasp: 'A03:2021',
    category: 'Cross-Site Scripting', title: 'Template auto-escaping disabled',
    pattern: /\|\s*safe\b|\{\{\{[^}]+\}\}\}|<%-\s*(?!include)|autoescape\s*(?:=\s*False|false|off)|\.html_safe\b|\braw\s*\(|Markup\s*\(/,
    description: 'Output is marked safe / unescaped in a template.',
    impact: 'Stored or reflected XSS if the value contains user data.',
    fix: 'Keep auto-escaping on; only mark trusted, sanitized HTML as safe.',
  },
  {
    id: 'ssti-py', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 8.8, cwe: 'CWE-1336', owasp: 'A03:2021',
    category: 'Server-Side Template Injection', title: 'Template rendered from a dynamic string',
    pattern: /render_template_string\s*\(|Template\s*\(\s*request\.|Environment\([^)]*\)\.from_string\s*\(/,
    description: 'Jinja templates compiled from strings can execute code if users control the template text.',
    impact: 'Remote code execution.',
    fix: 'Render static template files and pass user data only as context variables.',
  },
  {
    id: 'deserialization', agent: 'sentinel', langs: ['py', 'java', 'cs', 'php', 'rb', 'js'], severity: 'high', cvss: 8.8, cwe: 'CWE-502', owasp: 'A08:2021',
    category: 'Insecure Deserialization', title: 'Unsafe deserialization API',
    pattern: /\bpickle\.loads?\s*\(|\bcPickle\.loads?\(|\bdill\.loads?\(|\bmarshal\.loads?\(|\bshelve\.open\(|yaml\.unsafe_load\(|\bnew\s+ObjectInputStream\s*\(|XMLDecoder\s*\(|\bBinaryFormatter\b|NetDataContractSerializer|LosFormatter|SoapFormatter|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects)|\bunserialize\s*\(\s*\$_|Marshal\.load\s*\(|YAML\.load\s*\((?![^)]*safe)|require\(\s*["']node-serialize["']\)|\.unserialize\s*\(/,
    description: 'Deserializing untrusted data with these APIs can instantiate arbitrary objects and trigger gadget chains.',
    impact: 'Remote code execution.',
    fix: 'Use data-only formats (JSON) or safe loaders (yaml.safe_load, YAML.safe_load); never deserialize untrusted bytes with native serializers.',
  },
  {
    id: 'py-yaml-load', agent: 'sentinel', langs: ['py'], severity: 'high', cvss: 8.1, cwe: 'CWE-502', owasp: 'A08:2021',
    category: 'Insecure Deserialization', title: 'yaml.load without a safe Loader',
    pattern: /\byaml\.load\s*\((?![^)]*(?:Loader\s*=\s*)?(?:yaml\.)?(?:Safe|CSafe|Base)Loader)/,
    description: 'yaml.load with the default/unsafe loader can construct arbitrary Python objects.',
    impact: 'Remote code execution.',
    fix: 'Use yaml.safe_load(data).',
  },
  {
    id: 'xxe-java', agent: 'sentinel', langs: ['java'], severity: 'high', cvss: 8.2, cwe: 'CWE-611', owasp: 'A05:2021',
    category: 'XML External Entities', title: 'XML parser without XXE protection',
    pattern: /(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\s*\(/,
    unlessFile: /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL_DTD|setExpandEntityReferences\s*\(\s*false/,
    description: 'Default Java XML parsers resolve external entities.',
    impact: 'Local file disclosure, SSRF and denial of service via crafted XML.',
    fix: 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and set ACCESS_EXTERNAL_DTD/SCHEMA to "".',
  },
  {
    id: 'xxe-other', agent: 'sentinel', langs: ['py', 'php', 'cs'], severity: 'high', cvss: 8.2, cwe: 'CWE-611', owasp: 'A05:2021',
    category: 'XML External Entities', title: 'XML parsing with entity resolution enabled',
    pattern: /resolve_entities\s*=\s*True|LIBXML_NOENT|libxml_disable_entity_loader\s*\(\s*false|DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver|xml\.(?:etree|dom|sax)\.\w+\.parse(?:String)?\s*\(/,
    description: 'The XML parser is configured (or defaults) to resolve external entities.',
    impact: 'File disclosure / SSRF.',
    fix: 'Use defusedxml (Python), keep LIBXML_NOENT off (PHP), DtdProcessing.Prohibit (.NET).',
  },
  {
    id: 'prototype-pollution', agent: 'phantom', langs: ['js'], severity: 'medium', cvss: 6.5, cwe: 'CWE-1321', owasp: 'A08:2021',
    category: 'Prototype Pollution', title: 'Object key written from request data',
    pattern: new RegExp(String.raw`\[\s*(?:${USER_INPUT_JS})[^\]]*\]\s*=(?!=)|(?:_\.merge|_\.defaultsDeep|\$\.extend\s*\(\s*true|deepmerge|Object\.assign)\s*\([^)]*(?:${USER_INPUT_JS})`),
    description: 'Attacker-chosen keys like "__proto__" or "constructor" can modify Object.prototype.',
    impact: 'Logic bypass, denial of service, sometimes RCE through gadgets.',
    fix: 'Reject __proto__/constructor/prototype keys, use Object.create(null) or Map, and validate input with a schema.',
  },
  {
    id: 'csrf-disabled', agent: 'oracle', langs: ['java', 'py', 'rb', 'cs', 'js'], severity: 'medium', cvss: 6.5, cwe: 'CWE-352', owasp: 'A01:2021',
    category: 'Cross-Site Request Forgery', title: 'CSRF protection disabled',
    pattern: /csrf\(\)\s*\.disable\(\)|csrf\s*\(\s*\w+\s*->\s*\w+\.disable\(\)\)|@csrf_exempt|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session|IgnoreAntiforgeryToken|WTF_CSRF_ENABLED\s*=\s*False/,
    description: 'Cross-site request forgery protection is turned off for cookie-authenticated endpoints.',
    impact: 'Attackers can perform state-changing actions as a logged-in victim.',
    fix: 'Keep CSRF protection enabled, or use SameSite=strict cookies plus token/header verification.',
  },

  /* ═════════════ Crypto & configuration (CIPHER) ═════════════ */
  {
    id: 'weak-hash', agent: 'cipher', langs: ['*'], severity: 'medium', cvss: 5.9, cwe: 'CWE-328', owasp: 'A02:2021',
    category: 'Weak Cryptography', title: 'Weak hash algorithm (MD5/SHA-1)',
    pattern: /createHash\s*\(\s*["'](?:md5|sha1|md4)["']|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"|\b(?:MD5|SHA1)\.Create\s*\(|\bmd5\s*\(\s*\$|\bsha1\s*\(\s*\$|DigestUtils\.(?:md5|sha1)(?:Hex)?\s*\(|crypto\/md5|crypto\/sha1|Digest::(?:MD5|SHA1)/,
    unless: /usedforsecurity\s*=\s*False|etag|checksum|cache/i,
    description: 'MD5 and SHA-1 are broken for collision resistance and far too fast for password hashing.',
    impact: 'Password cracking, signature forgery, integrity bypass.',
    fix: 'Use SHA-256+ for integrity and bcrypt/scrypt/Argon2 for passwords.',
  },
  {
    id: 'weak-cipher', agent: 'cipher', langs: ['*'], severity: 'high', cvss: 7.4, cwe: 'CWE-327', owasp: 'A02:2021',
    category: 'Weak Cryptography', title: 'Weak or broken cipher / mode',
    pattern: /createCipher(?:iv)?\s*\(\s*["'](?:des|des-ede|des-ede3|rc2|rc4|bf|blowfish|aes-\d+-ecb)[^"']*["']|Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC2|RC4|Blowfish|AES|AES\/ECB[^"]*)"|\bDES\.new\(|\bARC4\.new\(|AES\.new\([^)]*MODE_ECB|CipherMode\.ECB|\bmcrypt_|\bRC4\b\s*\(/,
    description: 'DES/3DES/RC4/Blowfish are obsolete, and ECB mode leaks plaintext patterns. A bare "AES" in Java defaults to ECB.',
    impact: 'Encrypted data can be decrypted or manipulated.',
    fix: 'Use AES-256-GCM (or ChaCha20-Poly1305) with a random nonce per message.',
  },
  {
    id: 'deprecated-createcipher', agent: 'cipher', langs: ['js'], severity: 'medium', cvss: 5.9, cwe: 'CWE-329', owasp: 'A02:2021',
    category: 'Weak Cryptography', title: 'crypto.createCipher without IV',
    pattern: /crypto\.createCipher\s*\(|createDecipher\s*\(/,
    description: 'createCipher derives key and IV from a password with MD5 and a fixed IV — deprecated and insecure.',
    impact: 'Predictable ciphertext; key derivation is weak.',
    fix: 'Use crypto.createCipheriv("aes-256-gcm", key, randomIv).',
  },
  {
    id: 'insecure-random', agent: 'cipher', langs: ['*'], severity: 'medium', cvss: 5.3, cwe: 'CWE-338', owasp: 'A02:2021',
    category: 'Insecure Randomness', title: 'Non-cryptographic RNG used for a security value',
    pattern: /Math\.random\s*\(|\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\s*\(|new\s+Random\s*\(|\brand\s*\(|\bmt_rand\s*\(|math\/rand|\buniqid\s*\(/,
    // The random value must be assigned to / returned for something security-relevant — a bare mention of
    // "token" or "session" elsewhere on the line (tokens.length, a comment about backoff) is not enough.
    requires: SEC_TARGET,
    unless: /\b(?:delay|jitter|backoff|colou?r|width|height|index|idx|sleep|timeout|duration|animation|opacity|angle|offset)\w{0,12}\s*[:=](?!=)|\b[xyij]\s*[:=](?!=)/i,
    description: 'A predictable pseudo-random generator is used to create tokens, passwords, OTPs or IDs.',
    impact: 'Attackers can predict tokens and hijack sessions / reset links.',
    fix: 'Use crypto.randomBytes / crypto.randomUUID (Node), secrets module (Python), SecureRandom (Java), random_bytes (PHP).',
  },
  {
    id: 'tls-verify-off', agent: 'cipher', langs: ['*'], severity: 'high', cvss: 7.4, cwe: 'CWE-295', owasp: 'A02:2021',
    category: 'Improper Certificate Validation', title: 'TLS certificate verification disabled',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)|ServerCertificateValidationCallback\s*=|ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true|NoopHostnameVerifier|TrustAllStrategy|ALLOW_ALL_HOSTNAME_VERIFIER|curl\s+(?:-k|--insecure)\b|strict-ssl\s*=?\s*false/,
    description: 'HTTPS connections accept any certificate.',
    impact: 'Man-in-the-middle attackers can read and modify traffic, including credentials.',
    fix: 'Keep certificate verification on; trust a custom CA bundle if you use internal certificates.',
  },
  {
    id: 'jwt-weak', agent: 'cipher', langs: ['*'], severity: 'critical', cvss: 9.1, cwe: 'CWE-347', owasp: 'A02:2021',
    category: 'Broken Authentication', title: 'JWT signature verification weakened',
    pattern: /algorithms?\s*[:=]\s*\[?\s*["']none["']|verify_signature["']?\s*:\s*False|verify\s*=\s*False[^\n]*jwt|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|\.parseUnsecuredClaims|setSigningKey\(\s*""\s*\)/i,
    description: 'The application accepts unsigned tokens, skips signature checks or ignores expiry.',
    impact: 'Attackers can forge tokens and impersonate any user.',
    fix: 'Always verify with an explicit algorithm allow-list (e.g. jwt.verify(token, key, { algorithms: ["HS256"] })).',
  },
  {
    id: 'jwt-hardcoded-secret', agent: 'cipher', langs: ['js', 'py', 'java', 'go', 'php', 'rb', 'cs'], severity: 'high', cvss: 8.1, cwe: 'CWE-798', owasp: 'A07:2021',
    category: 'Hardcoded Credentials', title: 'JWT / session signed with a hardcoded secret',
    pattern: /jwt\.(?:sign|verify|encode|decode)\s*\([^)]*,\s*["'][^"']{3,}["']|(?:secret|secretOrKey|SECRET_KEY|JWT_SECRET|session_secret|secret_key_base)\s*[:=]\s*["'][^"']{3,}["']/,
    unless: /process\.env|os\.environ|getenv|ENV\[|config\(|your[-_]|change[-_]?me|example|<|\$\{/i,
    description: 'The signing secret for tokens or sessions is a literal in source code.',
    impact: 'Anyone with the code (or a leaked repo) can mint valid sessions for any user.',
    fix: 'Load secrets from environment variables / a secret manager and rotate the exposed one.',
  },
  {
    id: 'debug-enabled', agent: 'cipher', langs: ['py', 'js', 'php', 'conf', 'env', 'yaml', 'java', 'cs', 'rb'], severity: 'medium', cvss: 5.3, cwe: 'CWE-489', owasp: 'A05:2021',
    category: 'Security Misconfiguration', title: 'Debug mode enabled',
    // Upper-case DEBUG settings (Django/.env/constants) anywhere; lower-case `debug: true` only as a whole
    // config line (YAML / ini), so JS option objects like `{ debug: true, ... }` for a logger don't match.
    pattern: /\b(?:DJANGO_|FLASK_|APP_)?DEBUG\s*[:=]\s*(?:True|true|TRUE|1|["'](?:true|True|1)["'])(?![\w])|^\s*debug\s*[:=]\s*(?:true|True|on|1)\s*$|\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|(?:display_errors|DISPLAY_ERRORS)["']?\s*[=,]\s*["']?(?:On|1|true)|customErrors\s+mode\s*=\s*"Off"|config\.consider_all_requests_local\s*=\s*true/,
    description: 'Debug mode exposes stack traces, interactive debuggers (Werkzeug console = RCE) and internal data.',
    impact: 'Information disclosure; with Flask/Werkzeug debugger, remote code execution.',
    fix: 'Disable debug in production and drive it from an environment variable defaulting to off.',
  },
  {
    id: 'insecure-cookie', agent: 'cipher', langs: ['js', 'py', 'php', 'java', 'cs'], severity: 'low', cvss: 3.7, cwe: 'CWE-614', owasp: 'A05:2021',
    category: 'Security Misconfiguration', title: 'Cookie without Secure/HttpOnly',
    // secure:false in an SMTP/TLS client config (nodemailer STARTTLS on port 587) is not a cookie flag.
    skip: (lines, i) => /^\s*secure\s*:\s*false/i.test(lines[i]) && /createTransport|smtp|port\s*:\s*(?:25|587|2525)\b|host\s*:\s*["'][^"']*mail/i.test(around(lines, i, 6, 3)),
    pattern: /httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|setHttpOnly\s*\(\s*false|setSecure\s*\(\s*false|HttpOnly\s*=\s*false|session\.cookie_httponly\s*=\s*0/i,
    description: 'Session cookies readable from JavaScript or sent over plain HTTP are easier to steal.',
    impact: 'Session hijacking via XSS or network sniffing.',
    fix: 'Set HttpOnly, Secure and SameSite on session cookies.',
  },
  {
    id: 'weak-password-hash', agent: 'cipher', langs: ['*'], severity: 'high', cvss: 7.5, cwe: 'CWE-916', owasp: 'A02:2021',
    category: 'Weak Cryptography', title: 'Password stored with a fast hash',
    pattern: /(?:md5|sha1|sha256|sha512|createHash)\s*\([^)]*pass(?:word|wd)?|createHash\s*\(\s*["'](?:md5|sha1|sha256|sha384|sha512)["']\s*\)\s*\.update\s*\([^)]*pass(?:word|wd)?/i,
    unless: /bcrypt|argon|scrypt|pbkdf2/i,
    description: 'Passwords are hashed with a general-purpose hash; GPUs can test billions of guesses per second.',
    impact: 'Leaked hashes are quickly cracked.',
    fix: 'Use bcrypt (cost ≥ 12), scrypt or Argon2id.',
  },
  {
    id: 'bind-all-interfaces', agent: 'cipher', langs: ['py', 'js', 'go'], severity: 'low', cvss: 3.1, cwe: 'CWE-1327', owasp: 'A05:2021',
    category: 'Security Misconfiguration', title: 'Service binds to all interfaces',
    pattern: /host\s*=\s*["']0\.0\.0\.0["']|\.listen\s*\(\s*\d+\s*,\s*["']0\.0\.0\.0["']|ListenAndServe\s*\(\s*":\d+"/,
    description: 'The server listens on every network interface, which can expose development services.',
    impact: 'Unintended network exposure.',
    fix: 'Bind to 127.0.0.1 in development; expose deliberately via a reverse proxy in production.',
  },
  {
    id: 'insecure-tempfile', agent: 'phantom', langs: ['py', 'c'], severity: 'medium', cvss: 5.5, cwe: 'CWE-377', owasp: 'A01:2021',
    category: 'Race Condition', title: 'Insecure temporary file creation',
    pattern: /tempfile\.mktemp\s*\(|\btmpnam\s*\(|\btempnam\s*\(|\bmktemp\s*\(/,
    description: 'The file name is generated before the file is created, allowing a race (symlink attack).',
    impact: 'File overwrite / privilege escalation.',
    fix: 'Use tempfile.mkstemp / NamedTemporaryFile or mkstemp().',
  },

  /* ═════════════ Runtime & memory safety (PHANTOM) ═════════════ */
  {
    id: 'c-unsafe-func', agent: 'phantom', langs: ['c'], severity: 'high', cvss: 8.1, cwe: 'CWE-120', owasp: 'A06:2021',
    category: 'Buffer Overflow', title: 'Unbounded string/memory function',
    pattern: /(?<![\w.])(?:gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|stpcpy)\s*\(/,
    description: 'These functions do not check destination buffer size.',
    impact: 'Memory corruption, crashes, potentially code execution.',
    fix: 'Use bounded alternatives: fgets, strncpy/strlcpy, snprintf.',
  },
  {
    id: 'c-format-string', agent: 'phantom', langs: ['c'], severity: 'high', cvss: 7.5, cwe: 'CWE-134', owasp: 'A03:2021',
    category: 'Format String', title: 'printf-family call with non-literal format',
    pattern: /(?<![\w.])(?:printf|fprintf\s*\(\s*\w+\s*,|syslog\s*\(\s*\w+\s*,|sprintf\s*\(\s*\w+\s*,)\s*\(?\s*[a-zA-Z_]\w*\s*\)/,
    description: 'A variable is used as the format string; %n/%x specifiers can read or write memory.',
    impact: 'Information leak or memory corruption.',
    fix: 'Always use a literal format: printf("%s", buf).',
  },
  {
    id: 'c-system', agent: 'sentinel', langs: ['c'], severity: 'medium', cvss: 6.3, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'OS Command Injection', title: 'system()/popen() call',
    pattern: /(?<![\w.])(?:system|popen)\s*\(\s*[a-zA-Z_]/,
    description: 'Commands passed to system() are interpreted by the shell.',
    impact: 'Command injection if the string includes external data.',
    fix: 'Use execve-family calls with explicit arguments.',
  },
  {
    id: 'empty-catch', agent: 'phantom', langs: ['js', 'java', 'cs', 'php'], severity: 'low', cvss: 2.0, cwe: 'CWE-390', owasp: 'A09:2021',
    category: 'Error Handling', title: 'Exception silently swallowed',
    pattern: /catch\s*(?:\([^)]*\))?\s*\{\s*\}/,
    // Deliberately ignoring cancellation / "already gone" exceptions is an accepted idiom.
    unless: /catch\s*\(\s*(?:[\w.]*(?:OperationCanceled|TaskCanceled|Interrupted|FileNotFound|NoSuchFile|NumberFormat|ClosedChannel)\w*|AbortError)\b/,
    description: 'Errors are caught and ignored, hiding failures (including security-relevant ones).',
    impact: 'Undetected failures, inconsistent state, missing audit trail.',
    fix: 'Log the error with context or handle it explicitly; add a comment if ignoring is intentional.',
  },
  {
    id: 'py-bare-except', agent: 'phantom', langs: ['py'], severity: 'low', cvss: 2.0, cwe: 'CWE-396', owasp: 'A09:2021',
    category: 'Error Handling', title: 'Bare except: pass',
    pattern: /except\s*(?:Exception)?\s*:\s*pass\b/,
    description: 'All exceptions (including KeyboardInterrupt/SystemExit for bare except) are discarded.',
    impact: 'Hidden bugs and security failures.',
    fix: 'Catch specific exceptions and log them.',
  },
  {
    id: 'py-assert-security', agent: 'phantom', langs: ['py'], severity: 'medium', cvss: 5.3, cwe: 'CWE-617', owasp: 'A04:2021',
    category: 'Logic Flaw', title: 'assert used for a security check',
    pattern: /^\s*assert\s+[^\n]*(?:auth|admin|permission|is_staff|is_superuser|logged_in|owner|role)/i,
    description: 'assert statements are stripped when Python runs with -O, removing the check.',
    impact: 'Authorization bypass in optimized deployments.',
    fix: 'Use an explicit if-check that raises PermissionDenied / returns 403.',
  },
  {
    id: 'js-loose-auth-compare', agent: 'phantom', langs: ['js', 'php'], severity: 'medium', cvss: 5.9, cwe: 'CWE-697', owasp: 'A07:2021',
    category: 'Logic Flaw', title: 'Loose (==) comparison on a secret / password',
    pattern: /\b[\w.]*(?:password|passwd|token|secret|signature|otp|hmac)\w*\s*(?<![=!<>])(?:==|!=)(?!=)|(?<![=!<>])(?:==|!=)(?!=)\s*[\w.]*(?:password|passwd|token|secret|signature|hmac)\w*\b/i,
    unless: /\b(?:null|undefined|None|nil)\b|typeof|\.length|""|''|\b(?:true|false)\b|\d+\s*$/,
    description: 'Loose equality performs type juggling (PHP "0e123" == "0e456" is true) and is not constant time.',
    impact: 'Authentication bypass or timing attacks.',
    fix: 'Use strict comparison of hashes with a constant-time function (crypto.timingSafeEqual, hash_equals).',
  },
  {
    id: 'regex-dos', agent: 'phantom', langs: ['js', 'py', 'java', 'cs', 'rb', 'php'], severity: 'low', cvss: 3.7, cwe: 'CWE-1333', owasp: 'A05:2021',
    category: 'Denial of Service', title: 'Regular expression vulnerable to catastrophic backtracking',
    // A group that contains a quantified regex atom (\w+, [a-z]*, .+, a+) and is itself repeated: (a+)+, (\w+\s?)*, ([a-z]+.)+
    // Only optional items may follow the inner quantifier inside the group; a mandatory delimiter such as
    // ([\w-]+\.)+ makes the repetition unambiguous and is not flagged. Arithmetic like (a+b)*c doesn't match.
    pattern: /(?:new\s+RegExp|re\.compile|Pattern\.compile|Regex\(|\/)[^\n]*\((?:\?:)?[^()]*?(?:\\{1,2}[wWsSdD]|\]|\.|[a-zA-Z])[+*](?:\\{1,2}[wWsSdD][?*]|\[[^\]\n]*\][?*]|[^\\()[\]\n][?*])*\)(?:[+*]|\{\d+,\})/,
    description: 'Nested quantifiers like (a+)+ backtrack exponentially on crafted input.',
    impact: 'A single request can pin a CPU (ReDoS).',
    fix: 'Rewrite without nested quantifiers, bound input length, or use a linear-time engine (RE2).',
  },

  /* ═════════════ API & data exposure (ORACLE) ═════════════ */
  {
    id: 'cors-wildcard', agent: 'oracle', langs: ['*'], severity: 'medium', cvss: 5.3, cwe: 'CWE-942', owasp: 'A05:2021',
    category: 'CORS Misconfiguration', title: 'Permissive CORS policy',
    pattern: /Access-Control-Allow-Origin["']?\s*[,:=]\s*["']\*["']|\bcors\s*\(\s*\)|origin\s*:\s*(?:["']\*["']|true)\b|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|AllowAnyOrigin\s*\(\s*\)|allowedOrigins\s*\(\s*"\*"\s*\)|@CrossOrigin\s*(?:\(\s*\)|\(\s*(?:origins\s*=\s*)?"\*")/,
    description: 'Any website may read responses from this API. Combined with credentials or reflected origins it exposes user data.',
    impact: 'Cross-origin data theft.',
    fix: 'Allow only the specific origins that need access; never combine wildcard/reflected origins with credentials.',
  },
  {
    id: 'stack-trace-leak', agent: 'oracle', langs: ['js', 'py', 'java', 'cs', 'php'], severity: 'medium', cvss: 5.3, cwe: 'CWE-209', owasp: 'A05:2021',
    category: 'Information Exposure', title: 'Error details returned to the client',
    // Express: whole error object, any .stack, or .message on a 5xx / status-less response (4xx validation
    // messages are usually meant for the client). Java/C#/Python/PHP: exception text written to the response.
    pattern: /\bres\.(?:status\(\s*\d+\s*\)\.)?(?:send|json|write|end)\s*\(\s*(?:err|error|e|ex|exception)\s*\)|\bres\.(?:status\(\s*\d+\s*\)\.)?(?:send|json|write|end)\s*\([^;]*?\b(?:err|error|e|ex|exception)\.stack\b|\bres\.(?:status\(\s*5\d\d\s*\)\.)?(?:send|json)\s*\([^;]*?\b(?:err|error|e|ex|exception)\.message\b|return[^\n]*traceback\.format_exc\(\)|traceback\.format_exc\(\)[^\n]*return|(?:jsonify|Response|HttpResponse|JsonResponse)\s*\([^\n]*\bstr\(\s*(?:e|ex|err|exc|error)\s*\)|return\s+str\(\s*(?:e|ex|err|exc|error)\s*\)\s*,\s*5\d\d|printStackTrace\s*\(\s*(?:response|resp)\b|getWriter\(\)\.(?:print(?:ln)?|write)\s*\([^;]*\b(?:e|ex|exc|exception|t)\.(?:getMessage|toString|getStackTrace)\(|\.body\s*\([^;]*\b(?:e|ex|exc|exception)\.(?:getMessage|toString|getStackTrace)\(|sendError\s*\([^;]*\b(?:e|ex|exc|exception)\.(?:getMessage|toString)\(|\b(?:BadRequest|StatusCode|Problem|Content)\s*\([^;]*\b(?:e|ex|exception)\.(?:Message|StackTrace|ToString\(\))|\becho\s+\$(?:e|ex|exception)->(?:getMessage|getTraceAsString)\(/,
    unless: /console\.|logger\.|log\.|logging\./,
    description: 'Raw exception objects or stack traces are sent to API consumers.',
    impact: 'Leaks internal paths, queries, library versions and secrets that help attackers.',
    fix: 'Log the full error server-side and return a generic message with a correlation ID.',
  },
  {
    id: 'sensitive-logging', agent: 'oracle', langs: ['js', 'py', 'java', 'cs', 'php', 'go', 'rb'], severity: 'low', cvss: 3.3, cwe: 'CWE-532', owasp: 'A09:2021',
    category: 'Information Exposure', title: 'Sensitive value written to logs',
    // The sensitive word must be a logged *value* (argument, property, interpolation) — not prose inside the
    // message text such as "password reset email sent" or "token refreshed for %s".
    pattern: /(?:console\.(?:log|info|debug|warn|error)|\bprint|logger\.\w+|logging\.\w+|\blog\.\w+|System\.out\.println|fmt\.Print\w*|error_log|\bputs)\s*\([^)]*?(?:[(,{+.]\s*|\$\{\s*|\{|%\(\s*)[\w.]*?(?:password|passwd|secret|token|api_?key|authorization|credit_?card|ssn|cvv)\b(?!\s+[a-z]|\s*\()/i,
    description: 'Credentials or personal data may end up in log files and log aggregation services.',
    impact: 'Credential leakage to anyone with log access.',
    fix: 'Redact sensitive fields before logging.',
  },
  {
    id: 'postmessage-wildcard', agent: 'oracle', langs: ['js', 'html'], severity: 'medium', cvss: 5.4, cwe: 'CWE-345', owasp: 'A08:2021',
    category: 'Information Exposure', title: 'postMessage with "*" target / unchecked origin',
    pattern: /postMessage\s*\([^)]*,\s*["']\*["']\s*\)|addEventListener\s*\(\s*["']message["']\s*,(?![^\n]*origin)/,
    // A message handler that checks event.origin within its first lines is fine.
    skip: (lines, i) => /addEventListener/.test(lines[i]) && !/postMessage/.test(lines[i]) && /\.origin\b/.test(around(lines, i, 0, 8)),
    description: 'Messages are sent to any origin, or received without checking event.origin.',
    impact: 'Data leakage to or injection from malicious frames.',
    fix: 'Specify the exact target origin and validate event.origin in message handlers.',
  },
  {
    id: 'token-in-localstorage', agent: 'oracle', langs: ['js', 'html'], severity: 'low', cvss: 3.7, cwe: 'CWE-922', owasp: 'A04:2021',
    category: 'Insecure Storage', title: 'Credential stored in Web Storage',
    pattern: /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["'`][^"'`]*(?:token|jwt|auth|password|secret|api_?key|session)/i,
    description: 'Anything in localStorage is readable by any script on the page, so one XSS exposes the credential.',
    impact: 'Account takeover after XSS.',
    fix: 'Keep session tokens in HttpOnly cookies; keep API keys on the server.',
  },
  {
    id: 'graphql-introspection', agent: 'oracle', langs: ['js', 'py', 'java'], severity: 'low', cvss: 3.7, cwe: 'CWE-200', owasp: 'A05:2021',
    category: 'Information Exposure', title: 'GraphQL introspection / playground enabled',
    pattern: /introspection\s*:\s*true|playground\s*:\s*true|graphiql\s*[:=]\s*(?:true|True)/,
    description: 'The full API schema is published to anyone.',
    impact: 'Eases discovery of hidden or sensitive operations.',
    fix: 'Disable introspection and GraphiQL in production.',
  },
  {
    id: 'mass-assignment', agent: 'oracle', langs: ['js', 'rb', 'py'], severity: 'medium', cvss: 6.5, cwe: 'CWE-915', owasp: 'A08:2021',
    category: 'Mass Assignment', title: 'Model created/updated directly from request body',
    pattern: /\.(?:create|update|insertOne|findByIdAndUpdate|findOneAndUpdate|build|save|updateOne)\s*\(\s*(?:[\w.]+\s*,\s*)?req\.body\s*[,)]|params\.permit!|\.objects\.create\(\s*\*\*request\.(?:POST|data)/,
    description: 'Every field in the request body is written to the model, including ones like isAdmin or role.',
    impact: 'Privilege escalation / tampering with protected fields.',
    fix: 'Copy an explicit allow-list of fields or validate with a strict schema.',
  },
  {
    id: 'missing-auth-admin', agent: 'oracle', langs: ['js'], severity: 'medium', cvss: 6.5, cwe: 'CWE-306', owasp: 'A01:2021',
    category: 'Broken Access Control', title: 'Admin/internal route without visible auth middleware',
    pattern: /\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(\s*["'`]\/(?:api\/(?:v\d+\/)?)?(?:admin|internal|debug|manage|config)(?![\w-])[^"'`]*["'`]\s*,\s*(?:async\s*)?(?:\(|function\b|\w+\s*=>)/,
    // Auth applied once for the whole router / path prefix (router.use(requireAdmin), app.use('/admin', auth, ...)).
    unlessFile: /\b(?:app|router|\w+Router)\.use\s*\(\s*(?:["'`][^"'`]*["'`]\s*,\s*)?(?:[\w.]*\b(?:(?:require|ensure|is|check|verify|must)_?(?:Auth|Admin|Login|Logged|Role|Token|User|Jwt|Staff|Session)\w*|authenticate\w*|authorize\w*|authorise\w*|protect\w*|\w*[gG]uard|\w*[aA]uth(?:Middleware|enticated|orized)?|jwt\w*|adminOnly|admin[A-Z]\w*)\b)/,
    description: 'A privileged route is registered with the handler directly, with no authentication/authorization middleware in between.',
    impact: 'Unauthenticated access to administrative functions.',
    fix: 'Add auth + role checks: router.post("/admin/x", requireAuth, requireRole("admin"), handler).',
  },

  /* ═════════════ Supply chain / infrastructure (NEXUS) ═════════════ */
  {
    id: 'curl-pipe-shell', agent: 'nexus', langs: ['sh', 'docker', 'yaml', 'text', 'other', 'ps'], severity: 'medium', cvss: 6.5, cwe: 'CWE-494', owasp: 'A08:2021',
    category: 'Supply Chain', title: 'Remote script piped into a shell',
    pattern: /(?:curl|wget)\s[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|iex\s*\(\s*(?:New-Object\s+Net\.WebClient|irm|Invoke-RestMethod|iwr)/i,
    description: 'A script downloaded at runtime is executed without integrity verification.',
    impact: 'A compromised server or MITM yields code execution in your build/runtime.',
    fix: 'Download, verify a pinned checksum/signature, then execute; or use the package manager.',
  },
  {
    id: 'chmod-777', agent: 'nexus', langs: ['sh', 'docker', 'py', 'js', 'go', 'yaml'], severity: 'medium', cvss: 5.5, cwe: 'CWE-732', owasp: 'A01:2021',
    category: 'Insecure Permissions', title: 'World-writable permissions',
    pattern: /chmod\s+(?:-R\s+)?(?:0?777|a\+rwx|o\+w)|os\.chmod\([^)]*0o?777|fs\.chmod(?:Sync)?\([^)]*0o?777|os\.Chmod\([^)]*0777/,
    description: 'Files or directories are made writable by every user.',
    impact: 'Local privilege escalation and tampering.',
    fix: 'Grant the minimum permissions needed (e.g. 750/640).',
  },
  {
    id: 'docker-latest', agent: 'nexus', langs: ['docker'], severity: 'low', cvss: 3.1, cwe: 'CWE-1104', owasp: 'A06:2021',
    category: 'Supply Chain', title: 'Base image not pinned',
    pattern: /^\s*FROM\s+(?!scratch\b)(?:--platform=\S+\s+)?[^\s:@]+(?::latest)?(?:\s+AS\s+[\w.-]+)?\s*$/i,
    unless: /\$\{?\w+\}?/,
    // `FROM build` referring to an earlier multi-stage `... AS build` is not a registry image.
    skip: (lines, i) => {
      const img = lines[i].match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+)/i)?.[1];
      return !!img && lines.slice(0, i).some((l) => new RegExp(String.raw`^\s*FROM\s.*\sAS\s+${img.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\s*$`, 'i').test(l));
    },
    description: 'The image uses an implicit or :latest tag, so builds are not reproducible and may silently pull vulnerable versions.',
    impact: 'Unexpected, unreviewed dependency changes.',
    fix: 'Pin to a specific version tag or digest (FROM node:22.11-alpine@sha256:...).',
  },
  {
    id: 'docker-secret-env', agent: 'cipher', langs: ['docker'], severity: 'high', cvss: 7.5, cwe: 'CWE-798', owasp: 'A07:2021',
    category: 'Hardcoded Credentials', title: 'Secret baked into image via ENV/ARG',
    pattern: /^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*[\s=]+["']?[^\s"'$]{4,}/i,
    description: 'Values set with ENV/ARG are stored in image layers and visible with docker history.',
    impact: 'Anyone with the image can read the credential.',
    fix: 'Pass secrets at runtime (env vars, Docker/K8s secrets) or use BuildKit --mount=type=secret.',
  },
  {
    id: 'docker-add-remote', agent: 'nexus', langs: ['docker'], severity: 'low', cvss: 3.7, cwe: 'CWE-494', owasp: 'A08:2021',
    category: 'Supply Chain', title: 'ADD from remote URL',
    pattern: /^\s*ADD\s+https?:\/\//i,
    description: 'ADD downloads remote content without checksum verification.',
    impact: 'Tampered downloads end up in the image.',
    fix: 'Use RUN curl with checksum verification, or ADD --checksum=sha256:...',
  },
  {
    id: 'k8s-privileged', agent: 'nexus', langs: ['yaml'], severity: 'high', cvss: 7.8, cwe: 'CWE-250', owasp: 'A05:2021',
    category: 'Container Security', title: 'Privileged container / host access',
    pattern: /privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true|runAsUser\s*:\s*0\b|\/var\/run\/docker\.sock|SYS_ADMIN/,
    // SYS_ADMIN listed under capabilities.drop is the hardening, not the problem.
    skip: (lines, i) => {
      if (!/SYS_ADMIN/.test(lines[i]) || /privileged|hostNetwork|hostPID|hostIPC|runAsUser|docker\.sock|add\s*:/.test(lines[i])) return false;
      if (/drop\s*:/.test(lines[i])) return true;
      for (let k = i - 1; k >= Math.max(0, i - 15); k--) {
        if (/^\s*drop\s*:/.test(lines[k])) return true;
        if (/^\s*add\s*:/.test(lines[k])) return false;
      }
      return false;
    },
    description: 'The container gets host-level privileges or namespaces.',
    impact: 'Container escape to the host node.',
    fix: 'Drop privileges: privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, drop ALL capabilities.',
  },
  {
    id: 'gha-script-injection', agent: 'nexus', langs: ['yaml'], severity: 'high', cvss: 8.8, cwe: 'CWE-78', owasp: 'A03:2021',
    category: 'CI/CD Injection', title: 'GitHub Actions expression injection',
    pattern: /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits)[\w.\[\]*]*\.(?:title|body|message|label|name|ref)|head_ref)\s*\}\}/,
    description: 'Attacker-controlled event fields (PR title/body, branch names) are expanded inline into a run: script.',
    impact: 'Arbitrary command execution in CI with access to repository secrets.',
    fix: 'Pass the value through an environment variable (env: TITLE: ${{ ... }}) and reference "$TITLE" in the script.',
  },
  {
    id: 'gha-pr-target', agent: 'nexus', langs: ['yaml'], severity: 'medium', cvss: 6.5, cwe: 'CWE-829', owasp: 'A08:2021',
    category: 'CI/CD Security', title: 'pull_request_target workflow',
    pattern: /^\s*pull_request_target\s*:/,
    unlessFile: /^(?![\s\S]*actions\/checkout)/,
    description: 'pull_request_target runs with write tokens and secrets; checking out PR code in it lets forks run code with those privileges.',
    impact: 'Secret exfiltration / repository compromise.',
    fix: 'Use pull_request for untrusted code, or never check out the PR head in pull_request_target jobs.',
  },
  {
    id: 'tf-open-ingress', agent: 'nexus', langs: ['tf'], severity: 'medium', cvss: 6.5, cwe: 'CWE-284', owasp: 'A05:2021',
    category: 'Cloud Misconfiguration', title: 'Security group open to the internet',
    pattern: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]|ipv6_cidr_blocks\s*=\s*\[\s*"::\/0"\s*\]|source_address_prefix\s*=\s*"(?:\*|0\.0\.0\.0\/0|Internet)"/,
    description: 'Inbound traffic is allowed from any IP address.',
    impact: 'Exposed management ports / databases.',
    fix: 'Restrict CIDR ranges to known networks; put admin access behind a VPN/bastion.',
  },
  {
    id: 'tf-public-storage', agent: 'nexus', langs: ['tf'], severity: 'high', cvss: 7.5, cwe: 'CWE-284', owasp: 'A01:2021',
    category: 'Cloud Misconfiguration', title: 'Public or unencrypted cloud resource',
    pattern: /acl\s*=\s*"public-read(?:-write)?"|publicly_accessible\s*=\s*true|block_public_acls\s*=\s*false|encrypted\s*=\s*false|storage_encrypted\s*=\s*false|enable_https_traffic_only\s*=\s*false|allow_blob_public_access\s*=\s*true/,
    description: 'Storage/databases are publicly reachable or unencrypted.',
    impact: 'Data breach.',
    fix: 'Keep resources private, enable encryption at rest and enforce HTTPS.',
  },
  {
    id: 'html-target-blank', agent: 'oracle', langs: ['html', 'js'], severity: 'low', cvss: 2.6, cwe: 'CWE-1022', owasp: 'A05:2021',
    category: 'Reverse Tabnabbing', title: 'target="_blank" without rel="noopener"',
    pattern: /target\s*=\s*["']_blank["']/,
    unless: /noopener|noreferrer/,
    // JSX / HTML attributes are often split over several lines: look at the rest of the tag.
    skip: (lines, i) => {
      const before = around(lines, i, 4, 0), after = around(lines, i, 0, 4);
      const tagStart = before.lastIndexOf('<'), tagEnd = after.indexOf('>');
      const tag = before.slice(tagStart >= 0 ? tagStart : 0) + after.slice(lines[i].length, tagEnd >= 0 ? tagEnd : undefined);
      return /noopener|noreferrer/.test(tag);
    },
    description: 'The opened page can navigate the original tab via window.opener (older browsers).',
    impact: 'Phishing via tab replacement.',
    fix: 'Add rel="noopener noreferrer".',
  },
  {
    id: 'mixed-content', agent: 'oracle', langs: ['html', 'js'], severity: 'medium', cvss: 5.9, cwe: 'CWE-319', owasp: 'A02:2021',
    category: 'Cleartext Transmission', title: 'Script/stylesheet loaded over HTTP',
    pattern: /<(?:script|link|iframe)[^>]+(?:src|href)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i,
    description: 'Resources fetched over plain HTTP can be modified in transit.',
    impact: 'Network attackers can inject script (XSS).',
    fix: 'Load all resources over HTTPS and add Subresource Integrity for CDNs.',
  },
  {
    id: 'cdn-no-sri', agent: 'nexus', langs: ['html'], severity: 'low', cvss: 3.7, cwe: 'CWE-353', owasp: 'A08:2021',
    category: 'Supply Chain', title: 'Third-party script without Subresource Integrity',
    pattern: /<script[^>]+src\s*=\s*["']https?:\/\/(?!localhost)[^"']+["'][^>]*>/i,
    unless: /integrity\s*=|googletagmanager|google-analytics|recaptcha|maps\.googleapis/i,
    description: 'If the CDN is compromised, the injected script runs with full page privileges.',
    impact: 'Supply-chain XSS.',
    fix: 'Add integrity="sha384-..." crossorigin="anonymous" or self-host the file.',
  },
  {
    id: 'cleartext-url', agent: 'oracle', langs: ['js', 'py', 'java', 'cs', 'go', 'php', 'rb', 'yaml', 'env', 'conf'], severity: 'low', cvss: 3.7, cwe: 'CWE-319', owasp: 'A02:2021',
    category: 'Cleartext Transmission', title: 'Plain HTTP endpoint',
    // Public dotted host names only: excludes private/loopback IPs, docker-compose service names (http://db:5432),
    // reserved TLDs, and XML namespace / parser-feature URIs that are identifiers rather than endpoints.
    pattern: /["'=]\s*http:\/\/(?!localhost\b|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|www\.w3\.org|[\w.-]*schemas\.|xmlns|(?:www\.)?example\.(?:com|org|net)|json-schema\.org|purl\.org|ns\.adobe|(?:www\.)?xml\.org|(?:xml|www|maven|xerces)\.apache\.org|java\.sun\.com|javax\.xml|xmlpull\.org|(?:www\.)?opensource\.org|(?:www\.)?apache\.org\/(?:licenses|xml)|docs\.oasis-open\.org|ns\.|[\w.-]+\.(?:local|internal|test|localhost|example|invalid)(?![\w.-])|host\.docker\.internal)[\w-]+(?:\.[\w-]+)+/i,
    description: 'Traffic to this endpoint is not encrypted.',
    impact: 'Eavesdropping and tampering with requests/responses (including credentials).',
    fix: 'Use https:// URLs.',
  },
];

/** File-level checks that need more than one line of context. */
export const FILE_CHECKS = [
  {
    id: 'docker-root-user', agent: 'nexus', langs: ['docker'], severity: 'medium', cvss: 5.5, cwe: 'CWE-250', owasp: 'A05:2021',
    category: 'Container Security', title: 'Container runs as root',
    test: (c) => /^\s*FROM\s/im.test(c) && !/^\s*USER\s+(?!root\b|0\b)\S+/im.test(c),
    line: (lines) => Math.max(1, lines.findIndex((l) => /^\s*FROM\s/i.test(l)) + 1),
    description: 'No non-root USER instruction is set, so processes in the container run as root.',
    impact: 'A compromise of the app gives root inside the container, easing escapes.',
    fix: 'Create an unprivileged user and add "USER app" before CMD/ENTRYPOINT.',
  },
  {
    id: 'env-file-committed', agent: 'cipher', langs: ['env'], severity: 'high', cvss: 7.5, cwe: 'CWE-538', owasp: 'A05:2021',
    category: 'Secrets Management', title: 'Environment file included in the source',
    test: (c, f) => !/\.(?:example|sample|template|dist|defaults?)$/i.test(f.path) && /^\s*[A-Z_][A-Z0-9_]*\s*=\s*\S+/m.test(c),
    line: () => 1,
    description: 'A real .env file is part of the project/repository. These typically hold production credentials.',
    impact: 'Credential exposure to anyone with repository access.',
    fix: 'Remove it from version control (git rm --cached .env), add it to .gitignore, rotate the secrets, and commit a .env.example instead.',
  },
  {
    id: 'express-no-helmet', agent: 'oracle', langs: ['js'], severity: 'low', cvss: 3.1, cwe: 'CWE-693', owasp: 'A05:2021',
    category: 'Security Misconfiguration', title: 'Express app without security headers',
    test: (c) => /\bexpress\s*\(\s*\)/.test(c) && /\.listen\s*\(/.test(c) && !/helmet|Content-Security-Policy|X-Frame-Options/i.test(c),
    line: (lines) => Math.max(1, lines.findIndex((l) => /express\s*\(\s*\)/.test(l)) + 1),
    description: 'No helmet() or manual security headers (CSP, X-Frame-Options, HSTS…) are configured.',
    impact: 'Weaker defence against XSS, clickjacking and MIME sniffing.',
    fix: 'npm i helmet and app.use(helmet()).',
  },
  {
    id: 'express-no-ratelimit', agent: 'oracle', langs: ['js'], severity: 'low', cvss: 3.7, cwe: 'CWE-307', owasp: 'A07:2021',
    category: 'Brute Force', title: 'Login route without rate limiting',
    test: (c) => /\.(?:post)\s*\(\s*["'`][^"'`]*(?:login|signin|auth|token)[^"'`]*["'`]/i.test(c) && !/rate-?limit|rateLimit|slowDown|limiter|throttle/i.test(c),
    line: (lines) => Math.max(1, lines.findIndex((l) => /\.post\s*\(\s*["'`][^"'`]*(?:login|signin|auth|token)/i.test(l)) + 1),
    description: 'Authentication endpoints accept unlimited attempts.',
    impact: 'Credential stuffing and password brute force.',
    fix: 'Add express-rate-limit (or similar) to authentication routes and lock out after repeated failures.',
  },
];
