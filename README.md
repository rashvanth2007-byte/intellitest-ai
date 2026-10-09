# IntelliTest AI

Multi-agent security scanner for source code. Upload files, a whole folder or a **.zip**, paste a snippet, or give a **GitHub repository URL** — IntelliTest finds vulnerabilities and tells you exactly how to fix them.

Runs three ways from one codebase:

| Mode | Command | Data |
|---|---|---|
| **Localhost** | `npm run dev` → http://localhost:5173 | SQLite in `./data` |
| **Windows app** | `npm run build:win` → `desktop/dist/IntelliTest-AI-Setup-1.0.0.exe` | SQLite in `%APPDATA%\IntelliTest AI` |
| **Cloud** | Docker → Render (free) + Neon Postgres (free) — see [DEPLOY.md](DEPLOY.md) | PostgreSQL |

## What it checks

Every scan runs four engines, then merges, de-duplicates and scores the results (A–F, 0–100):

1. **Rule engine (offline)** — 80+ rules across JS/TS, Python, PHP, Java/Kotlin, Go, Ruby, C#, C/C++, shell, HTML/templates, Dockerfiles, Kubernetes/GitHub Actions YAML and Terraform: SQL/NoSQL/command/code injection, XSS, SSRF, XXE, path traversal, open redirect, insecure deserialization, SSTI, prototype pollution, mass assignment, weak crypto/hashes/RNG, JWT misuse, TLS verification off, debug mode, permissive CORS, CSRF disabled, leaked stack traces, CI/CD expression injection, privileged containers, public cloud storage, buffer overflows, format strings, ReDoS and more. Each finding has CWE, OWASP Top-10 category, CVSS, exact `file:line`, code snippet and a fix.
2. **Secret scanner** — 30 provider formats (AWS, GitHub, Stripe, Google, Slack, OpenAI, Anthropic, private keys, DB URLs with passwords…) plus entropy-checked generic credentials. Secret values are masked everywhere and **redacted before code is sent to any AI provider**.
3. **Dependency CVEs** — parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json`, `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pom.xml`, `build.gradle`, `*.csproj` and checks every package against [OSV.dev](https://osv.dev) (GitHub Advisories, PyPA, RustSec, Go vulndb…). Real CVSS scores, fixed versions, dev-only dependencies de-prioritised.
4. **Five AI agents** (optional, Claude or Gemini) — SENTINEL (injection/auth), PHANTOM (runtime & logic), CIPHER (secrets/crypto/config), NEXUS (supply chain/infra), ORACLE (API & data exposure). Files are ranked by security relevance and chunked, so large projects are covered by priority instead of truncated. Agent output is schema-validated and any finding pointing at a file that wasn't scanned is discarded (hallucination guard).

Live progress streams to the UI (Server-Sent Events). Reports export as **HTML, JSON, SARIF 2.1** (GitHub Code Scanning) and **CSV**.

## Accounts

- Email + password (bcrypt, rate-limited, CSRF-protected, HttpOnly session cookie).
- **Sign in with GitHub** (OAuth) — optional `repo` scope to scan private repositories.
- Every scan, finding and API key is private to its user. API keys are stored AES-256-GCM encrypted and never returned to the browser.

## Quick start (localhost)

Requires **Node.js 22.13+** (uses the built-in `node:sqlite`, so there are no native modules to compile).

```bash
npm install
```

```bash
npm run dev
```

Open http://localhost:5173, create an account, and scan. Without an AI key the rule, secret and CVE engines still run; add an Anthropic or Gemini key in **Settings** to enable the agents.

Production-style single server (serves the built UI on port 8787):

```bash
npm run build
```

```bash
npm start
```

Configuration lives in `.env` (copy `.env.example`); everything is optional for local use.

## Windows desktop app

```bash
npm run build:win
```

Produces `desktop/dist/IntelliTest-AI-Setup-1.0.0.exe` (NSIS installer with desktop + Start-menu shortcuts). The app runs the same server privately on `127.0.0.1`, keeps data in `%APPDATA%\IntelliTest AI\data`, and works offline (rules + secrets; CVE lookup and AI need internet). Optional server-wide keys and GitHub OAuth go in **File → Edit configuration**. The installer is unsigned, so Windows SmartScreen will show "More info → Run anyway" until you sign it with a code-signing certificate.

## Tests

```bash
npm test
```

The test suite covers every rule against vulnerable and safe samples, secret masking, lockfile parsing, CVSS maths, zip-slip and zip-bomb rejection, result normalisation/de-duplication, and full API flows (register/login/CSRF/password change and session revocation/paste scan/multipart upload/reports/user isolation). The API tests also pass against PostgreSQL: set `TEST_DATABASE_URL`.

## Project layout

```
server/   Express API, auth, scan pipeline, engines, reports (Node ESM)
  src/engines/rules/catalog.js   the rule catalogue — add rules here
  src/engines/secrets.js         secret patterns
  src/engines/deps.js            lockfile parsers + OSV client
  src/engines/ai/                Claude/Gemini providers, agents, chunker
web/      Vite single-page UI (vanilla JS modules)
desktop/  Electron wrapper + electron-builder config
```

## Bugs fixed from the prototype (`intellitest-ai.html`)

Repo URLs were never downloaded (the AI invented findings from the URL alone); only the first 7,000 characters were scanned; files were read asynchronously so fast clicks scanned nothing; same-named files overwrote each other; expanding one finding could open another (ID collision); a string CVSS from the model crashed the results view; mixed-case severities vanished from the list; the "high" alert threshold only fired if one agent found a critical; failed scans were saved as clean; the Gemini key sat in localStorage and was sent in the URL; scanned code could prompt-inject the agents; `.zip` was rejected; many languages weren't accepted.
