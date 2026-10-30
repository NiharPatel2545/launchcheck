# launchcheck

A passive security check for websites and projects built fast (with AI tools, templates, no-code backends). Point it at your
site or your project folder and get a score, the problems in plain English, and the fix for each.

```
launchcheck https://yoursite.com --repo ./my-app
Score 62/100 (grade C): 1 fix now, 3 fix soon, 4 good to fix, 1 notes
  [high  ] OpenAI API key exposed to visitors  (https://yoursite.com/assets/index-3f2a.js)
  [medium] No Content-Security-Policy  (https://yoursite.com/)
  ...
Report: launchcheck-report.html
```

## What it checks

**Website** (passive: what a visitor's browser receives, plus public DNS records and ordinary TLS handshakes):
- **Keys shipped to the browser**: about 25 kinds (OpenAI, Anthropic, AWS, Stripe, GitHub, GitLab, Slack, Google OAuth, Hugging Face,
  SendGrid, Twilio, Telegram, database addresses with passwords, private keys, Supabase `service_role` ...). It follows script tags
  and ES module imports through the site's own bundles. Keys are always masked in output.
- **AI keys**: OpenAI, Anthropic, Google or Groq called straight from browser code (which means the key is in the browser).
- **Encryption**: certificate valid, for the right name and not about to expire; old TLS 1.0/1.1 still switched on; HTTPS and the
  http-to-https redirect; HSTS.
- **Email spoofing**: SPF and DMARC (can anyone send mail as your domain?), CAA, DNSSEC.
- **Content-Security-Policy**: missing, `unsafe-inline` without hashes, `unsafe-eval`, wildcard script sources (header and `<meta>`).
- **Outside scripts**: old front-end libraries with published vulnerabilities (jQuery, Bootstrap, AngularJS, Lodash, Moment ...,
  from CDN addresses and file banners, checked against [OSV](https://osv.dev)); outside scripts without integrity hashes.
- **Forms**: login or other forms that send over plain HTTP.
- **Headers and cookies**: clickjacking, nosniff, Referrer-Policy, Permissions-Policy, version numbers in Server / X-Powered-By;
  Secure, HttpOnly and SameSite on cookies; CORS that echoes any origin; mixed content.
- **Leaks**: internal network addresses and linked source maps; whether `security.txt` tells people how to report a problem.

**Deeper checks on a site you own** (`--deep`, or the tick box on the web page): exposed `.git` and `.env` files, database dumps
and backups, folder listings, open admin login pages, open redirects. These request a short fixed list of addresses, so they run
only after you prove the site is yours with a DNS TXT record or a file at `/.well-known/launchcheck.txt` (launchcheck prints the
exact value). Local addresses (localhost, `*.test`) count as yours. Each hit must match the real file's content, so single-page
apps that answer every address with their home page do not produce false alarms.

**Project folder** (`--repo`):
- Secrets in files git would commit (an ignored local `.env` is fine), and secrets removed from files but still in git history
  (last 300 commits, vendored libraries skipped).
- `.env` files committed to git, or `.env` not in `.gitignore`; secret-looking names in public env variables (`NEXT_PUBLIC_`,
  `VITE_`, `REACT_APP_` ...), which end up in the browser bundle.
- Dependencies checked against OSV for every major language: `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`,
  `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` exact pins, `Cargo.lock`, `go.sum`, `Gemfile.lock`,
  `composer.lock`.
- Risky code (Python and JavaScript/TypeScript): SQL built from strings, `eval`, shell commands with `shell=True`, `pickle` /
  `yaml.load`, certificate checks turned off, debug mode on, unescaped `innerHTML`, hard-coded JWT secrets, CORS `*`, AI SDKs used
  from the browser. Parameterised queries, escaped HTML and test files are not flagged.
- Config: Dockerfiles running as root or on `:latest`; GitHub Actions with `pull_request_target` checking out PR code, issue or
  PR text pasted into shell commands, `write-all` tokens, third-party actions not pinned to a commit; Firebase rules open to
  everyone; Supabase tables created without Row Level Security.

## What it does not do

It never guesses passwords, sends attack payloads (SQL injection, XSS), scans ports or load-tests. Those need written permission,
and dedicated tools do them better. A good score means these common mistakes are absent, not that the app is secure: it does not
test your login, your API's authorisation rules or business logic. Code findings are pattern matches: each one says "look at this
line", not "this is exploitable". Use it on sites and code you own or have permission to check.

## How accurate it is

Every check has a planted example in the test suite (a deliberately broken demo site and repo) and a safe twin that must not be
flagged. On real sites, each new check was run against well-known sites and every finding was confirmed by hand; the false alarms
that turned up (a CSS variable read as an OpenAI key, a plugin's "requires jQuery 1.3.2" note read as jQuery itself, Google Fonts
flagged for integrity hashes, a library's example key header in old git history) were fixed and are covered by the rules above.
TLS checks were confirmed on badssl.com's expired, wrong-name, self-signed, TLS 1.0 and TLS 1.1 test servers.

## Install and run (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m launchcheck https://yoursite.com --out report.html --json report.json
.\.venv\Scripts\python.exe -m launchcheck --repo C:\path\to\project
```

Exit code is 1 when there is at least one "fix now" finding, so it can gate a CI pipeline. Add `--pdf report.pdf` for a PDF copy
and `--deep` for the owner-verified checks.

### Web page

```powershell
.\.venv\Scripts\python.exe -m launchcheck serve
```

Open http://127.0.0.1:8710, paste a website (and optionally a project folder) and press **Check site**. The checklist fills in live, the findings appear below with a fix for each, and **Download PDF** saves the report.
The server listens on this computer only and answers only its own page (other websites open in your browser cannot drive it).

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
```

The tests start a deliberately vulnerable demo site and a well-configured one on localhost, and build a demo repo with a
committed `.env`, a key deleted from the code but left in history, and an old dependency. Pass marks are at the top of
`tests/test_launchcheck.py`.

## Scoring

100 minus 15 per "fix now", 7 per "fix soon", 3 per "good to fix" (the same problem counts at most twice). A 90+, B 75+, C 60+, D 40+.
