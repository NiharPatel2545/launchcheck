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

**Website** (passive: the requests a visitor's browser makes, plus one plain-HTTP request and one request with an unknown Origin):
- API keys and tokens shipped to the browser: OpenAI, Anthropic, AWS, Stripe secret, GitHub, Slack, private keys, Supabase
  `service_role`. It follows script tags and ES module imports through the site's own bundles. Keys are always masked in output.
- Supabase anon key in the page: flagged as a note to confirm Row Level Security is on.
- HTTPS and the http-to-https redirect, HSTS.
- Content-Security-Policy, including `unsafe-inline` without hashes, `unsafe-eval` and wildcard script sources. Both header and
  `<meta>` policies are read.
- Clickjacking protection, nosniff, Referrer-Policy, Permissions-Policy, version numbers in Server / X-Powered-By.
- Cookie flags: Secure, HttpOnly on session cookies, SameSite.
- CORS that echoes any origin (worst with credentials).
- Scripts and styles loaded over plain HTTP on an HTTPS page.

**Project folder** (`--repo`):
- Secrets in files, and secrets removed from files but still in git history (last 300 commits).
- `.env` files committed to git, or `.env` not in `.gitignore`.
- Exactly pinned dependencies (`requirements*.txt`, `package-lock.json`, exact versions in `package.json`) checked against the
  free [OSV](https://osv.dev) vulnerability database.

## What it does not do

It never guesses passwords, fuzzes, probes for hidden files or tries an exploit. A good score means these common mistakes are
absent, not that the app is secure: it does not test your login, your API's authorisation rules or your database policies.
Use it on sites and code you own or have permission to check.

## Install and run (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m launchcheck https://yoursite.com --out report.html --json report.json
.\.venv\Scripts\python.exe -m launchcheck --repo C:\path\to\project
```

Exit code is 1 when there is at least one "fix now" finding, so it can gate a CI pipeline.

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
