"""Pass marks (written before the first run):
1. The vulnerable demo site produces every planted problem below, and the secrets appear only masked.
2. The well-configured demo site has no high or medium findings and scores at least 90.
3. The vulnerable demo repo shows: committed .env, a secret in code, a secret only in git history, a vulnerable dependency.
Added 30 Oct 2026, before the new checks ran:
4. Every newly planted problem is found: old library and missing integrity hash, insecure form, internal address, AI called from
   the browser; in the repo: yarn.lock dependency, SQL built from input, open Firebase rules, Supabase table without RLS, risky
   GitHub workflow, root Docker image, secret in a public env variable; with deep checks: exposed .git and .env, folder listing,
   open redirect.
6. Added 30 Oct 2026 (second round), before running: missing isolation headers on the bad site, a secret found only on a
   second page reached through a link, a dangling CNAME to an unclaimed GitHub Pages site, and MTA-STS missing on a domain
   that receives mail.
5. The safe versions are not flagged: parameterised SQL, escaped innerHTML, test files, and a single-page app that answers
   every address with its home page produces no deep-check findings.
Fake keys are assembled at runtime so this file itself never contains a key-shaped string.
"""
import base64
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from launchcheck import report
from launchcheck.findings import score
from launchcheck.repo import check_repo
from launchcheck.site import check_csp, check_site

FAKE_OSV = lambda deps: [["GHSA-test-1", "GHSA-test-2"] if n in ("jinja2", "jquery", "lodash") else [] for _, n, _, _ in deps]

ANT = "sk-" + "ant-" + "x" * 40
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"


def jwt(role):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b({'role': role, 'iss': 'supabase'})}.{'s' * 43}"


BAD_JS = (f'const a="{ANT}";const b="{AWS}";const svc="{jwt("service_role")}";const anon="{jwt("anon")}";'
          'const api="http://192.168.1.20:8080";fetch("https://api.openai.com/v1/chat/completions");')
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()", "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


GOOD_PAGE = ('<html><head><script src="/app.js"></script><script src="https://cdn.jsdelivr.net/npm/vue@3.4.0/dist/vue.js" '
             'integrity="sha384-abc" crossorigin="anonymous"></script></head><body><form action="/login"><input type="password"></form></body></html>')
GH = "ghp" + "_" + "A1b2C3d4" * 4 + "Zz9Y"
ABOUT = f'<html><body><p>about us</p><script>const t="{GH}"</script></body></html>'
BAD_PAGE = ('<html><head><script src="/app.js"></script><a href="/about">About</a><a href="/logout">Log out</a><script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script>'
            '</head><body><form action="http://login.example/x"><input type="password"></form></body></html>')
BAD_FILES = {"/.git/HEAD": "ref: refs/heads/main\n", "/.env": "DATABASE_PASSWORD=hunter2\n",
             "/uploads/": "<html><title>Index of /uploads</title></html>"}


def serve(good: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if not good and self.path.startswith("/?next="):               # open redirect
                self.send_response(302); self.send_header("Location", self.path.split("=", 1)[1]); self.end_headers(); return
            if not good and self.path in BAD_FILES:
                body = BAD_FILES[self.path].encode()
                self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body); return
            if not good and self.path == "/about":                      # reached only by following a link
                body = ABOUT.encode()
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body); return
            if self.path == "/app.js":
                body, ctype = b'import { k } from "./shared/keys.js"; console.log(k)', "application/javascript"
            elif self.path == "/shared/keys.js":                      # reached only by following an ES module import
                body, ctype = ("export const k = 1" if good else BAD_JS).encode(), "application/javascript"
            else:                       # every other address gets the home page, like a single-page app
                body, ctype = (GOOD_PAGE if good else BAD_PAGE).encode(), "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            if good:
                for k, v in GOOD_HEADERS.items():
                    self.send_header(k, v)
                self.send_header("Set-Cookie", "session=1; Path=/; HttpOnly; SameSite=Lax")
            else:
                self.send_header("X-Powered-By", "Express/4.17.1")
                self.send_header("Set-Cookie", "session=abc; Path=/")
                if self.headers.get("Origin"):
                    self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                    self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


@pytest.fixture
def bad_site():
    srv, url = serve(False)
    yield url
    srv.shutdown()


@pytest.fixture
def good_site():
    srv, url = serve(True)
    yield url
    srv.shutdown()


def test_vulnerable_site_finds_every_planted_problem(bad_site):
    findings, info = check_site(bad_site, query=FAKE_OSV)
    ids = {f.id for f in findings}
    planted = {"csp-missing", "framing-allowed", "nosniff-missing", "referrer-policy-missing", "permissions-policy-missing",
               "version-disclosure", "cookie-no-httponly", "cookie-no-samesite", "cors-reflects-origin",
               "secret-anthropic-key", "secret-aws-key", "secret-supabase-service", "supabase-anon",
               "sri-missing", "vulnerable-library", "form-insecure", "internal-address", "llm-from-browser",
               "coop-missing", "secret-github-token"}
    assert planted <= ids, planted - ids
    assert next(f for f in findings if f.id == "cors-reflects-origin").severity == "high"
    dump = json.dumps([f.to_dict() for f in findings])
    assert ANT not in dump and AWS not in dump and jwt("service_role") not in dump       # secrets only ever masked
    assert info["scripts_scanned"] == 2
    assert info["pages_scanned"] == 2                                     # home + /about; /logout is never followed
    assert next(f for f in findings if f.id == "secret-github-token").where.endswith("/about")
    assert score(findings) < 40


def test_good_site_is_clean(good_site):
    findings, info = check_site(good_site, query=FAKE_OSV, deep=True)
    assert info["verified_owner"]                                         # local addresses count as owned
    serious = [f for f in findings if f.severity in ("high", "medium")]
    assert not serious, [f.title for f in serious]
    assert score(findings) >= 90


def test_csp_rules():
    assert check_csp(["default-src 'self'; script-src 'self' 'unsafe-inline'"], "x")[0].id == "csp-unsafe-inline"
    assert not check_csp(["script-src 'self' 'unsafe-inline' 'sha256-abc'"], "x")          # hashes make browsers ignore unsafe-inline
    assert {f.id for f in check_csp(["script-src *"], "x")} == {"csp-wildcard-scripts"}
    assert check_csp([], "x")[0].id == "csp-missing"
    # a strict meta policy plus a loose header policy: both are enforced, so scripts are still limited
    assert not check_csp(["frame-ancestors 'none'", "default-src 'self'; script-src 'self' 'sha256-abc'"], "x")


def git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def test_vulnerable_repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={ANT}\n")
    (tmp_path / "old.py").write_text(f'KEY = "{AWS}"\n')
    (tmp_path / "requirements.txt").write_text("jinja2==2.10\nrequests>=2\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    (tmp_path / "old.py").write_text("KEY = None\n")                       # removed from the code, still in history
    git(tmp_path, "commit", "-qam", "remove key")
    findings, info = check_repo(str(tmp_path), query=FAKE_OSV)
    ids = {f.id for f in findings}
    assert {"env-committed", "secret-anthropic-key", "secret-aws-key", "vulnerable-dependency"} <= ids, ids
    assert any(f.where == "git history" and f.id == "secret-aws-key" for f in findings)
    assert info["dependencies_checked"] == 1                               # only exact pins are looked up


def test_report_renders(bad_site):
    findings, info = check_site(bad_site, query=FAKE_OSV)
    data = report.build(bad_site, findings, info)
    html = report.to_html(data)
    assert "Fix now" in html and str(data["score"]) in html and ANT not in html
    assert json.loads(report.to_json(data))["grade"] in "ABCDF"


def test_web_page_answers_only_its_own_page():
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from launchcheck.web import app
    c = TestClient(app, base_url="http://127.0.0.1:8710")
    assert c.get("/").status_code == 200
    assert c.post("/api/scan", json={}, headers={"Origin": "http://127.0.0.1:8710"}).status_code == 422      # own page: reaches validation
    assert c.post("/api/scan", json={"url": "x"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/scan", json={"url": "x"}).status_code == 403                                         # no Origin at all
    assert TestClient(app, base_url="http://rebind.example").get("/").status_code == 403                     # DNS rebinding


def test_css_variable_is_not_an_openai_key():
    from launchcheck.secrets import scan_text
    css = 'x=get("--sk-dotnav-animation-stagger-duration");y=get("--sk-dotnav-animation-collapse-duration")'
    assert scan_text(css, "a.js", True) == []
    key = "sk-" + "proj-" + "Ab3" * 15
    assert [f.id for f in scan_text(f'k="{key}"', "a.js", True)] == ["secret-openai-key"]


def test_deep_checks_on_owned_site(bad_site):
    findings, info = check_site(bad_site, query=FAKE_OSV, deep=True)
    assert info["verified_owner"]
    ids = [f.id for f in findings]
    assert ids.count("exposed-file") == 2, [f.where for f in findings if f.id == "exposed-file"]       # .git/HEAD and .env
    assert {"directory-listing", "open-redirect"} <= set(ids)


def test_deep_checks_need_proof_of_ownership(monkeypatch, tmp_path):
    monkeypatch.setenv("LAUNCHCHECK_HOME", str(tmp_path))
    from launchcheck import verified
    monkeypatch.setattr(verified, "SECRET_FILE", tmp_path / "secret")
    assert verified.token_for("Example.com") == verified.token_for("example.com")
    nobody = lambda name, rtype: ([], False)
    assert not verified.is_verified("https://site.invalid/", lookup=nobody)
    owner = lambda name, rtype: (["v=spf1 -all", verified.token_for("site.invalid")], False)
    assert verified.is_verified("https://site.invalid/", lookup=owner)


def test_new_repo_checks(tmp_path):
    git(tmp_path, "init", "-q")
    w = lambda rel, text: ((tmp_path / rel).parent.mkdir(parents=True, exist_ok=True), (tmp_path / rel).write_text(text))
    w("yarn.lock", 'lodash@^4.17.0:\n  version "4.17.15"\n  resolved "https://registry.yarnpkg.com/lodash"\n')
    w("app.py", 'def get(cur, user_id):\n    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                'def ok(cur, ph, x):\n    cur.execute(f"INSERT INTO t (a) VALUES ({ph})", (x,))\n')
    w("web/ui.js", 'el.innerHTML = `<b>${esc(name)}</b>`; box.innerHTML = "<i>static</i>";\n')
    w("tests/test_x.py", 'cur.execute(f"SELECT * FROM t WHERE id = {x}")\n')
    w("firestore.rules", "service cloud.firestore { match /{d=**} { allow read, write: if true; } }\n")
    w("supabase/migrations/001.sql", "create table profiles (id uuid);\ncreate table notes (id uuid);\n"
                                     "alter table notes enable row level security;\n")
    w(".github/workflows/ci.yml", "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
                                  "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: some/action@v1\n")
    w("Dockerfile", "FROM node:latest\nCOPY . .\nCMD node app.js\n")
    w(".env.example", "NEXT_PUBLIC_OPENAI_API_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n")
    findings, info = check_repo(str(tmp_path), query=FAKE_OSV)
    ids = [f.id for f in findings]
    assert {"vulnerable-dependency", "code-sql-string", "firebase-open-rules", "supabase-no-rls", "gha-prt-checkout",
            "gha-unpinned", "docker-root", "docker-latest", "public-env-secret"} <= set(ids), set(ids)
    assert ids.count("code-sql-string") == 1                               # parameterised query and test file not flagged
    assert "code-html-injection" not in ids                                # escaped and static HTML not flagged
    assert [f.evidence for f in findings if f.id == "supabase-no-rls"] == ["profiles"]
    assert [f.evidence for f in findings if f.id == "public-env-secret"] == ["NEXT_PUBLIC_OPENAI_API_KEY"]


def test_email_and_tls_rules():
    from launchcheck.dnsmail import check_domain, registrable
    from launchcheck.tls import cert_days_left
    from datetime import datetime, timezone
    assert registrable("www.shop.example.co.uk") == "example.co.uk" and registrable("www.example.com") == "example.com"
    bare = lambda name, rtype: ([], False)
    assert {f.id for f in check_domain("www.example.com", bare)} == {"email-no-spf", "email-no-dmarc", "dns-no-caa", "dns-no-dnssec"}
    good = {("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"], ("example.com", "MX"): ["1 smtp.google.com."],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"], ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
            ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=1"]}
    assert check_domain("example.com", lambda n, t: (good.get((n, t), []), True)) == []
    weak = dict(good); weak[("example.com", "TXT")] = ["v=spf1 +all"]; weak[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=none"]
    assert {f.id for f in check_domain("example.com", lambda n, t: (weak.get((n, t), []), True))} == {"email-weak-spf", "email-dmarc-none"}
    no_sts = dict(good); del no_sts[("_mta-sts.example.com", "TXT")]
    assert {f.id for f in check_domain("example.com", lambda n, t: (no_sts.get((n, t), []), True))} == {"email-no-mta-sts"}
    assert cert_days_left("Jan 10 00:00:00 2027 GMT", datetime(2027, 1, 1, tzinfo=timezone.utc)) == 9


def test_subdomain_takeover():
    from launchcheck.dnsmail import check_takeover

    def dns(gone):
        def lookup(name, rtype):
            if rtype == "CNAME":
                return (["old-docs.github.io."] if name == "docs.example.com" else []), False
            if gone:
                raise LookupError("NXDOMAIN")
            return ["185.199.108.153"], False
        return lookup
    unclaimed = "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"
    assert [f.id for f in check_takeover("docs.example.com", unclaimed, dns(False))] == ["subdomain-takeover"]
    assert [f.id for f in check_takeover("docs.example.com", "", dns(True))] == ["subdomain-takeover"]      # target deleted
    assert check_takeover("docs.example.com", "<h1>Our docs</h1>", dns(False)) == []                        # still claimed
    assert check_takeover("www.example.com", unclaimed, dns(False)) == []                                   # no CNAME
