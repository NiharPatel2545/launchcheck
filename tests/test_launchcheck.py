"""Pass marks (written before the first run):
1. The vulnerable demo site produces every planted problem below, and the secrets appear only masked.
2. The well-configured demo site has no high or medium findings and scores at least 90.
3. The vulnerable demo repo shows: committed .env, a secret in code, a secret only in git history, a vulnerable dependency.
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

ANT = "sk-" + "ant-" + "x" * 40
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"


def jwt(role):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg': 'HS256', 'typ': 'JWT'})}.{b({'role': role, 'iss': 'supabase'})}.{'s' * 43}"


BAD_JS = f'const a="{ANT}";const b="{AWS}";const svc="{jwt("service_role")}";const anon="{jwt("anon")}";'
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def serve(good: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/app.js":
                body, ctype = b'import { k } from "./shared/keys.js"; console.log(k)', "application/javascript"
            elif self.path == "/shared/keys.js":                      # reached only by following an ES module import
                body, ctype = ("export const k = 1" if good else BAD_JS).encode(), "application/javascript"
            else:
                body, ctype = b'<html><head><script src="/app.js"></script></head><body>hi</body></html>', "text/html; charset=utf-8"
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
    findings, info = check_site(bad_site)
    ids = {f.id for f in findings}
    planted = {"csp-missing", "framing-allowed", "nosniff-missing", "referrer-policy-missing", "permissions-policy-missing",
               "version-disclosure", "cookie-no-httponly", "cookie-no-samesite", "cors-reflects-origin",
               "secret-anthropic-key", "secret-aws-key", "secret-supabase-service", "supabase-anon"}
    assert planted <= ids, planted - ids
    assert next(f for f in findings if f.id == "cors-reflects-origin").severity == "high"
    dump = json.dumps([f.to_dict() for f in findings])
    assert ANT not in dump and AWS not in dump and jwt("service_role") not in dump       # secrets only ever masked
    assert info["scripts_scanned"] == 2
    assert score(findings) < 40


def test_good_site_is_clean(good_site):
    findings, _ = check_site(good_site)
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
    fake_osv = lambda deps: [["GHSA-test-1", "GHSA-test-2"] if n == "jinja2" else [] for _, n, _, _ in deps]
    findings, info = check_repo(str(tmp_path), query=fake_osv)
    ids = {f.id for f in findings}
    assert {"env-committed", "secret-anthropic-key", "secret-aws-key", "vulnerable-dependency"} <= ids, ids
    assert any(f.where == "git history" and f.id == "secret-aws-key" for f in findings)
    assert info["dependencies_checked"] == 1                               # only exact pins are looked up


def test_report_renders(bad_site):
    findings, info = check_site(bad_site)
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
