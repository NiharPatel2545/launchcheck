"""Passive checks of a live website: the same few requests any visitor's browser makes, plus one plain-HTTP request and one
request with an unfamiliar Origin header. Nothing is probed, guessed or attacked."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from launchcheck.findings import Finding
from launchcheck.secrets import scan_text

UA = "launchcheck/0.1 (passive security check; +https://github.com/)"
TIMEOUT = 15
MAX_SCRIPTS = 30
MAX_BYTES = 3_000_000
TEST_ORIGIN = "https://launchcheck-origin-test.invalid"
# relative or absolute paths in `import ... from "x"`, `import "x"` and `import("x")`; bare package names are skipped
IMPORT = re.compile(r"""(?:\bimport\s*(?:[\w*{}\s,$]+\s*from\s*)?|\bimport\s*\(\s*)["']((?:\.{1,2}/|/|https?://)[^"'\s]+?\.m?js)["']""")


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.resources, self.meta_csp = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag in ("script", "img", "iframe", "audio", "video", "source") and a.get("src"):
            self.resources.append((tag, a["src"]))
        if tag == "link" and a.get("href") and "stylesheet" in (a.get("rel") or ""):
            self.resources.append(("stylesheet", a["href"]))
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "content-security-policy" and a.get("content"):
            self.meta_csp.append(a["content"])


def _get(session, url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return session.get(url, headers={"User-Agent": UA, **kw.pop("headers", {})}, **kw)


def _set_cookies(resp) -> list[str]:
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return raw.getlist("Set-Cookie")
    v = resp.headers.get("Set-Cookie")
    return [v] if v else []


def _local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost") or host.endswith(".test")


def parse_csp(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), bits[1:])
    return out


def check_csp(policies: list[str], where: str) -> list[Finding]:
    if not policies:
        return [Finding("csp-missing", "No Content-Security-Policy", "medium",
                        "Without a CSP, any script that gets injected into your page (a bad dependency, a comment field, a browser extension "
                        "exploit) runs with full access to your visitors' sessions and data.",
                        "Add a Content-Security-Policy header (or <meta http-equiv> tag). Start strict and add only the hosts you use:\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                        where)]
    out = []
    # every policy is enforced, so one strict policy is enough for a directive; judge script-src on the strictest one present
    scripts = [p.get("script-src", p.get("default-src")) for p in map(parse_csp, policies)]
    scripts = [s for s in scripts if s is not None]
    if not scripts:
        out.append(Finding("csp-no-script-src", "CSP does not limit scripts", "medium",
                           "The policy has neither script-src nor default-src, so it does not stop injected scripts.",
                           "Add script-src 'self' (plus the exact script hosts you use) to the policy.", where))
    else:
        strict = [s for s in scripts if "'unsafe-inline'" not in s or any(x.startswith(("'sha", "'nonce-")) for x in s)]
        if not strict:
            out.append(Finding("csp-unsafe-inline", "CSP allows any inline script ('unsafe-inline')", "medium",
                               "'unsafe-inline' lets an injected <script> run, which removes most of what a CSP is for.",
                               "Allow your own inline scripts by hash ('sha256-...') or nonce instead of 'unsafe-inline', or move them into files.",
                               where))
        if all("'unsafe-eval'" in s for s in scripts):
            out.append(Finding("csp-unsafe-eval", "CSP allows eval ('unsafe-eval')", "low",
                               "eval() turns injected text into running code.", "Remove 'unsafe-eval' and the code that needs it.", where))
        if all(any(x in ("*", "https:", "http:", "data:") for x in s) for s in scripts):
            out.append(Finding("csp-wildcard-scripts", "CSP lets scripts load from anywhere", "medium",
                               "A wildcard source (*, https:, data:) in script-src lets an attacker load their own script from any site.",
                               "List the exact hosts you load scripts from (e.g. https://cdn.jsdelivr.net) instead of a wildcard.", where))
    return out


def check_site(url: str, session: requests.Session | None = None) -> tuple[list[Finding], dict]:
    s = session or requests.Session()
    out: list[Finding] = []
    info: dict = {"url": url}
    try:
        r = _get(s, url, allow_redirects=True)
    except requests.RequestException as e:
        return [Finding("unreachable", "Site could not be reached", "info", f"The request failed: {type(e).__name__}.",
                        "Check the URL and that the site is up.", url)], info
    final = r.url
    u = urlparse(final)
    https = u.scheme == "https"
    info.update(final_url=final, status=r.status_code, https=https)
    h = {k.lower(): v for k, v in r.headers.items()}
    html = r.text if "html" in h.get("content-type", "") else ""
    page = _Page()
    try:
        page.feed(html)
    except Exception:
        pass

    # HTTPS
    if not https and not _local(u.hostname or ""):
        out.append(Finding("no-https", "Site is served over plain HTTP", "high",
                           "Everything visitors send (logins, forms) travels unencrypted and can be read or changed on public Wi-Fi.",
                           "Serve the site over HTTPS (most hosts do it free) and redirect http:// to https://.", final))
    if https:
        try:
            plain = _get(s, final.replace("https://", "http://", 1), allow_redirects=False)
            loc = plain.headers.get("Location", "")
            if plain.status_code < 300 or plain.status_code >= 400 or not loc.startswith("https://"):
                out.append(Finding("no-https-redirect", "http:// does not redirect to https://", "medium",
                                   "Visitors who type your address without https:// stay on an unencrypted connection.",
                                   "Redirect every http:// request to https:// with a 301 (Cloudflare: 'Always Use HTTPS').",
                                   final.replace("https://", "http://", 1), f"HTTP {plain.status_code}"))
        except requests.RequestException:
            pass
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(Finding("hsts-missing", "No Strict-Transport-Security header", "medium",
                               "Without HSTS a visitor's first request can be downgraded to plain HTTP by someone on the same network.",
                               "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", final))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000:
                out.append(Finding("hsts-short", "Strict-Transport-Security max-age is short", "low",
                                   "A short HSTS lifetime gives less protection between visits.", "Use max-age=31536000 (one year).",
                                   final, hsts))

    # headers
    policies = ([h["content-security-policy"]] if "content-security-policy" in h else []) + page.meta_csp
    out += check_csp(policies, final)
    frame_ok = "x-frame-options" in h or any("frame-ancestors" in p for p in ([h.get("content-security-policy", "")]))
    if not frame_ok:
        out.append(Finding("framing-allowed", "Other sites can embed your pages in a frame", "medium",
                           "A malicious site can show your page invisibly and trick visitors into clicking buttons on it (clickjacking).",
                           "Add the header X-Frame-Options: DENY, or frame-ancestors 'none' in a Content-Security-Policy header "
                           "(frame-ancestors does not work in a <meta> tag).", final))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Finding("nosniff-missing", "No X-Content-Type-Options: nosniff", "low",
                           "Browsers may guess file types and run an uploaded file as a script.", "Add: X-Content-Type-Options: nosniff", final))
    if "referrer-policy" not in h:
        out.append(Finding("referrer-policy-missing", "No Referrer-Policy", "low",
                           "Full page addresses (which can contain tokens or search terms) leak to every site you link to.",
                           "Add: Referrer-Policy: strict-origin-when-cross-origin", final))
    if "permissions-policy" not in h:
        out.append(Finding("permissions-policy-missing", "No Permissions-Policy", "low",
                           "Embedded or injected code can ask for the camera, microphone or location.",
                           "Add a Permissions-Policy that turns off what you do not use, e.g. camera=(), microphone=(), geolocation=()", final))
    for name in ("server", "x-powered-by"):
        v = h.get(name, "")
        if re.search(r"\d+\.\d+", v):
            out.append(Finding("version-disclosure", f"{name.title()} header reveals software versions", "low",
                               "Version numbers tell attackers exactly which known bugs to try.",
                               f"Remove or shorten the {name} header (Express: app.disable('x-powered-by')).", final, f"{name}: {v}"))

    # cookies
    for c in _set_cookies(r):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        sensitive = bool(re.search(r"sess|auth|token|sid|jwt|login", name, re.I))
        if https and "secure" not in [p.strip() for p in low.split(";")]:
            out.append(Finding("cookie-no-secure", f"Cookie '{name}' is missing Secure", "medium" if sensitive else "low",
                               "The cookie can be sent over plain HTTP and read on the way.", "Set the Secure flag on the cookie.", final))
        if sensitive and "httponly" not in low:
            out.append(Finding("cookie-no-httponly", f"Cookie '{name}' is missing HttpOnly", "medium",
                               "Any injected script can read this login/session cookie and take over the account.",
                               "Set the HttpOnly flag on session and auth cookies.", final))
        if "samesite" not in low:
            out.append(Finding("cookie-no-samesite", f"Cookie '{name}' has no SameSite", "low",
                               "Other sites can make requests that carry this cookie (cross-site request forgery).",
                               "Set SameSite=Lax (or Strict) on the cookie.", final))

    # CORS: one request with an origin the site cannot know
    try:
        cr = _get(s, final, headers={"Origin": TEST_ORIGIN}, allow_redirects=False)
        acao, acac = cr.headers.get("Access-Control-Allow-Origin", ""), cr.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == TEST_ORIGIN:
            out.append(Finding("cors-reflects-origin", "CORS allows any website" + (" with cookies" if acac else ""),
                               "high" if acac else "medium",
                               "The server copies back whatever Origin it is sent, so any website can read responses from it"
                               + (" using your visitors' logged-in session." if acac else "."),
                               "Allow only your own front-end origins (an exact list), never echo the Origin header back.", final,
                               f"Access-Control-Allow-Origin: {acao}" + ("; Allow-Credentials: true" if acac else "")))
        elif acao == "*" and acac:
            out.append(Finding("cors-wildcard-credentials", "CORS wildcard with credentials", "high",
                               "A wildcard origin combined with credentials is a misconfiguration that some servers turn into 'allow everyone'.",
                               "Use an exact list of allowed origins.", final))
    except requests.RequestException:
        pass

    # mixed content
    if https:
        for tag, src in page.resources:
            if src.startswith("http://"):
                active = tag in ("script", "stylesheet", "iframe")
                out.append(Finding("mixed-content", f"Page loads a {tag} over plain HTTP", "medium" if active else "low",
                                   "Browsers block or warn on insecure content, and an insecure script can be swapped on the way.",
                                   "Load it over https:// (or host it yourself).", final, src))

    # secrets in what the browser downloads
    out += scan_text(html, final, public=True)
    host = u.hostname
    scanned = 0
    # script tags, then ES module imports found in the page and in each bundle (Vite/Next/plain modules load code this way)
    queue = [urljoin(final, src) for src in page.scripts] + [urljoin(final, m) for m in IMPORT.findall(html)]
    done: set[str] = set()
    while queue and scanned < MAX_SCRIPTS:
        full = queue.pop(0)
        if full in done or urlparse(full).hostname != host:
            continue                      # only this site's own bundles, not public CDNs
        done.add(full)
        scanned += 1
        try:
            js = _get(s, full, stream=True)
            body = js.raw.read(MAX_BYTES, decode_content=True).decode("utf-8", "replace")
        except Exception:
            continue
        queue += [urljoin(full, m) for m in IMPORT.findall(body)]
        out += scan_text(body, full, public=True)
        if re.search(r"//# sourceMappingURL=(?!data:)", body):
            out.append(Finding("source-map", "JavaScript source maps are linked", "info",
                               "Source maps let anyone read your original front-end source. Fine if it holds no secrets; some teams prefer not to publish them.",
                               "Do not deploy .map files, or restrict them, if you do not want the source public.", full))
    info["scripts_scanned"] = scanned
    return out, info
