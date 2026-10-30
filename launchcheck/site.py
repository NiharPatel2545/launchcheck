"""Passive checks of a live website: the same few requests any visitor's browser makes, plus one plain-HTTP request and one
request with an unfamiliar Origin header. Nothing is probed, guessed or attacked."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from launchcheck.findings import Finding
from launchcheck.secrets import scan_text

LIB_URL = [                                     # library name and version from common CDN addresses
    re.compile(r"/(?:npm/)?(@?[\w.-]+(?:/[\w.-]+)?)@(\d+\.\d+\.\d+)"),                      # jsdelivr, unpkg
    re.compile(r"/ajax/libs/([\w.-]+)/(\d+\.\d+\.\d+)/"),                                  # cdnjs
    re.compile(r"code\.jquery\.com/(jquery)-(\d+\.\d+\.\d+)"),
]
HEAD = r"(?:/\*!?|^[ \t]*\*)[ \t]*"            # a library's own header comment line
LIB_BANNER = [                                  # version banners that libraries keep in their minified files
    ("jquery", re.compile(HEAD + r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)", re.M)),
    ("bootstrap", re.compile(HEAD + r"Bootstrap v(\d+\.\d+\.\d+)", re.M)),
    ("angular", re.compile(HEAD + r"AngularJS v(1\.\d+\.\d+)", re.M)),
    ("lodash", re.compile(HEAD + r"(?:@license\s+)?Lodash (?:<https://lodash\.com/>\s+)?v?(\d+\.\d+\.\d+)|" + HEAD + r"lodash(?:\.min)?\.js v?(\d+\.\d+\.\d+)", re.M | re.I)),
    ("moment", re.compile(r"^//! moment\.js\s*\n//! version : (\d+\.\d+\.\d+)", re.M)),
    ("handlebars", re.compile(HEAD + r"handlebars v(\d+\.\d+\.\d+)", re.M | re.I)),
    ("dompurify", re.compile(HEAD + r"@license DOMPurify (\d+\.\d+\.\d+)", re.M)),
]
DYNAMIC_HOSTS = ("googletagmanager.com", "google-analytics.com", "js.stripe.com", "maps.googleapis.com", "www.google.com",
                 "www.gstatic.com", "challenges.cloudflare.com", "static.cloudflareinsights.com", "connect.facebook.net",
                 "fonts.googleapis.com", "js.hs-scripts.com", "plausible.io", "cdn.cookielaw.org", "hcaptcha.com", "paypal.com",
                 "clerk.com", "accounts.dev", "posthog.com", "intercom.io", "intercomcdn.com", "crisp.chat")
CDN_NAMES = {"jquery": "jquery", "twitter-bootstrap": "bootstrap", "angular.js": "angular", "lodash.js": "lodash", "moment.js": "moment"}
PRIVATE_IP = re.compile(r"(?<![\d.])(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
LLM_FROM_BROWSER = re.compile(r"api\.openai\.com/v1|api\.anthropic\.com/v1|anthropic-dangerous-direct-browser-access|dangerouslyAllowBrowser\s*:\s*!?0?true|generativelanguage\.googleapis\.com/v1|api\.groq\.com/openai")

UA = "launchcheck/0.1 (passive security check; +https://github.com/NiharPatel2545/launchcheck)"
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
        self.sri, self.forms, self.passwords = [], [], 0       # (src, has integrity) for scripts and stylesheets; form actions

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
            self.sri.append((a["src"], bool(a.get("integrity"))))
        if tag == "link" and a.get("href") and "stylesheet" in (a.get("rel") or ""):
            self.sri.append((a["href"], bool(a.get("integrity"))))
        if tag == "form":
            self.forms.append(a.get("action") or "")
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.passwords += 1
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


def libraries(urls: list[str], bodies: list[str]) -> set[tuple[str, str]]:
    """(npm name, version) of well-known front-end libraries seen in script addresses or file banners."""
    found = set()
    for u in urls:
        for rx in LIB_URL:
            m = rx.search(u)
            if m:
                found.add((CDN_NAMES.get(m.group(1), m.group(1)), m.group(2)))
                break
    for b in bodies:
        for name, rx in LIB_BANNER:
            m = rx.search(b[:300_000])
            if m:
                found.add((name, next(g for g in m.groups() if g)))
    return found


def check_libraries(urls: list[str], bodies: list[str], where: str, query=None) -> list[Finding]:
    libs = sorted(libraries(urls, bodies))
    if not libs:
        return []
    from launchcheck.repo import osv_query
    try:
        ids = (query or osv_query)([("npm", n, v, where) for n, v in libs])
    except Exception:
        return []
    return [Finding("vulnerable-library", f"{n} {v} in the page has {len(vs)} known vulnerabilit{'y' if len(vs) == 1 else 'ies'}",
                    "high" if len(vs) >= 3 else "medium",
                    "Old front-end libraries have public exploits (often cross-site scripting) that work on any site still loading them.",
                    f"Upgrade {n} to its latest version and redeploy. Details: " + ", ".join(f"https://osv.dev/vulnerability/{x}" for x in vs[:3]),
                    where, ", ".join(vs[:6])) for (n, v), vs in zip(libs, ids) if vs]


def check_page(final: str, html: str, page: _Page, bodies: list[str]) -> list[Finding]:
    """Checks on what the page itself contains: forms, outside scripts without integrity hashes, internal addresses,
    calls to AI providers straight from the browser."""
    out = []
    u = urlparse(final)
    host, https = u.hostname, u.scheme == "https"
    from launchcheck.dnsmail import registrable
    missing = []
    for src, has_sri in page.sri:
        full = urljoin(final, src)
        h = urlparse(full).hostname
        if (h and h != host and urlparse(full).scheme in ("http", "https") and not has_sri and not full.split("?")[0].endswith(".css")
                and not h.endswith(DYNAMIC_HOSTS) and registrable(h) != registrable(host or "")):
            missing.append(full)
    if missing:
        out.append(Finding("sri-missing", f"{len(missing)} outside script{'s' if len(missing) > 1 else ''} loaded without an integrity hash", "low",
                           "If that CDN or host is ever hacked, the changed file runs on your site with full access to your visitors.",
                           'Add integrity="sha384-..." crossorigin="anonymous" to each tag (cdnjs and jsdelivr show the hash), '
                           "or host the files yourself. Scripts that change by design (analytics, Stripe, reCAPTCHA) can't take a hash.",
                           final, ", ".join(missing[:3]) + (" …" if len(missing) > 3 else "")))
    for action in page.forms:
        if action.startswith("http://"):
            out.append(Finding("form-insecure", "A form sends its data over plain HTTP", "high" if page.passwords else "medium",
                               "Whatever is typed into it travels unencrypted.", "Point the form's action at an https:// address.", final, action))
    if page.passwords and not https and not _local(host or ""):
        out.append(Finding("password-over-http", "Password field on a page without HTTPS", "high",
                           "Passwords typed here can be read by anyone on the same network.", "Serve the page over HTTPS.", final))
    ips = sorted(set(PRIVATE_IP.findall(html + "\n".join(bodies))))
    if ips:
        out.append(Finding("internal-address", "Internal network addresses in the page or its scripts", "low",
                           "Private IP addresses reveal how your internal network is laid out, which helps an attacker who gets a foothold.",
                           "Remove internal addresses and debug settings from the production build.", final, ", ".join(ips[:5])))
    if any(LLM_FROM_BROWSER.search(b) for b in [html, *bodies]):
        out.append(Finding("llm-from-browser", "The browser calls an AI provider directly", "high",
                           "Calling OpenAI, Anthropic, Google or Groq from browser code means the API key is in the browser too: anyone "
                           "can copy it and run up your bill.",
                           "Call the AI provider from your own backend (a server route or edge function) that holds the key, and have "
                           "the browser call that route, with a per-user rate limit.", final))
    return out


def check_site(url: str, session: requests.Session | None = None, query=None, deep: bool = False) -> tuple[list[Finding], dict]:
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
    scanned, bodies = 0, []
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
        bodies.append(body)
        out += scan_text(body, full, public=True)
        if re.search(r"//# sourceMappingURL=(?!data:)", body):
            out.append(Finding("source-map", "JavaScript source maps are linked", "info",
                               "Source maps let anyone read your original front-end source. Fine if it holds no secrets; some teams prefer not to publish them.",
                               "Do not deploy .map files, or restrict them, if you do not want the source public.", full))
    info["scripts_scanned"] = scanned
    out += check_page(final, html, page, bodies)
    out += check_libraries([urljoin(final, x) for x in page.scripts], bodies, final, query)
    out += _security_txt(s, final)
    if deep:                                       # only on a site the user has proved is theirs
        from launchcheck.verified import check_verified, how_to_verify, is_verified
        verified = is_verified(final, s)
        info["verified_owner"] = verified
        out += check_verified(final, s) if verified else [how_to_verify(final)]
    if https and not _local(host or ""):
        from launchcheck.dnsmail import check_domain
        from launchcheck.tls import check_tls
        out += check_tls(host, u.port or 443) + check_domain(host)
    return out, info


def _security_txt(s, final: str) -> list[Finding]:
    """security.txt (RFC 9116) is a public file meant to be fetched: it says where to report a security problem."""
    try:
        r = _get(s, urljoin(final, "/.well-known/security.txt"), allow_redirects=True)
        if r.status_code == 200 and "contact:" in r.text.lower() and "<html" not in r.text[:500].lower():
            return []
    except requests.RequestException:
        return []
    return [Finding("security-txt-missing", "No security.txt", "info",
                    "People who find a security problem have no clear way to tell you, so reports go nowhere or go public.",
                    "Publish /.well-known/security.txt with at least:\nContact: mailto:security@yourdomain.com\n"
                    "Expires: 2027-12-31T00:00:00.000Z", urljoin(final, "/.well-known/security.txt"))]
