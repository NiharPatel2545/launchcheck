"""Checks that run only on a site the user has proved they own: exposed .git and .env files, backups and database dumps,
open folder listings, open admin pages and open redirects. Ownership is proved with a DNS TXT record or a file on the site,
holding a token made from the host name and a secret kept on this computer. Local addresses (localhost, *.test) count as owned.

Single requests to a short fixed list of addresses: no guessing, no logins, no attack payloads."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from launchcheck.findings import Finding

SECRET_FILE = Path(os.environ.get("LAUNCHCHECK_HOME", Path.home() / ".launchcheck")) / "secret"
TOKEN_FILE = "/.well-known/launchcheck.txt"
UA = "launchcheck/0.1 (owner-verified check; +https://github.com/NiharPatel2545/launchcheck)"

# (path, what it is, severity, test on the body that proves it is the real thing and not a catch-all page)
EXPOSED = [
    ("/.git/HEAD", "The site's git folder", "high", re.compile(r"^ref: refs/|^[0-9a-f]{40}\s*$")),
    ("/.git/config", "The site's git config", "high", re.compile(r"^\[core\]", re.M)),
    ("/.env", "A .env file", "high", re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M)),
    ("/.env.local", "A .env.local file", "high", re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M)),
    ("/.env.production", "A .env.production file", "high", re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M)),
    ("/backup.sql", "A database dump", "high", re.compile(r"(?:CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)", re.I)),
    ("/dump.sql", "A database dump", "high", re.compile(r"(?:CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)", re.I)),
    ("/backup.zip", "A backup archive", "high", re.compile(r"^PK\x03\x04")),
    ("/.DS_Store", "A macOS folder index", "low", re.compile(r"^\x00\x00\x00\x01Bud1")),
    ("/phpinfo.php", "A phpinfo page", "medium", re.compile(r"PHP Version \d")),
    ("/server-status", "Apache's live status page", "medium", re.compile(r"Apache Server Status")),
    ("/wp-config.php.bak", "A WordPress config backup", "high", re.compile(r"DB_PASSWORD")),
    ("/config.json", "A config file", "medium", re.compile(r'"(?:password|secret|api_?key|private_?key)"\s*:\s*"[^"]{4,}"', re.I)),
]
LISTING = re.compile(r"<title>\s*Index of /|Directory listing for /", re.I)
ADMIN = ["/admin", "/wp-admin/", "/phpmyadmin/", "/adminer.php"]
REDIRECT_PARAMS = ["next", "redirect", "redirect_to", "url", "return", "returnTo"]
CANARY = "https://launchcheck-redirect-test.invalid/"


def machine_secret() -> str:
    if not SECRET_FILE.exists():
        SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        SECRET_FILE.write_text(secrets.token_hex(16), encoding="utf-8")
    return SECRET_FILE.read_text("utf-8").strip()


def token_for(host: str) -> str:
    return "launchcheck-verify=" + hashlib.sha256(f"{machine_secret()}:{host.lower()}".encode()).hexdigest()[:24]


def _local(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith((".localhost", ".test"))


def is_verified(url: str, session=None, lookup=None) -> bool:
    host = urlparse(url).hostname or ""
    if _local(host):
        return True
    tok = token_for(host)
    s = session or requests.Session()
    try:
        r = s.get(urljoin(url, TOKEN_FILE), headers={"User-Agent": UA}, timeout=10, allow_redirects=False)
        if r.status_code == 200 and tok in r.text:
            return True
    except requests.RequestException:
        pass
    try:
        from launchcheck.dnsmail import doh_lookup
        txt, _ = (lookup or doh_lookup)(host, "TXT")
        return any(tok in t for t in txt)
    except Exception:
        return False


def how_to_verify(url: str) -> Finding:
    host = urlparse(url).hostname or url
    tok = token_for(host)
    return Finding("verify-to-unlock", "Prove you own this site to unlock deeper checks", "info",
                   "Some checks (exposed .git or .env files, backups, open admin pages, open redirects) request specific addresses "
                   "on the site, so launchcheck runs them only on sites you have shown are yours.",
                   f"Either add a DNS TXT record on {host} with the value\n{tok}\nor publish a file at https://{host}{TOKEN_FILE} "
                   f"containing that line. Then run the check again with deeper checks switched on.", url)


def check_verified(url: str, session=None) -> list[Finding]:
    s = session or requests.Session()
    get = lambda path, **kw: s.get(urljoin(url, path), headers={"User-Agent": UA}, timeout=10, **kw)
    out = []
    try:
        base = get("/launchcheck-not-a-real-page-" + secrets.token_hex(4), allow_redirects=False)
        catch_all = base.status_code == 200          # single-page apps answer every address with the same page
    except requests.RequestException:
        return []
    for path, what, sev, proof in EXPOSED:
        try:
            r = get(path, allow_redirects=False, stream=True)
            body = r.raw.read(4096, decode_content=True).decode("latin-1")
        except (requests.RequestException, OSError):
            continue
        if r.status_code == 200 and proof.search(body):
            out.append(Finding("exposed-file", f"{what} can be downloaded: {path}", sev,
                               "Anyone can fetch it. Git folders rebuild your whole source code (with any keys in its history); .env "
                               "files and dumps hand over passwords and data directly.",
                               f"Block {path} at the web server (nginx: location ~ /\\. {{ deny all; }}), remove it from the deployed "
                               "folder, and rotate any secret it contained.", urljoin(url, path)))
    for folder in ("/uploads/", "/static/", "/images/", "/files/", "/backup/"):
        try:
            r = get(folder, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and LISTING.search(r.text[:3000]):
            out.append(Finding("directory-listing", f"Folder listing is switched on: {folder}", "medium",
                               "Anyone can browse every file in the folder, including ones you never linked to.",
                               "Turn off auto-index (nginx: autoindex off; Apache: Options -Indexes).", urljoin(url, folder)))
    for path in ADMIN:
        try:
            r = get(path, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code == 200 and not (catch_all and r.text == base.text) and re.search(r'type=["\']?password', r.text, re.I):
            out.append(Finding("admin-exposed", f"Admin login page is open to the internet: {path}", "low",
                               "Bots try common passwords on admin pages all day.",
                               "Put admin pages behind a VPN, an IP allowlist or single sign-on, and require two-factor login.",
                               urljoin(url, path)))
    for p in REDIRECT_PARAMS:
        try:
            r = get(f"/?{p}={CANARY}", allow_redirects=False)
        except requests.RequestException:
            continue
        if 300 <= r.status_code < 400 and r.headers.get("Location", "").startswith(CANARY):
            out.append(Finding("open-redirect", f"Open redirect through ?{p}=", "medium",
                               "Scammers send links on your trusted domain that bounce visitors to their phishing page.",
                               "Only redirect to relative paths or an allowlist of your own domains.", urljoin(url, f"/?{p}=")))
            break
    return out
