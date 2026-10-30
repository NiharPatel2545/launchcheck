"""Patterns for credentials that must never ship to a browser or sit in a repo. Matches are masked before they are reported."""
from __future__ import annotations

import base64
import json
import re

from launchcheck.findings import Finding, mask

# (id, label, regex, severity). Publishable/public keys (Stripe pk_, Supabase anon) are handled separately: they are meant to be public.
PATTERNS = [
    ("anthropic-key", "Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}", "high"),
    # not after a word char or '-' (CSS variables like --sk-nav-animation-duration), and random keys always have a digit and a capital
    ("openai-key", "OpenAI API key", r"(?<![\w-])sk-(?:proj-|svcacct-|admin-)?(?=[\w-]*\d)(?=[\w-]*[A-Z])[A-Za-z0-9_\-]{32,}", "high"),
    ("aws-key", "AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("stripe-secret", "Stripe secret key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}", "high"),
    ("github-token", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high"),
    ("slack-token", "Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    ("private-key", "Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----(?:\\[rn]|[\s+\"'])+[A-Za-z0-9+/=]{40,}", "high"),
    ("google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "low"),
    ("google-oauth-secret", "Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", "high"),
    ("gitlab-token", "GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "high"),
    ("huggingface-token", "Hugging Face token", r"\bhf_[A-Za-z]{34}\b", "high"),
    ("npm-token", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b", "high"),
    ("pypi-token", "PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "high"),
    ("sendgrid-key", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high"),
    ("mailgun-key", "Mailgun API key", r"\bkey-[0-9a-f]{32}\b", "high"),
    ("twilio-key", "Twilio API key", r"\bSK[0-9a-f]{32}\b", "high"),
    ("telegram-token", "Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b", "high"),
    ("digitalocean-token", "DigitalOcean token", r"\bdo[opr]_v1_[a-f0-9]{64}\b", "high"),
    ("shopify-token", "Shopify access token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "high"),
    ("groq-key", "Groq API key", r"\bgsk_[A-Za-z0-9]{52}\b", "high"),
    ("replicate-token", "Replicate API token", r"\br8_[A-Za-z0-9]{37}\b", "high"),
    ("stripe-webhook-secret", "Stripe webhook secret", r"\bwhsec_[A-Za-z0-9]{32,}\b", "high"),
    ("azure-storage-key", "Azure storage account key", r"AccountKey=[A-Za-z0-9+/]{86}==", "high"),
    # database address with a real-looking password (not localhost, not a placeholder)
    ("database-url", "Database address with password",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://[^\s:@/'\"]+:(?!password\b|pass\b|secret\b|changeme\b|postgres\b|\$\{|<)[^\s@/'\"]{6,}@(?!(?:localhost|127\.0\.0\.1|db|postgres|mysql|redis|mongo)(?:[:/\s'\"]|$))[^\s/'\"]+",
     "high"),
]
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_COMPILED = [(i, label, re.compile(rx), sev) for i, label, rx, sev in PATTERNS]


def _jwt_role(token: str) -> str | None:
    try:
        part = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        return str(payload.get("role")) if isinstance(payload, dict) and payload.get("role") else None
    except Exception:
        return None


def scan_text(text: str, where: str, public: bool) -> list[Finding]:
    """public=True: text a browser downloads (page, JS bundle), so any server secret in it is exposed to every visitor."""
    out: list[Finding] = []
    seen: set[str] = set()
    for pid, label, rx, sev in _COMPILED:
        for m in rx.finditer(text):
            s = m.group(0)
            if s in seen:
                continue
            seen.add(s)
            line = text.count("\n", 0, m.start()) + 1
            loc = f"{where}:{line}" if not public else where
            if pid == "google-api-key":
                out.append(Finding(
                    "google-api-key", f"{label} found", "low",
                    "Google browser keys (Maps, Firebase) are often public by design, but an unrestricted key can be used by anyone on your bill.",
                    "In Google Cloud Console > Credentials, restrict this key to your website's domain and to only the APIs it needs.",
                    loc, mask(s)))
                continue
            why = ("Anyone who opens your site can read this key in the browser and use it: run up your bill, read or delete your data."
                   if public else "Anyone with a copy of the repo (or its history) can use this key. Public repos are scanned by bots within minutes.")
            out.append(Finding(
                f"secret-{pid}", f"{label} {'exposed to visitors' if public else 'in the code'}", sev, why,
                "Revoke (rotate) this key now in the provider's dashboard: assume it is already copied. Then move it to a server-side "
                "environment variable and call the provider from your backend, never from browser code. Remove it from git history "
                "(e.g. `git filter-repo`) if it was committed.",
                loc, mask(s), ["secret"]))
    for m in JWT.finditer(text):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        role = _jwt_role(tok)
        if role == "service_role":
            out.append(Finding(
                "secret-supabase-service", f"Supabase service_role key {'exposed to visitors' if public else 'in the code'}", "high",
                "The service_role key bypasses all Row Level Security: whoever has it can read, change and delete every row in your database.",
                "Rotate it in Supabase > Project Settings > API (roll the JWT secret). Use only the anon key in the browser, and keep the "
                "service_role key on your server.",
                where, mask(tok), ["secret"]))
        elif role == "anon" and public:
            out.append(Finding(
                "supabase-anon", "Supabase anon key in the page (normal, but check RLS)", "info",
                "The anon key is meant to be public. It is only safe if Row Level Security is on for every table; without RLS anyone can read your tables with it.",
                "In Supabase > Table Editor, make sure RLS is enabled on every table and each table has policies that only allow what visitors should do.",
                where, mask(tok)))
    return out
