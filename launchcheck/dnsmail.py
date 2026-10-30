"""Domain checks from public DNS records: can someone send email pretending to be you (SPF, DMARC), who may issue certificates
for the domain (CAA), and whether the records are signed (DNSSEC). Looked up over DNS-over-HTTPS, so no extra package."""
from __future__ import annotations

import requests

from launchcheck.findings import Finding

DOH = "https://cloudflare-dns.com/dns-query"


def doh_lookup(name: str, rtype: str) -> tuple[list[str], bool]:
    """(record values, signed with DNSSEC) for one name and type."""
    r = requests.get(DOH, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=10)
    r.raise_for_status()
    j = r.json()
    num = {"TXT": 16, "MX": 15, "CAA": 257, "A": 1, "CNAME": 5}[rtype]
    if j.get("Status") == 3:
        raise LookupError("NXDOMAIN")
    vals = [a["data"].replace('" "', "").strip('"') for a in j.get("Answer", []) if a.get("type") == num]
    return vals, bool(j.get("AD"))


def registrable(host: str) -> str:
    """Rough registrable domain: www.shop.example.com -> example.com, example.co.uk stays whole."""
    parts = host.lower().strip(".").split(".")
    if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_domain(host: str, lookup=doh_lookup) -> list[Finding]:
    dom = registrable(host)
    try:
        txt, signed = lookup(dom, "TXT")
        mx, _ = lookup(dom, "MX")
        dmarc, _ = lookup("_dmarc." + dom, "TXT")
        caa, _ = lookup(dom, "CAA")
    except Exception as e:
        return [Finding("dns-unavailable", "Could not read the domain's DNS records", "info",
                        f"The DNS lookup failed ({type(e).__name__}).", "Run the scan again later.", dom)]
    out = []
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    sends = bool(mx)
    if not spf:
        out.append(Finding("email-no-spf", "No SPF record: anyone can send email as this domain", "medium" if sends else "low",
                           "Without SPF, receiving mail servers can't tell your real email from a scammer's fake invoice or "
                           "password-reset mail sent in your name.",
                           "Add a TXT record on the domain listing who sends your mail, e.g. v=spf1 include:_spf.google.com -all "
                           "(Google Workspace) or, if the domain sends no mail at all: v=spf1 -all", dom))
    elif any(t.rstrip().endswith(("+all", "?all")) for t in spf):
        out.append(Finding("email-weak-spf", "SPF record allows any sender", "medium",
                           "'+all' or '?all' tells mail servers to accept mail from anywhere, which defeats SPF.",
                           "End the SPF record with -all (or ~all while testing).", dom, spf[0]))
    dm = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if not dm:
        out.append(Finding("email-no-dmarc", "No DMARC record", "medium" if sends else "low",
                           "DMARC tells mail servers to reject mail that fails SPF/DKIM. Without it, fake mail in your name still "
                           "lands in inboxes.",
                           f"Add a TXT record at _dmarc.{dom}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{dom} "
                           "(move to p=reject once reports look clean).", "_dmarc." + dom))
    elif "p=none" in dm[0].replace(" ", "").lower():
        out.append(Finding("email-dmarc-none", "DMARC is set to monitor only (p=none)", "low",
                           "p=none collects reports but still lets spoofed mail through.",
                           "Move to p=quarantine, then p=reject, once the reports show only your own senders.", "_dmarc." + dom, dm[0]))
    if sends:
        try:
            sts, _ = lookup("_mta-sts." + dom, "TXT")
        except Exception:
            sts = []
        if not any(t.lower().startswith("v=stsv1") for t in sts):
            out.append(Finding("email-no-mta-sts", "No MTA-STS policy for incoming mail", "info",
                               "Without MTA-STS, an attacker on the network path can force mail sent to you over an unencrypted "
                               "connection and read it.",
                               f"Publish an MTA-STS policy (a TXT record at _mta-sts.{dom} plus a policy file at "
                               f"https://mta-sts.{dom}/.well-known/mta-sts.txt); Google Workspace and Microsoft 365 document the steps.",
                               "_mta-sts." + dom))
    if not caa:
        out.append(Finding("dns-no-caa", "No CAA record", "info",
                           "A CAA record limits which certificate authorities may issue certificates for your domain.",
                           f'Add a CAA record, e.g. {dom}. CAA 0 issue "letsencrypt.org" (list the CA your host uses).', dom))
    if not signed:
        out.append(Finding("dns-no-dnssec", "DNS records are not signed (DNSSEC off)", "info",
                           "DNSSEC stops attackers from forging your DNS answers. Most registrars and Cloudflare turn it on in one click.",
                           "Turn on DNSSEC at your DNS provider and add the DS record at your registrar.", dom))
    return out


# services where a DNS name pointing at a deleted app or bucket can be claimed by anyone, with the page each shows when unclaimed
TAKEOVER = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("herokudns.com", "No such app"),
    ("amazonaws.com", "NoSuchBucket"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.net", ""), ("trafficmanager.net", ""), ("blob.core.windows.net", "The specified resource does not exist"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("myshopify.com", "Sorry, this shop is currently unavailable"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("pantheonsite.io", "The gods are wise"),
    ("ghost.io", "Domain error"),
    ("readthedocs.io", "unknown to Read the Docs"),
    ("netlify.app", "Not Found - Request ID"),
    ("vercel.app", "DEPLOYMENT_NOT_FOUND"),
    ("fly.dev", ""), ("onrender.com", ""),
]


def check_takeover(host: str, body: str, lookup=doh_lookup) -> list[Finding]:
    """The scanned name points (CNAME) at a hosting service, and that service says nothing lives there any more."""
    try:
        cname, _ = lookup(host, "CNAME")
    except Exception:
        return []
    for target in cname:
        t = target.rstrip(".").lower()
        for suffix, fingerprint in TAKEOVER:
            if not t.endswith(suffix):
                continue
            try:
                lookup(t, "A")
                dangling = False
            except LookupError:
                dangling = True                    # the target name no longer exists
            except Exception:
                dangling = False
            if dangling or (fingerprint and fingerprint in body):
                return [Finding("subdomain-takeover", f"{host} points at an unclaimed {suffix} address", "high",
                                "The DNS record still sends visitors to a hosting service where your app or bucket no longer "
                                "exists. Anyone can create one with that name and serve their own page (phishing, cookie theft) "
                                "on your domain.",
                                f"Delete the CNAME record for {host}, or re-create the app/bucket at {t} so it is yours again.",
                                host, f"CNAME {t}")]
    return []
