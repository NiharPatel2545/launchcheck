"""Encryption checks: the site's certificate (valid, right name, not about to expire) and whether old TLS 1.0/1.1 is still
switched on. Ordinary TLS handshakes, the same any browser makes."""
from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

from launchcheck.findings import Finding

TIMEOUT = 10


def cert_days_left(not_after: str, now: datetime | None = None) -> int:
    """Days until a certificate's notAfter date (as Python's ssl module formats it), negative once expired."""
    end = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return (end - (now or datetime.now(timezone.utc))).days


def _trusted() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _handshake(host: str, port: int, ctx: ssl.SSLContext):
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version()


def _old_tls_accepted(host: str, port: int) -> str | None:
    with warnings.catch_warnings():                # the TLSv1 names are deprecated; we use them only to test for them
        warnings.simplefilter("ignore", DeprecationWarning)
        versions = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
    for name, ver in versions:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")             # let this client offer the old versions at all
            ctx.minimum_version = ctx.maximum_version = ver
            _handshake(host, port, ctx)
            return name
        except (ssl.SSLError, OSError, ValueError):
            continue
    return None


def check_tls(host: str, port: int = 443) -> list[Finding]:
    where = f"{host}:{port}"
    try:
        cert, version = _handshake(host, port, _trusted())
    except ssl.SSLCertVerificationError as e:
        reason = e.verify_message or str(e)
        if "expired" in reason:
            title = "The certificate has expired"
        elif "hostname" in reason.lower() or "match" in reason.lower():
            title = "The certificate is for a different name"
        else:
            title = "The certificate is not trusted"
        return [Finding("tls-cert-invalid", title, "high",
                        "Browsers show a full-page security warning, and visitors who click through can't tell your site from an impostor.",
                        "Renew or reissue the certificate for this exact name (Let's Encrypt is free; most hosts do it automatically) and "
                        "serve the full chain.", where, reason)]
    except (OSError, ssl.SSLError):
        old = _old_tls_accepted(host, port)       # a server that speaks only old TLS fails the modern handshake
        if old:
            return [Finding("tls-old-version", f"The site only offers old {old}", "high",
                            f"Current browsers refuse {old}, so most visitors can't open the site at all, and it has known weaknesses.",
                            "Turn on TLS 1.2 and 1.3 at your host or web server and turn off 1.0/1.1.", where)]
        return []                                  # no TLS on this port; the HTTPS check reports that
    out = []
    days = cert_days_left(cert["notAfter"])
    if days < 14:
        out.append(Finding("tls-cert-expiring", f"The certificate expires in {days} days", "medium" if days >= 3 else "high",
                           "When it lapses every visitor gets a security warning.",
                           "Renew it now and turn on automatic renewal.", where, cert["notAfter"]))
    old = _old_tls_accepted(host, port)
    if old:
        out.append(Finding("tls-old-version", f"Old {old} is still switched on", "medium",
                           f"{old} has known weaknesses and every current browser has dropped it; leaving it on only helps attackers "
                           "force a weaker connection.",
                           "Allow TLS 1.2 and 1.3 only (Cloudflare: SSL/TLS > Edge Certificates > Minimum TLS Version = 1.2; "
                           "nginx: ssl_protocols TLSv1.2 TLSv1.3;).", where))
    return out
