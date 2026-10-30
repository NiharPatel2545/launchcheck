"""launchcheck https://yoursite.com [--repo PATH] [--out report.html] [--json report.json]"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from launchcheck import report
from launchcheck.findings import sort_findings
from launchcheck.repo import check_repo
from launchcheck.site import check_site


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["serve"]:                                  # launchcheck serve [--port 8710]: the local web page
        from launchcheck.web import serve
        port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 8710
        serve(port)
        return 0
    ap = argparse.ArgumentParser(prog="launchcheck", description="Passive security check of a website and/or a project folder.")
    ap.add_argument("url", nargs="?", help="website to check, e.g. https://example.com")
    ap.add_argument("--repo", help="local project folder to check (secrets, .env files, vulnerable dependencies)")
    ap.add_argument("--out", default="launchcheck-report.html", help="HTML report path")
    ap.add_argument("--json", help="also write the results as JSON")
    ap.add_argument("--pdf", help="also write the report as a PDF")
    a = ap.parse_args(argv)
    if not a.url and not a.repo:
        ap.error("give a URL, --repo, or both")
    findings, info = [], {}
    if a.url:
        url = a.url if "://" in a.url else "https://" + a.url
        f, i = check_site(url)
        findings += f; info["site"] = i
    if a.repo:
        f, i = check_repo(a.repo)
        findings += f; info["repo"] = i
    data = report.build(" + ".join(x for x in (a.url, a.repo) if x), findings, info)
    Path(a.out).write_text(report.to_html(data), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(report.to_json(data), encoding="utf-8")
    if a.pdf:
        from launchcheck.pdf import build_pdf
        Path(a.pdf).write_bytes(build_pdf(data))
    c = data["counts"]
    print(f"Score {data['score']}/100 (grade {data['grade']}): {c['high']} fix now, {c['medium']} fix soon, {c['low']} good to fix, {c['info']} notes")
    for f in sort_findings(findings):
        if f.severity != "info":
            print(f"  [{f.severity:6}] {f.title}" + (f"  ({f.where})" if f.where else ""))
    print(f"Report: {Path(a.out).resolve()}")
    return 1 if c["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
