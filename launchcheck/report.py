"""Self-contained HTML report (no outside requests, works offline and as an email attachment) plus JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape

from launchcheck.findings import Finding, grade, score, sort_findings

SEV_LABEL = {"high": "Fix now", "medium": "Fix soon", "low": "Good to fix", "info": "Note"}

CSS = """
:root{--bg:#f7f7f4;--card:#fff;--ink:#16190f;--mut:#5b6155;--line:#e2e4dc;--high:#c0392b;--medium:#b9770e;--low:#2e6fa7;--info:#6b6f66;--ok:#3d7a1f}
@media(prefers-color-scheme:dark){:root{--bg:#0f120e;--card:#171b16;--ink:#eef0ea;--mut:#a3aa9c;--line:#2a3027;--high:#ef6f5e;--medium:#e3a23f;--low:#6fb0e8;--info:#9aa094;--ok:#8fd16a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}.mut{color:var(--mut)}
.top{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:24px 0}
.score{width:120px;height:120px;border-radius:50%;display:grid;place-items:center;border:8px solid var(--c);font-weight:700}
.score b{font-size:38px;line-height:1}.score span{font-size:14px;color:var(--mut)}
.counts{display:flex;gap:10px;flex-wrap:wrap}.counts div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;min-width:110px}
.counts b{display:block;font-size:22px}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c);border-radius:12px;padding:16px 18px;margin:12px 0}
.f h3{margin:0 0 6px;font-size:17px}.tag{display:inline-block;font-size:12px;font-weight:700;color:var(--c);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}
.f p{margin:6px 0}.where{font-size:13px;color:var(--mut);word-break:break-all}
pre{white-space:pre-wrap;background:var(--bg);border-radius:6px;padding:12px 14px;font:14px/1.5 inherit;font-family:inherit;margin:6px 0 0}
.ok{color:var(--ok);font-weight:600}footer{margin-top:40px;font-size:13px;color:var(--mut)}
"""


def build(target: str, findings: list[Finding], info: dict) -> dict:
    s = score(findings)
    return {"target": target, "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "score": s, "grade": grade(s),
            "counts": {k: sum(f.severity == k for f in findings) for k in ("high", "medium", "low", "info")},
            "info": info, "findings": [f.to_dict() for f in sort_findings(findings)]}


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2)


def to_html(data: dict) -> str:
    col = lambda k: f"var(--{k})"
    g = data["grade"]
    ring = col("ok") if g in "AB" else col("medium") if g in "CD" else col("high")
    fs = data["findings"]
    items = "".join(
        f'<article class="f" style="--c:{col(f["severity"])}"><span class="tag">{SEV_LABEL[f["severity"]]}</span>'
        f'<h3>{escape(f["title"])}</h3><p>{escape(f["why"])}</p>'
        f'<p><b>Fix:</b></p><pre>{escape(f["fix"])}</pre>'
        + (f'<p class="where">{escape(f["where"])}' + (f' · seen: {escape(f["evidence"])}' if f["evidence"] else "") + "</p>" if f["where"] or f["evidence"] else "")
        + "</article>" for f in fs)
    counts = "".join(f'<div style="--c:{col(k)}"><b style="color:{col(k)}">{v}</b>{SEV_LABEL[k]}</div>' for k, v in data["counts"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Launch check: {escape(data['target'])}</title><style>{CSS}</style></head><body><main>
<h1>Launch check</h1><p class="mut">{escape(data['target'])} · {escape(data['checked_at'])}</p>
<div class="top"><div class="score" style="--c:{ring}"><div style="text-align:center"><b>{data['score']}</b><br><span>grade {g}</span></div></div>
<div class="counts">{counts}</div></div>
{items or '<p class="ok">No problems found by these checks.</p>'}
<footer>Passive checks only: the requests a normal visitor's browser makes, plus one plain-HTTP and one cross-origin request. A good score means
these common mistakes are absent, not that the app is secure: it does not test your login, your API's authorisation rules or your database access rules.</footer>
</main></body></html>"""
