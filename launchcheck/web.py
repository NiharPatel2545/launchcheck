"""Local web page for launchcheck: `launchcheck serve`, then open http://127.0.0.1:8710.
Listens on this computer only (127.0.0.1), because the folder check reads files from your disk."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from launchcheck import localguard, report
from launchcheck.repo import check_repo
from launchcheck.site import check_site

app = FastAPI(title="launchcheck", docs_url=None, redoc_url=None, openapi_url=None)
localguard.install(app)
HISTORY: list[dict] = []          # last scans this session, newest first (memory only)


class ScanRequest(BaseModel):
    url: str = Field("", max_length=2000)
    repo: str = Field("", max_length=500)


@app.post("/api/scan")
async def scan(req: ScanRequest) -> dict:
    url, repo = req.url.strip(), req.repo.strip()
    if not url and not repo:
        raise HTTPException(422, "Enter a website, a project folder, or both.")
    if url:
        url = url if "://" in url else "https://" + url
        if urlparse(url).scheme not in ("http", "https") or not urlparse(url).hostname:
            raise HTTPException(422, "That does not look like a website address.")
    findings, info = [], {}
    if url:
        f, i = await asyncio.to_thread(check_site, url)
        findings += f; info["site"] = i
    if repo:
        f, i = await asyncio.to_thread(check_repo, repo)
        findings += f; info["repo"] = i
    data = report.build(" + ".join(x for x in (url, repo) if x), findings, info)
    HISTORY.insert(0, {"target": data["target"], "score": data["score"], "grade": data["grade"], "checked_at": data["checked_at"]})
    del HISTORY[10:]
    return {"summary": {k: data[k] for k in ("target", "score", "grade", "counts")}, "html": report.to_html(data)}


@app.get("/api/history")
def history() -> list[dict]:
    return HISTORY


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>launchcheck</title><style>
:root{--bg:#f7f7f4;--card:#fff;--ink:#16190f;--mut:#5b6155;--line:#e2e4dc;--acc:#2f6f2a;--on:#fff;--bad:#c0392b}
@media(prefers-color-scheme:dark){:root{--bg:#0f120e;--card:#171b16;--ink:#eef0ea;--mut:#a3aa9c;--line:#2a3027;--acc:#8fd16a;--on:#0f120e;--bad:#ef6f5e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 48px}h1{margin:0;font-size:30px}p.mut{color:var(--mut);margin:4px 0 20px}
form{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;display:grid;gap:12px}
label{font-size:14px;color:var(--mut);display:grid;gap:6px}input{font:inherit;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--ink)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}button{font:inherit;font-weight:600;padding:12px 22px;border:0;border-radius:999px;background:var(--acc);color:var(--on);cursor:pointer}
button:disabled{opacity:.6;cursor:progress}.err{color:var(--bad)}#hist{margin-top:14px;font-size:14px;color:var(--mut)}#hist button{background:none;color:var(--acc);padding:0;font-weight:500}
iframe{width:100%;height:80vh;border:1px solid var(--line);border-radius:16px;margin-top:18px;background:var(--card)}
</style></head><body><main>
<h1>launchcheck</h1><p class="mut">A passive security check for your website and project folder: exposed keys, missing headers, open CORS, weak CSP, vulnerable packages.</p>
<form id="f"><label>Website<input id="url" placeholder="https://yoursite.com" autocomplete="url"></label>
<label>Project folder on this computer (optional)<input id="repo" placeholder="C:\\path\\to\\your\\project"></label>
<div class="row"><button id="go">Run the check</button><span id="st" aria-live="polite"></span></div>
<p style="margin:0;font-size:13px;color:var(--mut)">Only check sites and code you own or have permission to test. Nothing is attacked: it makes the requests a normal visitor's browser makes.</p></form>
<div id="hist"></div><iframe id="out" title="Report" hidden></iframe>
<script>
const $ = s => document.querySelector(s), esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c])
async function hist(){ const h = await (await fetch('/api/history')).json()
  $('#hist').innerHTML = h.length ? 'Earlier this session: ' + h.map(x => `<span>${esc(x.target)} <b>${x.score}</b></span>`).join(' · ') : '' }
$('#f').addEventListener('submit', async e => { e.preventDefault(); const b = $('#go'); b.disabled = true; $('#st').className=''; $('#st').textContent = 'Checking… (about 10 seconds)'
  try { const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url: $('#url').value, repo: $('#repo').value})})
    const d = await r.json(); if (!r.ok) throw new Error(d.detail?.[0]?.msg || d.detail || 'The check failed.')
    const c = d.summary.counts; $('#st').textContent = `Score ${d.summary.score}/100 (grade ${d.summary.grade}): ${c.high} fix now, ${c.medium} fix soon, ${c.low} good to fix`
    $('#out').srcdoc = d.html; $('#out').hidden = false; hist()
  } catch(err) { $('#st').className = 'err'; $('#st').textContent = err.message } finally { b.disabled = false } })
hist()
</script></main></body></html>"""


def serve(port: int = 8710) -> None:
    import socket
    import uvicorn
    with socket.socket() as probe:                     # say so plainly if something already uses the port
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            print(f"Port {port} is already in use: launchcheck may already be running at http://127.0.0.1:{port}. "
                  f"Close the other window, or pick another port with --port.")
            return
    print(f"launchcheck is running: open http://127.0.0.1:{port}  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
