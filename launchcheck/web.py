"""Local web page for launchcheck: `launchcheck serve`, then open http://127.0.0.1:8710.
Listens on this computer only (127.0.0.1), because the folder check reads files from your disk."""
from __future__ import annotations

import asyncio
import uuid
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from launchcheck import localguard, report
from launchcheck.repo import check_repo
from launchcheck.site import check_site

app = FastAPI(title="launchcheck", docs_url=None, redoc_url=None, openapi_url=None)
localguard.install(app)
SCANS: dict[str, dict] = {}          # recent scans this session, for the PDF download (memory only, last 20)

# what the page lists, and which finding ids belong to each row ("site" rows need a URL, "repo" rows a folder)
CHECKS = [
    ("secrets", "Keys in public code", "API keys, tokens and private keys a visitor's browser can read", "both", ("secret-",)),
    ("https", "HTTPS", "Encrypted connection, and http:// sent on to https://", "site", ("no-https",)),
    ("hsts", "Strict transport", "Browsers told to always use HTTPS", "site", ("hsts-",)),
    ("csp", "Content-Security-Policy", "Injected scripts blocked", "site", ("csp-",)),
    ("framing", "Clickjacking", "Other sites cannot frame your pages", "site", ("framing-",)),
    ("headers", "Safety headers", "nosniff, Referrer-Policy, Permissions-Policy", "site", ("nosniff-", "referrer-", "permissions-")),
    ("cookies", "Cookie flags", "Secure, HttpOnly and SameSite on cookies", "site", ("cookie-",)),
    ("cors", "Cross-site access", "CORS does not let any website read your data", "site", ("cors-",)),
    ("mixed", "Mixed content", "Nothing loaded over plain HTTP", "site", ("mixed-content",)),
    ("versions", "Version leaks", "Server versions and source maps", "site", ("version-", "source-map")),
    ("env", ".env files", "Secrets files kept out of git", "repo", ("env-",)),
    ("deps", "Vulnerable packages", "Dependencies with published vulnerabilities", "repo", ("vulnerable-dependency", "osv-")),
]


def check_rows(findings: list[dict], has_site: bool, has_repo: bool) -> list[dict]:
    rows = []
    for key, name, desc, scope, prefixes in CHECKS:
        if (scope == "site" and not has_site) or (scope == "repo" and not has_repo):
            rows.append({"key": key, "status": "skip"})
            continue
        sev = {f["severity"] for f in findings if f["id"].startswith(prefixes)}
        rows.append({"key": key, "status": "fail" if sev & {"high", "medium"} else "warn" if "low" in sev else "pass"})
    return rows


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
    sid = uuid.uuid4().hex[:10]
    SCANS[sid] = data
    for old in list(SCANS)[:-20]:
        SCANS.pop(old, None)
    return {"id": sid, "target": data["target"], "score": data["score"], "grade": data["grade"], "counts": data["counts"],
            "checked_at": data["checked_at"], "findings": data["findings"], "checks": check_rows(data["findings"], bool(url), bool(repo))}


@app.get("/api/scan/{sid}/pdf")
def scan_pdf(sid: str) -> Response:
    data = SCANS.get(sid)
    if not data:
        raise HTTPException(404, "That scan is no longer in memory. Run the check again.")
    from launchcheck.pdf import build_pdf
    return Response(build_pdf(data), media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="launchcheck-report.pdf"'})


@app.get("/api/checks")
def checks() -> list[dict]:
    return [{"key": k, "name": n, "desc": d, "scope": s} for k, n, d, s, _ in CHECKS]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>launchcheck: find the holes before you launch</title><style>
:root{--bg:#f3f4f0;--surface:#fff;--sunk:#e9eae5;--ink:#111311;--mut:#5d625e;--line:#dfe1da;--pass:#17803d;--warn:#a86400;--fail:#c2321f;--low:#2b5fa8;--acc:#111311;--on:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#0e100e;--surface:#171a17;--sunk:#1f231f;--ink:#f0f2ee;--mut:#9ca39b;--line:#2a2f2a;--pass:#58c27a;--warn:#e0a63f;--fail:#f07462;--low:#7fa9e6;--acc:#f0f2ee;--on:#0e100e}}
[hidden]{display:none!important}*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit}button,input{font:inherit;color:inherit}.sr{position:absolute;left:-9999px}
.wrap{max-width:1240px;margin:0 auto;padding:0 28px}
.top{display:flex;align-items:center;justify-content:space-between;height:72px}
.mark{display:flex;align-items:center;gap:10px;font-weight:700;font-size:19px;letter-spacing:-.02em;text-decoration:none}.mark svg{width:26px;height:26px}
.top nav{display:flex;gap:26px;font-size:15px;color:var(--mut)}.top nav a{text-decoration:none}.top nav a:hover{color:var(--ink)}
.hero{display:grid;grid-template-columns:1.05fr .95fr;gap:56px;padding:56px 0 96px;align-items:start}
h1{font-size:clamp(44px,6.2vw,84px);line-height:.94;letter-spacing:-.045em;margin:0;max-width:11ch}
.lead{font-size:20px;color:var(--mut);max-width:36ch;margin:28px 0 36px}
.bar{display:flex;background:var(--surface);border:2px solid var(--ink);border-radius:4px;overflow:hidden}
.bar input{flex:1;min-width:0;border:0;background:none;padding:20px;font-size:21px;outline:none}
.bar button{border:0;background:var(--acc);color:var(--on);font-weight:650;padding:0 28px;font-size:18px;cursor:pointer;transition:opacity .15s}
.bar button:hover{opacity:.88}.bar button:active{opacity:.75}.bar button:disabled{opacity:.5;cursor:progress}
.bar:focus-within{outline:3px solid color-mix(in srgb,var(--pass) 45%,transparent);outline-offset:2px}
details{margin-top:18px;font-size:15px;color:var(--mut)}summary{cursor:pointer;width:max-content}summary:hover{color:var(--ink)}
details input{display:block;width:100%;margin-top:10px;padding:13px 14px;border:1px solid var(--line);border-radius:4px;background:var(--surface);font-size:16px}
.fine{font-size:14px;color:var(--mut);margin:22px 0 0;max-width:52ch}.err{color:var(--fail);font-weight:600}
.list{background:var(--surface);border-radius:6px;padding:10px 0}
.list h2{font-size:17px;margin:12px 24px 8px;letter-spacing:-.01em}
.row{display:grid;grid-template-columns:28px 1fr auto;gap:14px;align-items:center;padding:11px 24px}
.row + .row{border-top:1px solid var(--line)}
.row b{font-weight:600;font-size:16px}.row small{display:block;color:var(--mut);font-size:14px;line-height:1.35}
.st{width:22px;height:22px;border-radius:50%;background:var(--sunk);display:grid;place-items:center;color:#fff;font-size:13px;font-weight:800;transition:background .25s,transform .25s}
.row[data-s=checking] .st{animation:pulse 1s ease-in-out infinite}
.row[data-s=pass] .st{background:var(--pass)}.row[data-s=warn] .st{background:var(--warn)}.row[data-s=fail] .st{background:var(--fail)}
.row[data-s=skip]{opacity:.45}.word{font-size:14px;color:var(--mut);font-weight:600}
.row[data-s=pass] .word{color:var(--pass)}.row[data-s=warn] .word{color:var(--warn)}.row[data-s=fail] .word{color:var(--fail)}
@keyframes pulse{50%{transform:scale(.75);opacity:.5}}
.res{background:var(--surface);padding:72px 0 96px}
.sum{display:grid;grid-template-columns:auto 1fr auto;gap:40px;align-items:end;padding-bottom:40px}
.score{font-size:clamp(96px,13vw,168px);font-weight:750;line-height:.8;letter-spacing:-.06em}
.score small{font-size:22px;letter-spacing:0;font-weight:600;color:var(--mut);margin-left:6px}
.sum h2{font-size:clamp(28px,3vw,40px);line-height:1.05;letter-spacing:-.03em;margin:0 0 10px}
.counts{display:flex;gap:22px;flex-wrap:wrap;color:var(--mut);font-size:16px}.counts b{color:var(--ink);font-size:20px}
.btn{display:inline-flex;align-items:center;gap:8px;background:var(--acc);color:var(--on);border:0;border-radius:4px;padding:14px 20px;font-weight:650;text-decoration:none;cursor:pointer;transition:opacity .15s}
.btn:hover{opacity:.88}.btn.alt{background:var(--sunk);color:var(--ink)}
.grp{display:grid;grid-template-columns:220px 1fr;gap:40px;padding:36px 0;border-top:1px solid var(--line)}
.grp h3{font-size:22px;margin:0;letter-spacing:-.02em}.grp h3 small{display:block;font-size:15px;color:var(--mut);font-weight:500;margin-top:4px}
.f{padding:0 0 28px}.f + .f{border-top:1px solid var(--line);padding-top:24px}
.f h4{font-size:19px;margin:0 0 6px;letter-spacing:-.01em}.f p{margin:0 0 12px;max-width:68ch}
.f pre{margin:0;background:var(--sunk);border-radius:4px;padding:14px 16px;font:15px/1.5 inherit;font-family:inherit;white-space:pre-wrap;overflow-wrap:anywhere}
.f .meta{font-size:14px;color:var(--mut);margin-top:10px;overflow-wrap:anywhere}
.g-high h3{color:var(--fail)}.g-medium h3{color:var(--warn)}.g-low h3{color:var(--low)}
.clean{font-size:22px;color:var(--pass);font-weight:650;padding:24px 0}
.hist{font-size:14px;color:var(--mut);padding:28px 0 0}
footer{padding:40px 0 48px;color:var(--mut);font-size:14px}
.reveal{opacity:0;transform:translateY(18px);animation:in .5s cubic-bezier(.2,.8,.2,1) forwards}
.reveal:nth-child(2){animation-delay:.08s}.reveal:nth-child(3){animation-delay:.16s}.reveal:nth-child(4){animation-delay:.24s}
@keyframes in{to{opacity:1;transform:none}}
@media(max-width:900px){.hero{grid-template-columns:1fr;gap:40px;padding:28px 0 64px}.sum{grid-template-columns:1fr;gap:20px}.grp{grid-template-columns:1fr;gap:16px}
 .wrap{padding:0 18px}.top nav a:not(:last-child){display:none}.bar input{font-size:18px;padding:16px}.bar button{padding:0 18px;font-size:16px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}.reveal{opacity:1;transform:none}}
</style></head><body>
<div class="wrap"><header class="top"><a class="mark" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>launchcheck</a>
<nav><a href="#checks">What it checks</a><a href="https://github.com/NiharPatel2545/launchcheck" target="_blank" rel="noopener">GitHub</a></nav></header>
<section class="hero"><div><h1>Find the holes before you launch.</h1>
<p class="lead">Paste your site. In about ten seconds you get every exposed key, missing header and leaky setting, with the fix for each.</p>
<form id="f"><div class="bar"><label for="url" class="sr">Website address</label><input id="url" placeholder="yoursite.com" autocomplete="url" inputmode="url"><button id="go">Check site</button></div>
<details><summary>Also check a project folder on this computer</summary><label for="repo" class="sr">Project folder</label><input id="repo" placeholder="C:\path\to\your\project"></details>
<p id="st" class="fine" aria-live="polite">Passive only: it makes the requests a normal visitor's browser makes and never attacks anything. Check sites and code you own.</p></form></div>
<div class="list" id="checks"><h2>What gets checked</h2><div id="rows"></div></div></section></div>
<section class="res" id="res" hidden><div class="wrap"><div class="sum"><div class="score" id="score"></div><div><h2 id="verdict"></h2><div class="counts" id="counts"></div></div>
<div style="display:flex;gap:10px;flex-wrap:wrap"><a class="btn" id="pdf" href="#">Download PDF</a><button class="btn alt" id="again" type="button">Check another</button></div></div>
<div id="groups"></div><div class="hist" id="hist"></div></div></section>
<div class="wrap"><footer>launchcheck is open source and runs on your computer only. A good score means these common mistakes are absent, not that the app is secure.</footer></div>
<script>
const $ = s => document.querySelector(s), esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c])
const WORD = {pass: 'Passed', warn: 'Minor', fail: 'Problem', skip: 'Not run', checking: 'Checking', idle: ''}, GLYPH = {pass: '✓', warn: '!', fail: '✕'}
const SEV = [['high', 'Fix now', 'Visitors or attackers can use these today'], ['medium', 'Fix soon', 'Real weaknesses, not yet an open door'], ['low', 'Good to fix', 'Hardening that closes small gaps'], ['info', 'Notes', 'Worth knowing, nothing broken']]
let CHECKS = [], history = []
const setRow = (key, s) => { const r = document.querySelector(`[data-k="${key}"]`); if (!r) return; r.dataset.s = s; r.querySelector('.st').textContent = GLYPH[s] || ''; r.querySelector('.word').textContent = WORD[s] }
async function init(){ CHECKS = await (await fetch('/api/checks')).json()
  $('#rows').innerHTML = CHECKS.map(c => `<div class="row" data-k="${c.key}" data-s="idle"><span class="st"></span><span><b>${esc(c.name)}</b><small>${esc(c.desc)}${c.scope === 'repo' ? ' (folder check)' : ''}</small></span><span class="word"></span></div>`).join('') }
function render(d){
  const c = d.counts, verdict = c.high ? `${c.high} thing${c.high > 1 ? 's' : ''} to fix before launch.` : c.medium ? 'No open doors, a few weak spots.' : 'Ready to launch on these checks.'
  $('#score').innerHTML = `${d.score}<small>/100 · ${d.grade}</small>`; $('#verdict').textContent = verdict
  $('#counts').innerHTML = `<span><b>${c.high}</b> fix now</span><span><b>${c.medium}</b> fix soon</span><span><b>${c.low}</b> good to fix</span><span><b>${c.info}</b> notes</span>`
  $('#pdf').href = `/api/scan/${d.id}/pdf`
  $('#groups').innerHTML = SEV.map(([k, name, sub]) => { const fs = d.findings.filter(f => f.severity === k); if (!fs.length) return ''
    return `<div class="grp g-${k} reveal"><h3>${name}<small>${sub}</small></h3><div>${fs.map(f => `<article class="f"><h4>${esc(f.title)}</h4><p>${esc(f.why)}</p><pre>${esc(f.fix)}</pre>${f.where || f.evidence ? `<div class="meta">${esc(f.where)}${f.evidence ? ' · seen: ' + esc(f.evidence) : ''}</div>` : ''}</article>`).join('')}</div></div>` }).join('') || '<p class="clean">No problems found by these checks.</p>'
  history.unshift(`${esc(d.target)} <b>${d.score}</b>`); $('#hist').innerHTML = history.length > 1 ? 'Earlier this session: ' + history.slice(1, 6).join(' · ') : ''
  $('#res').hidden = false; $('#res').scrollIntoView({behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}) }
$('#f').addEventListener('submit', async e => { e.preventDefault(); const url = $('#url').value.trim(), repo = $('#repo').value.trim(), b = $('#go'), st = $('#st')
  if (!url && !repo) { st.className = 'fine err'; st.textContent = 'Paste a website address, or open the folder option.'; return }
  b.disabled = true; st.className = 'fine'; st.textContent = 'Checking… about ten seconds.'
  CHECKS.forEach(c => setRow(c.key, (c.scope === 'site' && !url) || (c.scope === 'repo' && !repo) ? 'skip' : 'checking'))
  try { const r = await fetch('/api/scan', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url, repo})}), d = await r.json()
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'The check failed.')
    d.checks.forEach((c, i) => setTimeout(() => setRow(c.key, c.status), 90 * i))
    setTimeout(() => { render(d); st.textContent = `Checked ${d.target} at ${d.checked_at}.` }, 90 * d.checks.length + 250)
  } catch (err) { st.className = 'fine err'; st.textContent = err.message; CHECKS.forEach(c => setRow(c.key, 'idle')) } finally { b.disabled = false } })
$('#again').addEventListener('click', () => { $('#url').value = ''; $('#url').focus(); window.scrollTo({top: 0}) })
init()
</script></body></html>"""


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
