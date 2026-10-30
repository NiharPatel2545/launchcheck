"""Checks of a local project folder: secrets in files and git history, committed .env files, and dependencies with known
vulnerabilities (OSV database, free, no key)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import requests

from launchcheck.findings import Finding
from launchcheck.secrets import scan_text

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next", ".cache", "site-packages"}
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".env", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".txt",
            ".md", ".html", ".vue", ".svelte", ".sh", ".ps1", ".rb", ".go", ".php", ".java", ".kt", ".cs", ".config", ".xml", ""}
MAX_FILE = 2_000_000
OSV_URL = "https://api.osv.dev/v1/querybatch"


def _git(repo: Path, *args: str, limit: int = 40_000_000) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout[:limit].decode("utf-8", "replace") if p.returncode == 0 else None


def _files(repo: Path):
    for p in repo.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(repo).parts[:-1]):
            continue
        if p.is_file() and (p.suffix.lower() in TEXT_EXT or p.name.startswith(".env")) and p.stat().st_size <= MAX_FILE:
            yield p


def check_secrets(repo: Path) -> list[Finding]:
    out = []
    for p in _files(repo):
        try:
            text = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        out += scan_text(text, str(p.relative_to(repo)).replace("\\", "/"), public=False)
    return out


def check_env_files(repo: Path) -> list[Finding]:
    out = []
    tracked = _git(repo, "ls-files")
    if tracked is not None:
        for f in tracked.splitlines():
            name = f.rsplit("/", 1)[-1]
            if name.startswith(".env") and not re.search(r"example|sample|template|dist", name, re.I):
                out.append(Finding("env-committed", f"{f} is committed to git", "high",
                                   "Environment files hold your keys and passwords. Committed, they are in every clone and in history forever.",
                                   f"Rotate every key in it, then: git rm --cached {f}, add .env* to .gitignore, and commit a .env.example "
                                   "with blank values instead.", f))
        hist = _git(repo, "log", "-p", "--all", "-n", "300", "--no-color")
        if hist:
            current = {(f.id, f.evidence) for f in check_secrets(repo)}
            for f in scan_text(hist, "git history", public=False):
                if (f.id, f.evidence) not in current and f.severity == "high":
                    f.title = f.title.replace("in the code", "in git history")
                    f.why = "It was removed from the files but is still in the git history, which anyone with the repo can read."
                    f.where = "git history"
                    out.append(f)
    gi = repo / ".gitignore"
    if (repo / ".env").exists() and (not gi.exists() or not re.search(r"^\s*\.env", gi.read_text("utf-8", "replace"), re.M)):
        out.append(Finding("env-not-ignored", ".env is not in .gitignore", "medium",
                           "One `git add .` and your keys are committed.", "Add a line `.env*` (and `!.env.example`) to .gitignore.", ".gitignore"))
    return out


def _deps(repo: Path) -> list[tuple[str, str, str, str]]:
    """(ecosystem, name, version, file) for exactly pinned dependencies."""
    out = []
    for req in list(repo.glob("requirements*.txt")):
        for line in req.read_text("utf-8", "replace").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
            if m:
                out.append(("PyPI", re.sub(r"\[.*\]", "", m.group(1)), m.group(2), req.name))
    lock = repo / "package-lock.json"
    if lock.exists():
        try:
            data = json.loads(lock.read_text("utf-8"))
            for path, meta in (data.get("packages") or {}).items():
                if path.startswith("node_modules/") and meta.get("version") and not meta.get("dev"):
                    out.append(("npm", path.split("node_modules/")[-1], meta["version"], "package-lock.json"))
        except (ValueError, OSError):
            pass
    elif (repo / "package.json").exists():
        try:
            data = json.loads((repo / "package.json").read_text("utf-8"))
            for name, ver in (data.get("dependencies") or {}).items():
                if re.fullmatch(r"\d+\.\d+\.\d+", str(ver)):
                    out.append(("npm", name, ver, "package.json"))
        except (ValueError, OSError):
            pass
    return out


def osv_query(deps, session: requests.Session | None = None) -> list[list[str]]:
    """Vulnerability ids per dependency, from the OSV batch API."""
    s = session or requests.Session()
    ids: list[list[str]] = []
    for i in range(0, len(deps), 500):
        chunk = deps[i:i + 500]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v, _ in chunk]}
        r = s.post(OSV_URL, json=body, timeout=30)
        r.raise_for_status()
        ids += [[v["id"] for v in (res.get("vulns") or [])] for res in r.json().get("results", [])]
    return ids


def check_dependencies(repo: Path, query=osv_query) -> list[Finding]:
    deps = _deps(repo)
    if not deps:
        return []
    try:
        results = query(deps)
    except Exception as e:
        return [Finding("osv-unavailable", "Could not check dependencies for known vulnerabilities", "info",
                        f"The OSV vulnerability database did not answer ({type(e).__name__}).", "Run the scan again later.", "")]
    out = []
    for (eco, name, ver, file), vulns in zip(deps, results):
        if vulns:
            fix = f"pip install -U {name}  (then update {file})" if eco == "PyPI" else f"npm install {name}@latest"
            out.append(Finding("vulnerable-dependency", f"{name} {ver} has {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
                               "high" if len(vulns) >= 3 else "medium",
                               "Published vulnerabilities come with public exploit details; bots scan for apps running old versions.",
                               f"Upgrade to a fixed version: {fix}. Details: " + ", ".join(f"https://osv.dev/vulnerability/{v}" for v in vulns[:3]),
                               file, ", ".join(vulns[:6]) + (" …" if len(vulns) > 6 else "")))
    return out


def check_repo(path: str, query=osv_query) -> tuple[list[Finding], dict]:
    repo = Path(path).resolve()
    if not repo.is_dir():
        return [Finding("repo-missing", "Project folder not found", "info", f"{repo} is not a folder.", "Check the path.", str(repo))], {}
    deps = _deps(repo)
    return check_secrets(repo) + check_env_files(repo) + check_dependencies(repo, query), {"repo": str(repo), "dependencies_checked": len(deps)}
