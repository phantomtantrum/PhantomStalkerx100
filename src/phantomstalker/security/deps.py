"""/deps — вразливості в залежностях проєкту за базою OSV.dev (безкоштовно, без ключа)."""

from __future__ import annotations

import asyncio
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError, score

OSV = "https://api.osv.dev/v1"
SKIP = {"node_modules", ".venv", "venv", ".git", "dist", "build", "target", "__pycache__"}


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    ecosystem: str  # PyPI | npm | Go | crates.io | RubyGems | Packagist
    source: str


# --- парсери файлів залежностей ----------------------------------------------------------
_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)")


def parse_requirements(text: str, source: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0]
        if m := _REQ.match(line):
            out.append(Package(m.group(1).lower(), m.group(2), "PyPI", source))
    return out


def parse_toml_lock(text: str, source: str, ecosystem: str) -> list[Package]:
    data = tomllib.loads(text)
    return [Package(p["name"].lower() if ecosystem == "PyPI" else p["name"], str(p["version"]), ecosystem, source)
            for p in data.get("package", []) if "name" in p and "version" in p]


def parse_pipfile_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                out.append(Package(name.lower(), version, "PyPI", source))
    return out


def parse_package_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    out: list[Package] = []
    if "packages" in data:  # lockfile v2/v3
        for path, meta in data["packages"].items():
            if path and "version" in meta and not meta.get("link"):
                name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
                out.append(Package(name, meta["version"], "npm", source))
        return out

    def walk(deps: dict) -> None:  # lockfile v1
        for name, meta in deps.items():
            if "version" in meta:
                out.append(Package(name, meta["version"], "npm", source))
            walk(meta.get("dependencies", {}))

    walk(data.get("dependencies", {}))
    return out


_YARN = re.compile(r'^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:? "?([^"\n]+)"?', re.M)


def parse_yarn_lock(text: str, source: str) -> list[Package]:
    return [Package(m.group(1), m.group(2), "npm", source) for m in _YARN.finditer(text)]


_GOMOD = re.compile(r"^\s*([\w.\-/]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", re.M)


def parse_go_mod(text: str, source: str) -> list[Package]:
    body = re.sub(r"^module .*$", "", text, flags=re.M)
    return [Package(m.group(1), m.group(2), "Go", source) for m in _GOMOD.finditer(body)
            if not m.group(1).startswith(("go ", "toolchain"))]


_GEM = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)\s]*)\)$", re.M)


def parse_gemfile_lock(text: str, source: str) -> list[Package]:
    return [Package(m.group(1), m.group(2).split("-")[0], "RubyGems", source) for m in _GEM.finditer(text)]


def parse_composer_lock(text: str, source: str) -> list[Package]:
    data = json.loads(text)
    return [Package(p["name"], p["version"].lstrip("v"), "Packagist", source)
            for key in ("packages", "packages-dev") for p in data.get(key, []) if "name" in p]


PARSERS = {
    "poetry.lock": lambda t, s: parse_toml_lock(t, s, "PyPI"),
    "uv.lock": lambda t, s: parse_toml_lock(t, s, "PyPI"),
    "Cargo.lock": lambda t, s: parse_toml_lock(t, s, "crates.io"),
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}


def find_packages(root: Path, max_depth: int = 3) -> tuple[list[Package], list[str]]:
    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for path in root.rglob("*"):
            rel = path.relative_to(root).parts
            if len(rel) > max_depth + 1 or any(p in SKIP for p in rel[:-1]) or not path.is_file():
                continue
            if path.name in PARSERS or re.fullmatch(r"requirements.*\.txt", path.name):
                files.append(path)
    packages: list[Package] = []
    sources = []
    for path in sorted(files):
        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        parser = PARSERS.get(path.name, parse_requirements)
        try:
            found = parser(path.read_text(encoding="utf-8", errors="replace"), rel)
        except (ValueError, KeyError, tomllib.TOMLDecodeError):
            continue
        if found:
            sources.append(f"{rel} ({len(found)})")
            packages.extend(found)
    unique = list({(p.ecosystem, p.name, p.version): p for p in packages}.values())
    return unique, sources


# --- OSV ---------------------------------------------------------------------------------
@dataclass
class Vuln:
    id: str
    summary: str
    severity: Severity
    aliases: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)


_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def parse_vuln(data: dict, package: Package) -> Vuln:
    sev_label = str((data.get("database_specific") or {}).get("severity", "")).upper()
    severity = _SEV.get(sev_label, Severity.MEDIUM)
    fixed = []
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package.name.lower():
            continue
        for rng in affected.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    summary = data.get("summary") or (data.get("details") or "").split("\n")[0][:160]
    return Vuln(data["id"], summary, severity, data.get("aliases", []), sorted(set(fixed)))


async def query_osv(packages: list[Package], client: httpx.AsyncClient) -> dict[Package, list[Vuln]]:
    ids_by_pkg: dict[Package, list[str]] = {}
    for start in range(0, len(packages), 500):
        chunk = packages[start:start + 500]
        body = {"queries": [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                            for p in chunk]}
        resp = await client.post(f"{OSV}/querybatch", json=body)
        resp.raise_for_status()
        for pkg, result in zip(chunk, resp.json().get("results", []), strict=False):
            ids = [v["id"] for v in result.get("vulns", [])]
            if ids:
                ids_by_pkg[pkg] = ids

    sem = asyncio.Semaphore(8)

    async def details(vid: str) -> dict:
        async with sem:
            resp = await client.get(f"{OSV}/vulns/{vid}")
            resp.raise_for_status()
            return resp.json()

    all_ids = sorted({vid for ids in ids_by_pkg.values() for vid in ids})
    fetched = dict(zip(all_ids, await asyncio.gather(*(details(v) for v in all_ids)), strict=True))
    return {pkg: [parse_vuln(fetched[v], pkg) for v in ids] for pkg, ids in ids_by_pkg.items()}


async def scan(path: str | Path = ".", client: httpx.AsyncClient | None = None) -> Report:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise SecurityError(f"Немає такого шляху: {root}")
    packages, sources = find_packages(root)
    r = Report(f"Вразливості залежностей · {root.name or root}")
    if not packages:
        r.add(Severity.INFO, "Не знайшов зафіксованих залежностей",
              "Підтримуються: requirements*.txt (==), poetry.lock, uv.lock, Pipfile.lock, package-lock.json, "
              "yarn.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock")
        return r
    own = client is None
    client = client or net.client()
    try:
        results = await query_osv(packages, client)
    except httpx.HTTPError as exc:
        raise SecurityError(net.describe_http_error(exc, "OSV.dev")) from exc
    finally:
        if own:
            await client.aclose()

    for pkg, vulns in sorted(results.items(), key=lambda kv: -max(v.severity for v in kv[1])):
        worst = max(v.severity for v in vulns)
        cves = [a for v in vulns for a in v.aliases if a.startswith("CVE-")] or [v.id for v in vulns]
        fixed = sorted({f for v in vulns for f in v.fixed})
        detail = "; ".join(f"{v.id}: {v.summary}" for v in vulns[:3])
        if len(vulns) > 3:
            detail += f"; …ще {len(vulns) - 3}"
        fix = f"Онови {pkg.name} щонайменше до {fixed[-1]}" if fixed else "Виправлення поки немає — оціни, чи вразливий код використовується"
        r.add(worst, f"{pkg.name} {pkg.version} [{pkg.ecosystem}] — {len(vulns)} вразл. ({', '.join(cves[:3])})",
              detail, fix)
    if not results:
        r.add(Severity.OK, "Відомих вразливостей не знайдено")
    r.score = score(r.findings)
    r.summary = f"Пакетів перевірено: {len(packages)} · уразливих: {len(results)}"
    r.notes.append("Джерела: " + ", ".join(sources))
    return r
