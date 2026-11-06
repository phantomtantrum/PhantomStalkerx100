"""/cve та /brief — дані про вразливості з NVD і каталогу CISA KEV (активно експлуатовані)."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV = "https://api.osv.dev/v1/vulns/"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW, "NONE": Severity.INFO}


async def fetch_kev(client: httpx.AsyncClient, max_age: float = 12 * 3600) -> list[dict]:
    cached = net.cache_get("kev", max_age)
    if cached is not None:
        return cached
    resp = await client.get(KEV)
    resp.raise_for_status()
    items = resp.json().get("vulnerabilities", [])
    net.cache_put("kev", items)
    return items


def _cvss(metrics: dict) -> tuple[float | None, str, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            sev = data.get("baseSeverity") or m.get("baseSeverity") or ""
            return data.get("baseScore"), str(sev).upper(), data.get("vectorString", "")
    return None, "", ""


def _products(cve: dict, limit: int = 6) -> list[str]:
    found: list[str] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5:
                    label = f"{parts[3]} {parts[4]}".replace("_", " ")
                    ver = parts[5] if parts[5] not in ("*", "-") else ""
                    if end := match.get("versionEndExcluding"):
                        ver = f"< {end}"
                    elif end := match.get("versionEndIncluding"):
                        ver = f"≤ {end}"
                    item = f"{label} {ver}".strip()
                    if item not in found:
                        found.append(item)
    return found[:limit]


def normalize_id(raw: str) -> str:
    """CVE — верхній регістр; GHSA — префікс великими, решта малими (OSV чутливий до регістру)."""
    raw = raw.strip()
    upper = raw.upper()
    if upper.startswith("CVE-"):
        return upper
    if upper.startswith("GHSA-"):
        return "GHSA-" + raw[5:].lower()
    return raw


async def lookup(cve_id: str, client: httpx.AsyncClient | None = None) -> Report:
    cve_id = normalize_id(cve_id)
    if not (CVE_RE.match(cve_id) or cve_id.startswith(("GHSA-", "PYSEC-", "GO-", "RUSTSEC-"))):
        raise SecurityError("Формат: /cve CVE-2024-3094 (або ідентифікатор GHSA-…)")
    own = client is None
    client = client or net.client()
    try:
        kev = {}
        try:
            kev = {v["cveID"]: v for v in await fetch_kev(client)}
        except httpx.HTTPError:
            pass
        if CVE_RE.match(cve_id):
            try:
                resp = await client.get(NVD, params={"cveId": cve_id})
                resp.raise_for_status()
                vulns = resp.json().get("vulnerabilities", [])
            except httpx.HTTPError:
                vulns = []
            if vulns:
                return _nvd_report(vulns[0]["cve"], kev.get(cve_id))
        resp = await client.get(OSV + cve_id)
        if resp.status_code == 404:
            raise SecurityError(f"{cve_id} не знайдено ні в NVD, ні в OSV")
        resp.raise_for_status()
        return _osv_report(resp.json(), kev.get(cve_id))
    except httpx.HTTPError as exc:
        raise SecurityError(net.describe_http_error(exc, "NVD/OSV")) from exc
    finally:
        if own:
            await client.aclose()


def _kev_finding(r: Report, item: dict) -> None:
    ransom = item.get("knownRansomwareCampaignUse", "").lower() == "known"
    r.add(Severity.CRITICAL, "Активно експлуатується зловмисниками (CISA KEV)",
          f"Додано до каталогу {item.get('dateAdded')}" + (" · використовується в атаках програм-вимагачів" if ransom else ""),
          item.get("requiredAction", "Онови вразливий продукт якнайшвидше"))


def _nvd_report(cve: dict, kev_item: dict | None) -> Report:
    score_, sev, vector = _cvss(cve.get("metrics", {}))
    title = cve["id"] + (f" — CVSS {score_} {sev}" if score_ is not None else "")
    r = Report(title)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    r.summary = f"Опубліковано {cve.get('published', '')[:10]}"
    if kev_item:
        _kev_finding(r, kev_item)
    r.add(_SEV.get(sev, Severity.MEDIUM), "Опис", desc)
    if vector:
        r.add(Severity.INFO, "Вектор CVSS", vector)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    if cwes:
        r.add(Severity.INFO, "Тип слабкості", ", ".join(cwes))
    if products := _products(cve):
        r.add(Severity.INFO, "Вразливі продукти", "; ".join(products))
    refs = [ref["url"] for ref in cve.get("references", [])][:4]
    r.notes += refs
    return r


def _osv_report(data: dict, kev_item: dict | None) -> Report:
    sev_label = str((data.get("database_specific") or {}).get("severity", "")).upper()
    r = Report(data["id"] + (f" — {sev_label}" if sev_label else ""))
    r.summary = f"Опубліковано {str(data.get('published', ''))[:10]}"
    if kev_item:
        _kev_finding(r, kev_item)
    r.add(_SEV.get(sev_label.replace("MODERATE", "MEDIUM"), Severity.MEDIUM),
          data.get("summary") or "Опис", (data.get("details") or "")[:600])
    pkgs = [f"{a['package'].get('ecosystem')}/{a['package'].get('name')}" for a in data.get("affected", [])
            if "package" in a]
    if pkgs:
        r.add(Severity.INFO, "Вразливі пакети", ", ".join(pkgs[:6]))
    if aliases := data.get("aliases"):
        r.add(Severity.INFO, "Інші ідентифікатори", ", ".join(aliases))
    r.notes += [ref["url"] for ref in data.get("references", [])][:4]
    return r


async def brief(stack: list[str], days: int = 14, client: httpx.AsyncClient | None = None,
                today: date | None = None) -> Report:
    """Свіжі активно експлуатовані вразливості, відфільтровані за твоїм стеком."""
    own = client is None
    client = client or net.client()
    try:
        items = await fetch_kev(client)
    except httpx.HTTPError as exc:
        raise SecurityError(net.describe_http_error(exc, "CISA KEV")) from exc
    finally:
        if own:
            await client.aclose()
    today = today or date.today()
    since = today - timedelta(days=days)
    terms = [t.strip().casefold() for t in stack if t.strip()]

    def recent(item: dict) -> bool:
        try:
            return datetime.strptime(item.get("dateAdded", ""), "%Y-%m-%d").date() >= since
        except ValueError:
            return False

    def relevant(item: dict) -> bool:
        hay = f"{item.get('vendorProject', '')} {item.get('product', '')} {item.get('vulnerabilityName', '')}".casefold()
        return any(t in hay for t in terms)

    fresh = sorted((i for i in items if recent(i)), key=lambda i: i.get("dateAdded", ""), reverse=True)
    picked = [i for i in fresh if relevant(i)] if terms else fresh[:15]
    scope = f"твій стек: {', '.join(stack)}" if terms else "увесь каталог (задай свій стек: /stack)"
    r = Report(f"Безпековий дайджест · {days} днів", summary=f"Нових у KEV: {len(fresh)} · {scope}")
    for item in picked:
        ransom = item.get("knownRansomwareCampaignUse", "").lower() == "known"
        r.add(Severity.CRITICAL if ransom else Severity.HIGH,
              f"{item['cveID']} · {item.get('vendorProject')} {item.get('product')}",
              item.get("shortDescription", "")[:300] + (" [вимагачі]" if ransom else ""),
              f"{item.get('requiredAction', '')} (термін: {item.get('dueDate', '—')})")
    if not picked:
        r.add(Severity.OK, "Нічого нового для твого стеку" if terms else "Нових записів немає")
    r.notes.append("Джерело: CISA Known Exploited Vulnerabilities — вразливості, які вже атакують у реальному світі.")
    return r
