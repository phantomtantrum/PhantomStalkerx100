import json
from datetime import date

import httpx
import pytest

from phantomstalker.security import cve, deps
from phantomstalker.security.report import SecurityError, Severity
from tests.conftest import mock_client


def test_parsers():
    assert deps.parse_requirements("Django==4.2.0 # web\nrequests>=2\nflask[async]==2.0.1 ; python_version>'3'", "r") == [
        deps.Package("django", "4.2.0", "PyPI", "r"), deps.Package("flask", "2.0.1", "PyPI", "r")]
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"},
                                                           "node_modules/@a/b": {"version": "1.0.0"}}})
    assert {(p.name, p.version) for p in deps.parse_package_lock(lock, "l")} == {("lodash", "4.17.20"), ("@a/b", "1.0.0")}
    v1 = json.dumps({"dependencies": {"x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}}}})
    assert len(deps.parse_package_lock(v1, "l")) == 2
    assert deps.parse_toml_lock('[[package]]\nname = "Requests"\nversion = "2.0"\n', "p", "PyPI")[0].name == "requests"
    yarn = '"lodash@^4.17.0":\n  version "4.17.20"\n  resolved "x"\n\n"@babel/core@^7":\n  version "7.1.0"\n'
    assert {(p.name, p.version) for p in deps.parse_yarn_lock(yarn, "y")} == {("lodash", "4.17.20"), ("@babel/core", "7.1.0")}
    gomod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n"
    assert {(p.name, p.version) for p in deps.parse_go_mod(gomod, "g")} == {("golang.org/x/net", "v0.17.0"), ("github.com/a/b", "v1.2.3")}
    gem = "GEM\n  specs:\n    rails (7.0.1)\n      actionpack (= 7.0.1)\n    nokogiri (1.13.0-x86_64-linux)\n"
    assert {(p.name, p.version) for p in deps.parse_gemfile_lock(gem, "G")} == {("rails", "7.0.1"), ("nokogiri", "1.13.0")}
    assert deps.parse_composer_lock(json.dumps({"packages": [{"name": "a/b", "version": "v1.0"}]}), "c")[0].version == "1.0"


def osv_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/querybatch"):
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "GHSA-aaaa"}]} if q["package"]["name"] == "django" else {} for q in queries]})
    if request.url.path.endswith("/vulns/GHSA-aaaa"):
        return httpx.Response(200, json={
            "id": "GHSA-aaaa", "summary": "SQL injection", "aliases": ["CVE-2023-0001"],
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"name": "Django", "ecosystem": "PyPI"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.2.7"}]}]}]})
    return httpx.Response(404)


async def test_deps_scan_with_osv(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==4.2.0\nrequests==2.31.0\n")
    r = await deps.scan(tmp_path, client=mock_client(osv_handler))
    f = r.findings[0]
    assert f.severity == Severity.HIGH and "django 4.2.0" in f.title and "CVE-2023-0001" in f.title
    assert "4.2.7" in f.fix
    assert "Пакетів перевірено: 2 · уразливих: 1" == r.summary


async def test_deps_no_lockfiles_and_network_error(tmp_path):
    r = await deps.scan(tmp_path, client=mock_client(osv_handler))
    assert r.findings[0].severity == Severity.INFO
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n")

    def down(request):
        raise httpx.ConnectError("no route")

    with pytest.raises(SecurityError, match="OSV.dev"):
        await deps.scan(tmp_path, client=mock_client(down))


KEV = {"vulnerabilities": [
    {"cveID": "CVE-2024-3094", "vendorProject": "XZ Utils", "product": "liblzma", "vulnerabilityName": "XZ backdoor",
     "dateAdded": "2026-11-01", "shortDescription": "Backdoor", "requiredAction": "Downgrade", "dueDate": "2026-11-20",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-1111", "vendorProject": "Google", "product": "Chromium V8", "vulnerabilityName": "Type confusion",
     "dateAdded": "2026-11-04", "shortDescription": "RCE", "requiredAction": "Update Chrome", "dueDate": "2026-11-25",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0001", "vendorProject": "Old", "product": "Thing", "dateAdded": "2020-01-01"},
]}
NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-3094", "published": "2024-03-29T17:15:21",
    "descriptions": [{"lang": "en", "value": "Malicious code was discovered in xz."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL",
                                                "vectorString": "CVSS:3.1/AV:N/AC:L"}}]},
    "weaknesses": [{"description": [{"value": "CWE-506"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://example.org/xz"}]}}]}


def cve_handler(request: httpx.Request) -> httpx.Response:
    if "cisa.gov" in request.url.host:
        return httpx.Response(200, json=KEV)
    if "nvd.nist.gov" in request.url.host:
        if request.url.params.get("cveId") == "CVE-2024-3094":
            return httpx.Response(200, json=NVD)
        return httpx.Response(200, json={"vulnerabilities": []})
    if request.url.path.endswith("/GHSA-xxxx"):
        return httpx.Response(200, json={"id": "GHSA-xxxx", "summary": "Prototype pollution",
                                         "database_specific": {"severity": "MODERATE"},
                                         "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]})
    return httpx.Response(404)


async def test_cve_lookup_nvd_with_kev():
    r = await cve.lookup("cve-2024-3094", client=mock_client(cve_handler))
    assert "CVSS 10.0 CRITICAL" in r.title
    assert r.findings[0].severity == Severity.CRITICAL and "CISA KEV" in r.findings[0].title
    assert any("tukaani xz 5.6.0" in f.detail for f in r.findings)
    assert "https://example.org/xz" in r.notes


async def test_cve_osv_fallback_and_errors():
    assert cve.normalize_id("ghsa-JFHM-5ghh-2F97") == "GHSA-jfhm-5ghh-2f97"
    r = await cve.lookup("ghsa-XXXX", client=mock_client(cve_handler))
    assert "MODERATE" in r.title and any("npm/lodash" in f.detail for f in r.findings)
    with pytest.raises(SecurityError, match="не знайдено"):
        await cve.lookup("CVE-2099-9999", client=mock_client(cve_handler))
    with pytest.raises(SecurityError, match="Формат"):
        await cve.lookup("hello", client=mock_client(cve_handler))


async def test_brief_filters_by_stack_and_date():
    r = await cve.brief(["chrom"], days=14, client=mock_client(cve_handler), today=date(2026, 11, 6))
    assert [f.title.split(" ")[0] for f in r.findings] == ["CVE-2026-1111"]
    assert r.findings[0].severity == Severity.CRITICAL  # вимагачі
    r_all = await cve.brief([], days=14, client=mock_client(cve_handler), today=date(2026, 11, 6))
    assert len(r_all.findings) == 2 and "/stack" in r_all.summary
