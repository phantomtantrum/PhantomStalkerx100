import hashlib
import zipfile

import httpx

from phantomstalker.security import filecheck, phish
from phantomstalker.security.report import Severity
from tests.conftest import mock_client


def sev_of(report, needle):
    return next(f.severity for f in report.findings if needle in f.title + f.detail)


def test_url_heuristics():
    assert any("IP-адреса" in m for _, m in phish.analyze_url("http://192.168.1.5/login"))
    assert any("«@»" in m for _, m in phish.analyze_url("https://google.com@evil.example/x"))
    assert any("скорочене" in m for _, m in phish.analyze_url("https://bit.ly/abc"))
    assert any("paypal" in m for _, m in phish.analyze_url("https://paypa1.com"))
    assert any("binance" in m for _, m in phish.analyze_url("https://binance.com.secure-check.ru/login"))
    assert any("monobank" in m for _, m in phish.analyze_url("monobamk-secure.top"))
    assert phish.analyze_url("https://www.monobank.ua/") == []
    assert phish.analyze_url("https://github.com/phantomtantrum") == []


def test_text_verdicts():
    bad = phish.analyze("Терміново підтвердіть акаунт Binance: https://blnance-support.xyz/verify і введіть seed фразу")
    assert "Ймовірно фішинг" in bad.title
    assert sev_of(bad, "сід-фразу") == Severity.CRITICAL
    good = phish.analyze("Привіт! Зустрінемось завтра о 10? Ось план: https://github.com/team/repo")
    assert "Явних ознак" in good.title


EML = """Return-Path: <bounce@mailer-x.ru>
Received: from mailer-x.ru
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=mailer-x.ru; dkim=none; dmarc=fail
From: "PayPal Support" <service@paypal-alerts.co>
Reply-To: help@another-domain.net
Subject: Your account is suspended
Content-Type: text/html; charset=utf-8

<html><body><p>Unusual activity. <a href="http://paypa1-login.com/verify">Verify your account</a></p></body></html>
"""


def test_email_headers():
    r = phish.analyze(EML)
    assert sev_of(r, "SPF: fail") == Severity.HIGH
    assert sev_of(r, "DMARC: fail") == Severity.HIGH
    assert sev_of(r, "Reply-To") == Severity.MEDIUM
    assert sev_of(r, "PayPal Support") == Severity.HIGH
    assert any("paypa1-login.com" in f.title for f in r.findings)
    assert "Тема: Your account is suspended" in r.notes
    assert "Ймовірно фішинг" in r.title


async def test_file_hashes_and_checksum(tmp_path):
    f = tmp_path / "tool.tar.gz"
    f.write_bytes(b"hello world")
    good = hashlib.sha256(b"hello world").hexdigest()
    r = await filecheck.check(str(f), good)
    assert sev_of(r, "збігається") == Severity.OK
    r = await filecheck.check(str(f), "0" * 64)
    assert sev_of(r, "НЕ збігається") == Severity.CRITICAL
    assert any("abusech" in n for n in r.notes)


async def test_file_masquerade_and_macros(tmp_path):
    exe = tmp_path / "invoice.pdf.exe"
    exe.write_bytes(b"MZ\x90\x00rest")
    r = await filecheck.check(str(exe))
    assert sev_of(r, "Подвійне розширення") == Severity.HIGH
    fake_pdf = tmp_path / "scan.pdf"
    fake_pdf.write_bytes(b"MZ\x90\x00")
    assert sev_of(await filecheck.check(str(fake_pdf)), "Windows-програма") == Severity.HIGH
    doc = tmp_path / "report.docm"
    with zipfile.ZipFile(doc, "w") as z:
        z.writestr("word/vbaProject.bin", b"x")
    assert sev_of(await filecheck.check(str(doc)), "макроси") == Severity.MEDIUM


async def test_malwarebazaar(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")

    def found(request: httpx.Request) -> httpx.Response:
        assert request.headers["Auth-Key"] == "k"
        return httpx.Response(200, json={"query_status": "ok", "data": [{"signature": "AgentTesla",
                                                                          "file_type": "exe", "tags": ["rat"]}]})

    r = await filecheck.check(str(f), api_key="k", client=mock_client(found))
    assert sev_of(r, "AgentTesla") == Severity.CRITICAL
    r = await filecheck.check(str(f), api_key="k", client=mock_client(
        lambda req: httpx.Response(200, json={"query_status": "hash_not_found"})))
    assert sev_of(r, "не знайдено") == Severity.OK
