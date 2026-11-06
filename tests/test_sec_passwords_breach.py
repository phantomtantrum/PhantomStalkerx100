import hashlib
import re

import httpx
import pytest

from phantomstalker.security import breach, incident, passwords
from phantomstalker.security.report import SecurityError, Severity
from tests.conftest import mock_client


def test_entropy_ranks_passwords():
    weak, mid, strong = passwords.entropy("password1"), passwords.entropy("Tr0ub4dor&3"), passwords.entropy(
        "correct-horse-battery-staple-91")
    assert weak < mid < strong
    assert passwords.rating(passwords.entropy("qwerty"))[0] == Severity.CRITICAL
    assert passwords.rating(passwords.entropy("x7$Kp!2mQz@9vLw#4"))[0] == Severity.OK
    assert passwords.entropy("aaaaaaaaaaaa") < passwords.entropy("aqzmwlxnskeo")


def range_handler(password: str, count: int):
    digest = hashlib.sha1(password.encode()).hexdigest().upper()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/range/" + digest[:5])  # лише префікс
        assert password not in str(request.url) and digest[5:] not in str(request.url)
        assert request.headers.get("Add-Padding") == "true"
        lines = ["0018A45C4D1DEF81644B54AB7F969B88D65:0", f"{digest[5:]}:{count}", "FFFFF00000000000000000000000000000:3"]
        return httpx.Response(200, text="\r\n".join(lines))

    return handler


async def test_pwned_check_found_and_clean():
    r = await passwords.check("password1", client=mock_client(range_handler("password1", 2427155)))
    assert any(f.severity == Severity.CRITICAL and "2 427 155" in f.title for f in r.findings)
    r = await passwords.check("unique-Pass-19x!", client=mock_client(range_handler("unique-Pass-19x!", 0)))
    assert any(f.severity == Severity.OK and "не знайдено" in f.title for f in r.findings)
    assert all("unique-Pass-19x!" not in f.title + f.detail for f in r.findings)
    with pytest.raises(SecurityError):
        await passwords.check("")


def test_generators():
    pw = passwords.generate_password(24)
    assert len(pw) == 24 and re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)
    phrase, bits = passwords.generate_passphrase(6)
    assert len(phrase.split("-")) == 6 and bits > 100
    assert passwords.generate_password(24) != passwords.generate_password(24)
    report = passwords.passgen_report("32")
    assert len(report.findings[0].title) == 32


async def test_breach_found_none_and_errors():
    def found(request):
        assert request.headers["hibp-api-key"] == "k"
        return httpx.Response(200, json=[
            {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "Canva", "Title": "Canva", "BreachDate": "2019-05-24", "DataClasses": ["Email addresses", "Names"]}])

    r = await breach.check("me@example.com", "k", client=mock_client(found))
    assert r.findings[0].severity == Severity.LOW and "Canva" in r.findings[0].title  # новіші перші
    assert any(f.severity == Severity.HIGH and "Adobe" in f.title for f in r.findings)
    assert r.summary == "Витоків: 2 · з паролями: 1"
    r = await breach.check("me@example.com", "k", client=mock_client(lambda req: httpx.Response(404)))
    assert r.findings[0].severity == Severity.OK
    with pytest.raises(SecurityError, match="ключ"):
        await breach.check("me@example.com", "bad", client=mock_client(lambda req: httpx.Response(401)))
    with pytest.raises(SecurityError):
        await breach.check("not-an-email", "k")
    assert breach.value_hash(" Me@Example.com ") == breach.value_hash("me@example.com")


def test_incident_playbooks():
    assert incident.find("зламали телеграм").key == "telegram"
    assert incident.find("вкрали USDT з metamask").key == "crypto"
    r = incident.report("telegram")
    assert r.checklist and r.findings[0].detail == "негайно"
    assert len(incident.report("").findings) == len(incident.PLAYBOOKS)
    generic = incident.report("щось дивне з роутером")
    assert "/explain" in generic.notes[0]
