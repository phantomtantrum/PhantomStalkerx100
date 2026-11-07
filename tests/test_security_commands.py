from datetime import date

import pytest

from phantomstalker.core.commands import (
    AskSecret,
    CommandProcessor,
    Confirm,
    Say,
    match_commands,
    redact,
)
from phantomstalker.core.security_commands import Copyable, Explain, RunTask, ShowReport
from phantomstalker.services.crm import CRMRepository
from phantomstalker.services.settings import SettingsService


@pytest.fixture
def proc(conn, keyring_backend):
    report = {"text": ""}
    p = CommandProcessor(CRMRepository(conn), SettingsService(conn, keyring_backend), lambda: "",
                         today=lambda: date(2026, 11, 6), last_report=lambda: report["text"])
    p._report = report
    return p


def test_security_commands_are_listed_and_grouped(proc):
    names = {c.name for c in match_commands("/")}
    assert {"audit", "ssh", "logs", "secrets", "deps", "cve", "brief", "phish", "file", "pwned", "passgen",
            "breach", "incident", "checkaddr", "approvals", "encrypt", "decrypt", "exif", "explain", "keys"} <= names
    help_text = "\n".join(proc.run("/help").details)
    assert "Безпека:" in help_text and "/audit" in help_text


def test_background_tasks(proc):
    for line in ("/audit", "/ssh", "/logs", "/secrets", "/deps", "/cve CVE-2024-3094", "/brief", "/file x",
                 "/checkaddr 0xabc", "/exif a.jpg"):
        assert isinstance(proc.run(line), RunTask), line
    assert proc.run("/audit").sync and not proc.run("/deps").sync


def test_instant_reports(proc):
    assert isinstance(proc.run("/passgen"), ShowReport)
    assert isinstance(proc.run("/incident telegram"), ShowReport)
    assert isinstance(proc.run("/phish https://paypa1.com/login"), ShowReport)
    assert proc.run("/phish").kind == "error"
    assert proc.run("/cve").kind == "error"


def test_pwned_asks_secret_then_runs(proc):
    out = proc.run("/pwned")
    assert isinstance(out, AskSecret)
    assert isinstance(out.on_submit("hunter2"), RunTask)


def test_key_required_commands(proc, keyring_backend):
    assert "hibp" in "\n".join(proc.run("/breach me@example.com").details)
    assert proc.run("/approvals 0xabc").kind == "error"
    proc.settings.set_secret("hibp", "k")
    confirm = proc.run("/breach me@example.com")
    assert isinstance(confirm, Confirm) and "ВЛАСНІ" in confirm.question
    assert isinstance(confirm.on_yes(), RunTask)
    assert proc.run("/breach not-email").kind == "error"


def test_encrypt_flow(proc):
    ask = proc.run("/encrypt секретне повідомлення")
    assert isinstance(ask, AskSecret)
    assert ask.on_submit("short").kind == "error"
    again = ask.on_submit("correct horse")
    assert isinstance(again, AskSecret)
    assert again.on_submit("different pass").kind == "error"
    task = again.on_submit("correct horse")
    assert isinstance(task, RunTask) and task.sync
    result = task.job()
    assert isinstance(result, Copyable) and result.text.startswith("-----BEGIN AGE")
    dec = proc.run("/decrypt " + result.text.replace("\n", " "))
    plain = dec.on_submit("correct horse").job()
    assert plain.text == "секретне повідомлення"


def test_explain_needs_report(proc):
    assert proc.run("/explain").kind == "error"
    proc._report["text"] = "Аудит: фаєрвол вимкнено"
    out = proc.run("/explain як це на macOS?")
    assert isinstance(out, Explain) and "фаєрвол" in out.text and "macOS" in out.text


def test_keys_and_redaction(proc):
    out = proc.run("/keys")
    assert all(name in "\n".join(out.details) for name in ("anthropic", "hibp", "etherscan", "abusech"))
    assert isinstance(proc.run("/key hibp"), AskSecret)
    assert proc.run("/key nope").kind == "error"
    secret = "sk-ant-" + "x" * 30
    from phantomstalker.core.commands import VerifyKey, clean_key

    assert isinstance(proc.run(f"/key {secret}"), VerifyKey)
    assert isinstance(proc.run("/key test"), VerifyKey) and proc.run("/key test").note is None
    assert clean_key(f' "{secret}"\n') == secret
    assert clean_key(f"ANTHROPIC_API_KEY={secret}") == secret
    assert clean_key(f"sk-ant-\n{secret[7:]}") == secret
    assert proc.settings.get_api_key() == secret
    assert redact(f"/key {secret}") == "/key ••••••••"
    assert redact("/key hibp") == "/key hibp"


def test_stack(proc):
    assert "не задано" in proc.run("/stack").title
    proc.run("/stack windows, Chrome , python")
    assert proc.settings.stack == ["windows", "Chrome", "python"]


def test_footprint_logged_as_hash(proc, monkeypatch):
    import phantomstalker.core.security_commands as sc
    from phantomstalker.security.report import Report

    async def fake_check(email, key, client=None):
        return Report("ok", summary="Витоків: 0")

    monkeypatch.setattr(sc.breach, "check", fake_check)
    proc.settings.set_secret("hibp", "k")
    task = proc.run("/breach me@example.com").on_yes()
    import asyncio

    asyncio.run(task.job())
    rows = proc.crm.conn.execute("SELECT value_hash, source FROM footprint_checks").fetchall()
    assert len(rows) == 1 and rows[0]["source"] == "hibp" and "me@example.com" not in rows[0]["value_hash"]
    assert isinstance(Say("x"), Say)
