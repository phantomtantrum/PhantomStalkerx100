"""Безпекові slash-команди. Кожна повертає Outcome; важкі перевірки — як RunTask (у фоні зі спінером)."""

from __future__ import annotations

import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from phantomstalker.security import (
    audit,
    breach,
    cryptobox,
    cve,
    deps,
    evm,
    exif,
    filecheck,
    incident,
    logs,
    passwords,
    phish,
    secrets_scan,
    sshaudit,
)
from phantomstalker.security.report import Report

if TYPE_CHECKING:
    from phantomstalker.core.commands import Outcome


@dataclass
class RunTask:
    """Фонова задача: job повертає Report або інший Outcome. sync=True — запуск у потоці."""

    title: str
    job: Callable[[], Awaitable[Any]] | Callable[[], Any]
    sync: bool = False


@dataclass
class ShowReport:
    report: Report


@dataclass
class Explain:
    """Передати текст Claude-аналітику на пояснення."""

    text: str
    preface: str = "Поясни цей звіт безпеки: що серйозно, що ні, і що зробити по кроках."


@dataclass
class Copyable:
    """Результат, який варто скопіювати (зашифрований текст тощо)."""

    title: str
    text: str
    details: list[str] = field(default_factory=list)


def _split(args: str) -> list[str]:
    try:
        return shlex.split(args)
    except ValueError:
        return args.split()


class SecurityCommands:
    """Міксин для CommandProcessor: очікує self.settings, self.crm, self.last_report()."""

    settings: Any
    crm: Any
    last_report: Callable[[], str]

    def _need_key(self, name: str, what: str) -> Outcome | None:
        from phantomstalker.core.commands import Say
        from phantomstalker.services.settings import SECRETS

        if self.settings.has_secret(name):
            return None
        _k, env, label, where = SECRETS[name]
        return Say(f"Для {what} потрібен ключ: {label}",
                   [f"отримати: {where}", f"додати: /key {name}  (або змінна {env})"], kind="error")

    # --- машина й сервери ---
    def cmd_audit(self, _: str) -> Outcome:
        return RunTask("Перевіряю систему", audit.audit, sync=True)

    def cmd_ssh(self, args: str) -> Outcome:
        return RunTask("Перевіряю SSH", lambda: sshaudit.audit_ssh(args or None), sync=True)

    def cmd_logs(self, args: str) -> Outcome:
        def job() -> Report:
            text, source = logs.load(args.strip() or None)
            return logs.analyze(text, source)

        return RunTask("Аналізую журнали", job, sync=True)

    # --- код ---
    def cmd_secrets(self, args: str) -> Outcome:
        path = args.strip() or "."
        return RunTask(f"Шукаю секрети в {path}", lambda: secrets_scan.scan(path), sync=True)

    def cmd_deps(self, args: str) -> Outcome:
        path = args.strip() or "."
        return RunTask("Перевіряю залежності в OSV.dev", lambda: deps.scan(path))

    def cmd_cve(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        if not args.strip():
            raise CommandError("Вкажи ідентифікатор: /cve CVE-2024-3094")
        return RunTask(f"Шукаю {cve.normalize_id(args)}", lambda: cve.lookup(args))

    def cmd_brief(self, args: str) -> Outcome:
        days = int(args) if args.strip().isdigit() else 14
        return RunTask("Збираю безпековий дайджест", lambda: cve.brief(self.settings.stack, days))

    def cmd_stack(self, args: str) -> Outcome:
        from phantomstalker.core.commands import Say

        if not args.strip():
            current = ", ".join(self.settings.stack) or "не задано"
            return Say(f"Твій стек: {current}", ["/stack windows, chrome, python, nginx, docker",
                                                 "використовується в /brief для фільтрації вразливостей"])
        self.settings.set("stack", args)
        return Say("Стек збережено", [", ".join(self.settings.stack)], kind="ok")

    # --- фішинг і файли ---
    def cmd_phish(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        text = args.strip()
        if not text:
            raise CommandError("Встав текст листа/SMS/посилання або шлях до .eml: /phish <текст>")
        if cryptobox.looks_like_path(text):
            text = Path(text).expanduser().read_text(encoding="utf-8", errors="replace")
        return ShowReport(phish.analyze(text))

    def cmd_file(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        parts = _split(args)
        if not parts:
            raise CommandError("Формат: /file <шлях> [очікуваний SHA-256]")
        key = self.settings.get_secret("abusech")
        return RunTask("Перевіряю файл", lambda: filecheck.check(parts[0], parts[1] if len(parts) > 1 else "", key))

    # --- паролі й акаунти ---
    def cmd_pwned(self, _: str) -> Outcome:
        from phantomstalker.core.commands import AskSecret

        return AskSecret("введи пароль для перевірки (не зберігається й не надсилається)",
                         lambda pw: RunTask("Перевіряю пароль", lambda: passwords.check(pw)))

    def cmd_passgen(self, args: str) -> Outcome:
        return ShowReport(passwords.passgen_report(args))

    def cmd_breach(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError, Confirm

        email = args.strip()
        if not breach.valid_email(email):
            raise CommandError("Формат: /breach твоя@пошта.com")
        if missing := self._need_key("hibp", "перевірки пошти"):
            return missing
        key = self.settings.get_secret("hibp")

        def run() -> Outcome:
            async def job() -> Report:
                report = await breach.check(email, key)
                self.crm.log_footprint(breach.value_hash(email), "hibp", report.summary or report.title)
                return report

            return RunTask("Перевіряю витоки", job)

        return Confirm(f"Перевіряємо лише ВЛАСНІ адреси. {email} належить тобі, і ти згоден надіслати її до "
                       "haveibeenpwned.com? (y/n)", run)

    def cmd_incident(self, args: str) -> Outcome:
        return ShowReport(incident.report(args))

    # --- крипта ---
    def cmd_checkaddr(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        parts = args.split()
        if not parts:
            raise CommandError("Формат: /checkaddr <адреса> [очікувана адреса]")
        return RunTask("Перевіряю адресу", lambda: evm.check_address(parts[0], parts[1] if len(parts) > 1 else ""))

    def cmd_approvals(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        parts = args.split()
        if not parts:
            raise CommandError("Формат: /approvals <адреса гаманця> [eth|base|arbitrum|optimism|polygon|bsc]")
        if missing := self._need_key("etherscan", "перевірки дозволів"):
            return missing
        key = self.settings.get_secret("etherscan")
        chain = parts[1] if len(parts) > 1 else "eth"
        return RunTask("Читаю дозволи токенів", lambda: evm.approvals(parts[0], key, chain))

    # --- приватність ---
    def cmd_encrypt(self, args: str) -> Outcome:
        from phantomstalker.core.commands import AskSecret, CommandError, Say

        target = args.strip()
        if not target:
            raise CommandError("Формат: /encrypt <текст або шлях до файлу>")
        is_file = cryptobox.looks_like_path(target)

        def first(pw: str) -> Outcome:
            if len(pw) < cryptobox.MIN_PASSPHRASE:
                return Say(f"Пароль надто короткий — мінімум {cryptobox.MIN_PASSPHRASE} символів", kind="error")

            def second(pw2: str) -> Outcome:
                if pw2 != pw:
                    return Say("Паролі не збігаються", kind="error")
                if is_file:
                    return RunTask("Шифрую файл", lambda: Copyable(
                        "Файл зашифровано", "", [str(cryptobox.encrypt_file(target, pw)),
                                                  "розшифрувати: /decrypt <файл> або age -d"]), sync=True)
                return RunTask("Шифрую", lambda: Copyable(
                    "Зашифровано (скопійовано в буфер)", cryptobox.encrypt_text(target, pw),
                    ["надішли будь-яким месенджером; розшифрувати: /decrypt або age -d"]), sync=True)

            return AskSecret("повтори пароль", second)

        return AskSecret("придумай пароль для шифрування (мінімум 8 символів)", first)

    def cmd_decrypt(self, args: str) -> Outcome:
        from phantomstalker.core.commands import AskSecret, CommandError

        target = args.strip()
        if not target:
            raise CommandError("Встав зашифрований блок або шлях до .age-файлу: /decrypt <...>")
        is_file = cryptobox.looks_like_path(target)

        def run(pw: str) -> Outcome:
            if is_file:
                return RunTask("Розшифровую файл", lambda: Copyable(
                    "Файл розшифровано", "", [str(cryptobox.decrypt_file(target, pw))]), sync=True)
            return RunTask("Розшифровую", lambda: Copyable(
                "Розшифровано", cryptobox.decrypt_text(target, pw), []), sync=True)

        return AskSecret("пароль для розшифрування", run)

    def cmd_exif(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        parts = _split(args)
        if not parts:
            raise CommandError("Формат: /exif <фото.jpg> [--show]  (--show — лише показати, без очищення)")
        clean = "--show" not in parts
        path = next(p for p in parts if p != "--show")
        return RunTask("Читаю метадані", lambda: exif.process(path, clean=clean), sync=True)

    # --- ШІ ---
    def cmd_explain(self, args: str) -> Outcome:
        from phantomstalker.core.commands import CommandError

        report = self.last_report()
        if not report and not args.strip():
            raise CommandError("Спершу запусти перевірку (/audit, /secrets, /phish…) або допиши питання: /explain <текст>")
        text = report + (f"\n\nДодатково від користувача: {args.strip()}" if args.strip() else "")
        return Explain(text)
