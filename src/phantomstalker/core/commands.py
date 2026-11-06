"""Slash-команди. Чиста логіка без UI: команда → результат (Outcome), який рендерить консоль."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Literal

from phantomstalker.services.copilot import Action, CopilotRequest
from phantomstalker.services.crm import Contact, CRMRepository, humanize_days, parse_user_date
from phantomstalker.core.security_commands import Copyable, Explain, RunTask, SecurityCommands, ShowReport
from phantomstalker.core.theme import THEMES
from phantomstalker.services.settings import SECRETS, SettingsService

# --- результати команд ---------------------------------------------------------


@dataclass
class Say:
    """Рядок «● title» і необов'язкові деталі під ним («⎿ …»)."""

    title: str
    details: list[str] = field(default_factory=list)
    kind: Literal["info", "ok", "error"] = "info"
    react: tuple[str, dict[str, object]] | None = None


@dataclass
class StreamAction:
    request: CopilotRequest


@dataclass
class Confirm:
    question: str
    on_yes: Callable[[], Outcome]


@dataclass
class AskSecret:
    prompt: str
    on_submit: Callable[[str], Outcome]


@dataclass
class Clear:
    pass


@dataclass
class Exit:
    pass


Outcome = Say | StreamAction | Confirm | AskSecret | Clear | Exit | RunTask | ShowReport | Explain | Copyable


@dataclass(frozen=True)
class Command:
    name: str
    usage: str
    help: str
    group: str = ""


_SEC, _AI, _PPL, _SET = "Безпека", "Листування", "Люди", "Налаштування"
COMMANDS: tuple[Command, ...] = (
    Command("help", "", "усі команди й клавіші"),
    Command("audit", "", "аудит захищеності цього комп'ютера", _SEC),
    Command("ssh", "[тека]", "аудит SSH-ключів і налаштувань", _SEC),
    Command("logs", "[файл]", "підбір паролів і підозрілі входи в журналах", _SEC),
    Command("secrets", "[тека]", "API-ключі й паролі в коді та історії git", _SEC),
    Command("deps", "[тека]", "вразливості в залежностях (OSV.dev)", _SEC),
    Command("cve", "<CVE-…>", "що це за вразливість і чи її атакують", _SEC),
    Command("brief", "[днів]", "свіжі активно експлуатовані вразливості", _SEC),
    Command("stack", "[софт, …]", "твій софт для /brief", _SEC),
    Command("phish", "<текст|посилання|.eml>", "аналіз на фішинг", _SEC),
    Command("file", "<шлях> [sha256]", "хеші, підробка розширення, база шкідливого ПЗ", _SEC),
    Command("pwned", "", "чи злитий пароль + стійкість", _SEC),
    Command("passgen", "[довжина]", "згенерувати пароль і парольну фразу", _SEC),
    Command("breach", "<твоя пошта>", "чи світилася пошта у витоках (HIBP)", _SEC),
    Command("incident", "[що сталося]", "план дій, якщо тебе зламали", _SEC),
    Command("checkaddr", "<0x…> [очікувана]", "перевірка крипто-адреси перед переказом", _SEC),
    Command("approvals", "<0x…> [мережа]", "небезпечні дозволи токенів гаманця", _SEC),
    Command("encrypt", "<текст|файл>", "зашифрувати паролем (age)", _SEC),
    Command("decrypt", "<блок|файл>", "розшифрувати", _SEC),
    Command("exif", "<фото> [--show]", "прибрати GPS і метадані з фото", _SEC),
    Command("explain", "[питання]", "пояснення останнього звіту від ШІ", _SEC),
    Command("polish", "[текст]", "відполірувати (без тексту — останню відповідь)", _AI),
    Command("warmer", "[текст]", "зробити тепліше", _AI),
    Command("formal", "[текст]", "зробити формальніше", _AI),
    Command("shorter", "[текст]", "зробити коротше", _AI),
    Command("translate", "<мова> [текст]", "перекласти", _AI),
    Command("reply", "<повідомлення>", "запропонувати відповідь на отримане", _AI),
    Command("people", "[пошук]", "список людей", _PPL),
    Command("add", "<ім'я> [@нік] [#тег] [нотатки]", "додати людину", _PPL),
    Command("show", "<ім'я>", "картка людини", _PPL),
    Command("note", "<ім'я> <текст>", "дописати нотатку", _PPL),
    Command("met", "<ім'я> [про що]", "відмітити, що ви спілкувались", _PPL),
    Command("date", "<ім'я> <ДД.ММ> <подія>", "важлива дата (щорічно)", _PPL),
    Command("rm", "<ім'я>", "видалити людину", _PPL),
    Command("remind", "", "нагадування", _PPL),
    Command("name", "<ім'я>", "перейменувати фантома", _SET),
    Command("tone", "<опис>", "твій стиль письма", _SET),
    Command("color", "[колір]", "колір акценту інтерфейсу", _SET),
    Command("model", "[id]", "модель Claude", _SET),
    Command("key", "[сервіс]", "ключ API: anthropic, hibp, etherscan, abusech", _SET),
    Command("keys", "", "які ключі API налаштовано", _SET),
    Command("cd", "[тека]", "змінити поточну теку (для /secrets, /deps, /file)"),
    Command("clear", "", "очистити розмову"),
    Command("exit", "", "вийти"),
)

_ACTIONS = {
    "polish": Action.POLISH,
    "warmer": Action.WARMER,
    "formal": Action.FORMAL,
    "shorter": Action.SHORTER,
    "reply": Action.REPLY,
}


def match_commands(prefix: str) -> list[Command]:
    """Підказки для «/по…»."""
    word = prefix.lstrip("/").split(" ", 1)[0].casefold()
    return [c for c in COMMANDS if c.name.startswith(word)]


# --- розбір аргументів ---------------------------------------------------------


class CommandError(ValueError):
    pass


def resolve_contact(crm: CRMRepository, args: str) -> tuple[Contact, str]:
    """Знаходить людину за початком аргументів (ім'я може бути з кількох слів).

    Повертає (контакт, решта_аргументів).
    """
    words = args.split()
    if not words:
        raise CommandError("Вкажи ім'я людини.")
    contacts = crm.list_contacts()
    by_name = {c.name.casefold(): c for c in contacts}
    for i in range(len(words), 0, -1):
        candidate = " ".join(words[:i]).casefold().lstrip("@")
        if candidate in by_name:
            return by_name[candidate], " ".join(words[i:])
        handle_hits = [c for c in contacts if c.handle and c.handle.casefold().lstrip("@") == candidate]
        if len(handle_hits) == 1:
            return handle_hits[0], " ".join(words[i:])
    first = words[0].casefold()
    hits = [c for c in contacts if c.name.casefold().startswith(first)]
    if len(hits) == 1:
        return hits[0], " ".join(words[1:])
    if len(hits) > 1:
        raise CommandError("Кількох людей звати схоже: " + ", ".join(c.name for c in hits))
    raise CommandError(f"Не знаю нікого на ім'я «{words[0]}». Додай через /add.")


def parse_add(args: str) -> tuple[str, str, list[str], str]:
    """`Олена Петренко @olena #друзі #гори любить каву` → (ім'я, нік, теги, нотатки)."""
    name_parts: list[str] = []
    notes: list[str] = []
    handle, tags = "", []
    seen_marker = False
    for token in args.split():
        if token.startswith("@") and len(token) > 1:
            handle, seen_marker = token, True
        elif token.startswith("#") and len(token) > 1:
            tags.append(token[1:])
            seen_marker = True
        elif seen_marker:
            notes.append(token)
        else:
            name_parts.append(token)
    name = " ".join(name_parts).strip()
    if not name:
        raise CommandError("Вкажи ім'я: /add Олена @olena #друзі")
    return name, handle, tags, " ".join(notes)


def parse_day(raw: str) -> date:
    """ДД.ММ (рік не важливий) або повна дата."""
    raw = raw.strip()
    parts = raw.split(".")
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        try:
            return date(2000, int(parts[1]), int(parts[0]))  # 2000 — високосний, 29.02 теж ок
        except ValueError as exc:
            raise CommandError("Такої дати не буває.") from exc
    try:
        return parse_user_date(raw)
    except ValueError as exc:
        raise CommandError("Дата: ДД.ММ, ДД.ММ.РРРР або РРРР-ММ-ДД.") from exc


def contact_line(c: Contact) -> str:
    bits = [c.name]
    if c.handle:
        bits.append(c.handle)
    if c.tags:
        bits.append(" ".join(f"#{t}" for t in c.tags))
    return " · ".join(bits)


# --- виконання -----------------------------------------------------------------


class CommandProcessor(SecurityCommands):
    def __init__(self, crm: CRMRepository, settings: SettingsService,
                 last_output: Callable[[], str], today: Callable[[], date] = date.today,
                 last_report: Callable[[], str] = lambda: "") -> None:
        self.crm = crm
        self.settings = settings
        self._last_output = last_output
        self._today = today
        self.last_report = last_report

    def run(self, line: str) -> Outcome:
        name, _, args = line.strip().lstrip("/").partition(" ")
        name, args = name.casefold(), args.strip()
        handler = getattr(self, f"cmd_{name}", None)
        if handler is None:
            hint = match_commands(name)
            extra = [f"може, /{hint[0].name}?"] if hint else ["/help — список команд"]
            return Say(f"Невідома команда /{name}", extra, kind="error")
        try:
            return handler(args)
        except CommandError as exc:
            return Say(str(exc), kind="error")
        except ValueError as exc:
            return Say(str(exc), kind="error")

    # --- довідка ---
    def cmd_help(self, _: str) -> Outcome:
        width = max(len(c.name) + len(c.usage) for c in COMMANDS) + 3
        lines: list[str] = []
        for group in (_SEC, _AI, _PPL, _SET, ""):
            items = [c for c in COMMANDS if c.group == group]
            if items:
                lines.append(f"{group or 'Інше'}:")
                lines += [f"  /{c.name} {c.usage}".ljust(width + 2) + c.help for c in items]
                lines.append("")
        lines += [
            "Просто пиши — і фантом відповість. @ім'я додасть у розмову твої нотатки про людину.",
            "Багаторядковий текст можна вставляти — переноси збережуться.",
            "Tab — доповнити команду · ↑/↓ — історія · Esc — перервати · Ctrl+C — вихід",
        ]
        return Say("Команди", lines)

    # --- ко-пілот ---
    def _text_or_last(self, args: str) -> str:
        text = args or self._last_output()
        if not text.strip():
            raise CommandError("Додай текст після команди, наприклад: /polish привіт як ти")
        return text

    def _action(self, action: Action, args: str) -> Outcome:
        if action is Action.REPLY and not args:
            raise CommandError("Встав отримане повідомлення: /reply <текст>")
        return StreamAction(CopilotRequest(action, self._text_or_last(args)))

    def cmd_polish(self, args: str) -> Outcome:
        return self._action(Action.POLISH, args)

    def cmd_warmer(self, args: str) -> Outcome:
        return self._action(Action.WARMER, args)

    def cmd_formal(self, args: str) -> Outcome:
        return self._action(Action.FORMAL, args)

    def cmd_shorter(self, args: str) -> Outcome:
        return self._action(Action.SHORTER, args)

    def cmd_reply(self, args: str) -> Outcome:
        return self._action(Action.REPLY, args)

    def cmd_translate(self, args: str) -> Outcome:
        language, _, text = args.partition(" ")
        if not language:
            raise CommandError("Вкажи мову: /translate англійська [текст]")
        return StreamAction(CopilotRequest(Action.TRANSLATE, self._text_or_last(text.strip()),
                                           target_language=language))

    # --- люди ---
    def cmd_people(self, args: str) -> Outcome:
        contacts = self.crm.list_contacts(args or None)
        if not contacts:
            return Say("Нікого не знайшов" if args else "Поки нікого немає", ["/add Олена @olena #друзі"])
        today = self._today()
        width = max(len(contact_line(c)) for c in contacts) + 2
        lines = [contact_line(c).ljust(width) + humanize_days(c.days_since_contact(today))
                 for c in contacts]
        return Say(f"Люди ({len(contacts)})", lines)

    def cmd_add(self, args: str) -> Outcome:
        name, handle, tags, notes = parse_add(args)
        if any(c.name.casefold() == name.casefold() for c in self.crm.list_contacts()):
            raise CommandError(f"{name} вже є у списку — /show {name}")
        c = self.crm.add_contact(name, handle, tags, notes)
        details = [contact_line(c)] + ([notes] if notes else [])
        return Say("Додано", details, kind="ok", react=("contact_added", {"name": c.name}))

    def cmd_show(self, args: str) -> Outcome:
        c, _ = resolve_contact(self.crm, args)
        today = self._today()
        lines = [f"востаннє: {humanize_days(c.days_since_contact(today))}"]
        for d in self.crm.list_important_dates(c.id):
            nxt = d.next_occurrence(today)
            left = f" — через {(nxt - today).days} дн." if nxt else ""
            lines.append(f"{d.label}: {d.date:%d.%m}{left}")
        if c.notes.strip():
            lines += c.notes.strip().splitlines()
        for item in self.crm.list_interactions(c.id)[:3]:
            lines.append(f"{item.date:%d.%m.%Y}" + (f" — {item.summary}" if item.summary else ""))
        return Say(contact_line(c), lines)

    def cmd_note(self, args: str) -> Outcome:
        c, text = resolve_contact(self.crm, args)
        if not text:
            raise CommandError(f"Що записати? /note {c.name} любить каву")
        notes = (c.notes.rstrip() + "\n" + text).strip()
        self.crm.update_contact(c.id, notes=notes)
        return Say(f"Записав про {c.name}", [text], kind="ok", react=("contact_updated", {"name": c.name}))

    def cmd_met(self, args: str) -> Outcome:
        c, summary = resolve_contact(self.crm, args)
        self.crm.mark_contacted(c.id, summary=summary)
        return Say(f"Відмітив розмову: {c.name}", [summary] if summary else [], kind="ok",
                   react=("contacted", {"name": c.name}))

    def cmd_date(self, args: str) -> Outcome:
        c, rest = resolve_contact(self.crm, args)
        raw, _, label = rest.partition(" ")
        if not raw or not label.strip():
            raise CommandError(f"Формат: /date {c.name} 14.03 День народження")
        item = self.crm.add_important_date(c.id, label, parse_day(raw))
        return Say(f"Запам'ятав дату: {c.name}", [f"{item.label}: {item.date:%d.%m}"], kind="ok",
                   react=("date_added", {"label": item.label}))

    def cmd_rm(self, args: str) -> Outcome:
        c, _ = resolve_contact(self.crm, args)

        def yes() -> Outcome:
            self.crm.delete_contact(c.id)
            return Say(f"Видалено: {c.name}", kind="ok", react=("contact_deleted", {"name": c.name}))

        return Confirm(f"Видалити {c.name} разом з історією? (y/n)", yes)

    def cmd_remind(self, _: str) -> Outcome:
        items = self.crm.reminders(self._today(), stale_after_days=self.settings.stale_after_days)
        if not items:
            return Say("Нагадувань немає — з усіма на зв'язку")
        return Say("Нагадування", [r.text for r in items])

    # --- налаштування ---
    def cmd_name(self, args: str) -> Outcome:
        if not args:
            return Say(f"Мене звати {self.settings.phantom_name}", ["/name <нове ім'я>"])
        self.settings.set("phantom_name", args)
        return Say(f"Тепер мене звати {args}", kind="ok", react=("settings_saved", {}))

    def cmd_tone(self, args: str) -> Outcome:
        if not args:
            return Say("Твій стиль", [self.settings.tone_profile, "/tone <опис>"])
        self.settings.set("tone_profile", args)
        return Say("Запам'ятав твій стиль", [args], kind="ok", react=("settings_saved", {}))

    def cmd_color(self, args: str) -> Outcome:
        if not args:
            now = self.settings.get("color")
            lines = [f"{t.name:<10}{t.label}" + ("  ← зараз" if t.name == now else "") for t in THEMES.values()]
            return Say("Кольори", [*lines, "/color <назва>"])
        name = args.split()[0].casefold()
        by_label = {t.label: t.name for t in THEMES.values()}
        name = by_label.get(name, name)
        if name not in THEMES:
            raise CommandError(f"Немає кольору «{args}». Доступні: " + ", ".join(THEMES))
        self.settings.set("color", name)
        return Say(f"Колір: {THEMES[name].label}", kind="ok", react=("settings_saved", {}))

    def cmd_model(self, args: str) -> Outcome:
        if not args:
            return Say(f"Модель: {self.settings.model}")
        self.settings.set("model", args)
        return Say(f"Модель: {args}", kind="ok")

    def cmd_key(self, args: str) -> Outcome:
        name = (args.split() or ["anthropic"])[0].casefold()
        if name not in SECRETS and len(args.strip()) >= 20:  # вставили сам ключ: /key sk-ant-…
            self.settings.set_secret("anthropic", args.strip())
            return Say("Ключ Anthropic API збережено в keyring", kind="ok", react=("settings_saved", {}))
        if name not in SECRETS:
            raise CommandError("Сервіси: " + ", ".join(SECRETS))
        label = SECRETS[name][2]

        def save(value: str) -> Outcome:
            if not value.strip():
                return Say("Скасовано")
            try:
                self.settings.set_secret(name, value)
            except Exception as exc:
                return Say("Не вдалося зберегти в keyring", [type(exc).__name__,
                           f"можна задати змінну {SECRETS[name][1]} у .env"], kind="error")
            return Say(f"Ключ {label} збережено в keyring", kind="ok", react=("settings_saved", {}))

        return AskSecret(f"встав ключ {label} і натисни Enter (Esc — скасувати)", save)

    def cmd_keys(self, _: str) -> Outcome:
        lines = []
        for name, (_k, env, label, where) in SECRETS.items():
            mark = "✓" if self.settings.has_secret(name) else "·"
            lines.append(f"{mark} {name:<10} {label}" + ("" if self.settings.has_secret(name) else f" — {where}"))
        return Say("Ключі API", [*lines, "", "/key <сервіс> — додати; значення ніде не показуються"])

    def cmd_cd(self, args: str) -> Outcome:
        import os
        from pathlib import Path

        target = Path(args.strip() or "~").expanduser()
        try:
            os.chdir(target)
        except OSError as exc:
            raise CommandError(f"Не можу перейти в {target}: {exc.strerror or exc}") from exc
        return Say(f"Тека: {Path.cwd()}")

    def cmd_clear(self, _: str) -> Outcome:
        return Clear()

    def cmd_exit(self, _: str) -> Outcome:
        return Exit()

    cmd_quit = cmd_exit


def redact(line: str) -> str:
    """Для стрічки й історії: прибирає значення ключа з «/key <значення>»."""
    parts = line.strip().split(maxsplit=1)
    if len(parts) == 2 and parts[0].casefold() == "/key" and parts[1].split()[0].casefold() not in SECRETS:
        return "/key ••••••••"
    return line


def mention_context(crm: CRMRepository, text: str, today: date | None = None) -> str:
    """Для «@Олена» у повідомленні додає нотатки користувача про цю людину."""
    lowered = text.casefold()
    today = today or date.today()
    blocks = []
    for c in crm.list_contacts():
        keys = [c.name.casefold()] + ([c.handle.casefold().lstrip("@")] if c.handle else [])
        if any(f"@{k}" in lowered for k in keys):
            parts = [f"name: {c.name}"]
            if c.tags:
                parts.append("tags: " + ", ".join(c.tags))
            parts.append(f"last contact: {humanize_days(c.days_since_contact(today))}")
            for d in crm.list_important_dates(c.id):
                parts.append(f"{d.label}: {d.date:%d.%m}")
            if c.notes.strip():
                parts.append("notes: " + c.notes.strip())
            blocks.append("<contact>\n" + "\n".join(parts) + "\n</contact>")
    return "\n".join(blocks)


__all__ = [
    "COMMANDS",
    "AskSecret",
    "Clear",
    "Command",
    "CommandProcessor",
    "Confirm",
    "Exit",
    "Outcome",
    "Say",
    "StreamAction",
    "match_commands",
    "redact",
    "mention_context",
    "parse_add",
    "parse_day",
    "resolve_contact",
]
