"""Мінімалістичні віджети консолі: шапка з написом, стрічка, рядок статусу, поле вводу, підказки.

Усі кольори — імена ANSI з палітри терміналу користувача (див. core/theme.py).
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Input, Static

from phantomstalker import __version__
from phantomstalker.core.commands import Command, Say
from phantomstalker.core.persona import PersonaEngine
from phantomstalker.core.theme import ERROR, GAIN, MUTED, TEXT, current
from phantomstalker.security.report import Report, Severity
from phantomstalker.core import wordmark

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def welcome(location: str, available_width: int = 120) -> RenderableType:
    theme = current()
    logo = wordmark.render(available_width - 4, style=TEXT)  # мінус відступи
    info = Text()
    info.append(f"v{__version__}", style=MUTED)
    info.append("  ·  ", style=MUTED)
    info.append("/audit", style=f"bold {theme.accent}")
    info.append(" — перевірити цей комп'ютер  ·  ", style=MUTED)
    info.append("/help", style=f"bold {theme.accent}")
    info.append(" — усі команди\n", style=MUTED)
    info.append(location, style=MUTED)
    return Padding(Group(logo, Text(""), info), (1, 0, 0, 1))  # без рамки — як після figlet у терміналі


def user_line(text: str) -> RenderableType:
    return Text(f"> {text}", style=MUTED)


def bullet(body: RenderableType, color: str | None = None) -> RenderableType:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=1, no_wrap=True)
    grid.add_column(ratio=1)
    grid.add_row(Text("●", style=color or TEXT), body)
    return grid


def phantom_message(text: str) -> RenderableType:
    # ansi_dark: підсвітка коду теж з палітри терміналу, без власного фону
    md = Markdown(text, code_theme="ansi_dark", inline_code_theme="ansi_dark") if text else Text("")
    return bullet(md)


def say(result: Say) -> RenderableType:
    error = result.kind == "error"
    body = Text(result.title, style="bold")
    for i, line in enumerate(result.details):
        body.append("\n")
        body.append("⎿  " if i == 0 else "   ", style=MUTED)
        body.append(line, style="" if error else MUTED)
    return bullet(body, ERROR if error else None)


ICONS: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("✗", f"bold {ERROR}"),
    Severity.HIGH: ("✗", ERROR),
    Severity.MEDIUM: ("!", "yellow"),
    Severity.LOW: ("·", "yellow"),
    Severity.INFO: ("i", MUTED),
    Severity.OK: ("✓", GAIN),
}
NEWLINE_MARK = "⏎"


def report(r: Report) -> RenderableType:
    """Звіт інструменту безпеки: заголовок, оцінка, знахідки від найсерйозніших."""
    head = Text(r.title, style="bold")
    if r.score is not None and not r.checklist:
        color = GAIN if r.score >= 80 else "yellow" if r.score >= 50 else ERROR
        head.append(f"   {r.score}/100", style=f"bold {color}")
    if r.summary:
        head.append(f"\n{r.summary}", style=MUTED)
    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=len(str(len(r.findings))) + 1 if r.checklist else 1, no_wrap=True)
    rows.add_column(ratio=1)
    findings = r.findings if r.checklist else r.sorted_findings()
    for i, f in enumerate(findings, 1):
        icon, style = (f"{i}.", MUTED) if r.checklist else ICONS[f.severity]
        body = Text(f.title, style="bold" if f.severity >= Severity.HIGH and not r.checklist else "")
        if f.detail:
            body.append(f"\n{f.detail}", style=MUTED)
        if f.fix:
            body.append("\n→ ", style=current().accent)
            body.append(f.fix)
        rows.add_row(Text(icon, style=style), body)
    parts: list[RenderableType] = [head, Text(""), rows]
    for note in r.notes:
        parts.append(Text(note, style=f"italic {MUTED}"))
    if r.issues and not r.checklist:
        parts.append(Text("/explain — пояснення й план виправлення від ШІ", style=MUTED))
    return bullet(Group(*parts), ERROR if r.worst >= Severity.HIGH and not r.checklist else None)


def copyable(title: str, text: str, details: list[str]) -> RenderableType:
    body = Text(title, style="bold")
    if text:
        body.append("\n" + text.rstrip("\n"))
    for line in details:
        body.append("\n" + line, style=MUTED)
    return bullet(body)


class Entry(Static):
    """Один запис у стрічці."""

    DEFAULT_CSS = "Entry { margin-bottom: 1; }"

    def __init__(self, body: RenderableType, **kwargs) -> None:
        super().__init__(body, **kwargs)
        self._body = body

    @property
    def body(self) -> RenderableType:
        return self._body

    def update(self, body: RenderableType = "", *, layout: bool = True) -> None:  # type: ignore[override]
        self._body = body
        super().update(body, layout=layout)


class WelcomeEntry(Entry):
    """Шапка з логотипом PHANTOM STALKER; перебудовується під ширину вікна."""

    def __init__(self, location: str, **kwargs) -> None:
        self.location = location
        super().__init__(welcome(location), **kwargs)

    @property
    def body(self) -> RenderableType:
        width = self.app.size.width if self.is_attached else 120
        return welcome(self.location, width)

    def render(self) -> RenderableType:
        return self.body


class StatusLine(Static):
    DEFAULT_CSS = "StatusLine { height: 1; padding: 0 1; }"

    def __init__(self, persona: PersonaEngine, **kwargs) -> None:
        super().__init__(**kwargs)
        self.persona = persona
        self.busy = False

    def render(self) -> RenderableType:
        p, theme = self.persona, current()
        line = p.line.splitlines()[0] if p.line else ""
        if self.busy:
            out = Text(SPINNER[p.frame_index % len(SPINNER)], style=f"bold {theme.accent}")
            out.append(f" {line.rstrip('…. ')}…", style=TEXT)
            out.append("  esc — перервати", style=MUTED)
            return out
        return Text(line, style=f"italic {MUTED}")


class Suggestions(Static):
    DEFAULT_CSS = "Suggestions { height: auto; padding: 0 2; }"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.items: list[Command] = []
        self.selected = 0

    def show(self, items: list[Command]) -> None:
        self.items = items[:8]
        self.selected = min(self.selected, max(len(self.items) - 1, 0))
        self.refresh(layout=True)

    def move(self, step: int) -> None:
        if self.items:
            self.selected = (self.selected + step) % len(self.items)
            self.refresh()

    @property
    def current(self) -> Command | None:
        return self.items[self.selected] if self.items else None

    def render(self) -> RenderableType:
        if not self.items:
            return Text("/ команди · @ім'я · ↑↓ історія · esc перервати · ctrl+c вихід", style=MUTED)
        accent = current().accent
        width = max(len(c.name) + len(c.usage) for c in self.items) + 4
        out = Text()
        for i, c in enumerate(self.items):
            if i:
                out.append("\n")
            chosen = i == self.selected
            out.append(f"/{c.name} {c.usage}".ljust(width), style=f"bold {accent}" if chosen else TEXT)
            out.append(c.help, style=accent if chosen else MUTED)
        return out


def short_path(path: str, home: str, limit: int = 32) -> str:
    """/home/me/projects/app → ~/projects/app; задовгі шляхи — …/останні/частини."""
    if path == home or path.startswith(home.rstrip("/\\") + ("/" if "/" in home else "\\")):
        path = "~" + path[len(home):]
    if len(path) <= limit:
        return path or "/"
    parts = path.replace("\\", "/").split("/")
    tail = "/".join(parts[-2:])
    return "…/" + (tail if len(tail) <= limit - 2 else parts[-1][-(limit - 2):])


class PromptLabel(Static):
    """Шельний префікс рядка вводу: phantom-[~/тека] $ (або [пароль] / [y/n] у режимах вводу)."""

    DEFAULT_CSS = "PromptLabel { width: auto; height: 1; }"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mode: str = ""  # "" | "secret" | "confirm"

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.refresh(layout=True)

    def render(self) -> RenderableType:
        import os
        from pathlib import Path

        accent = current().accent
        where = {"secret": "пароль", "confirm": "y/n"}.get(self.mode) or short_path(os.getcwd(), str(Path.home()))
        out = Text("phantom", style=f"bold {accent}")
        out.append("-[", style=MUTED)
        out.append(where, style=f"bold {accent}" if self.mode else TEXT)
        out.append("]", style=MUTED)
        out.append(" $ ", style=MUTED)
        return out


class PromptInput(Input):
    """Поле «> …» з доповненням команд (Tab) та історією (↑/↓)."""

    BINDINGS = [
        Binding("tab", "complete", show=False, priority=True),
        Binding("up", "older", show=False, priority=True),
        Binding("down", "newer", show=False, priority=True),
    ]

    class Complete(Message):
        pass

    class Navigate(Message):
        def __init__(self, step: int) -> None:
            super().__init__()
            self.step = step

    def _on_paste(self, event) -> None:  # type: ignore[override]
        """Стандартне поле лишає лише перший рядок; ми зберігаємо всі, позначаючи переноси ⏎."""
        if event.text:
            lines = event.text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            while lines and not lines[-1].strip():
                lines.pop()
            joined = f" {NEWLINE_MARK} ".join(lines)
            if self.selection.is_empty:
                self.insert_text_at_cursor(joined)
            else:
                self.replace(joined, *self.selection)
        event.stop()

    def action_complete(self) -> None:
        self.post_message(self.Complete())

    def action_older(self) -> None:
        self.post_message(self.Navigate(-1))

    def action_newer(self) -> None:
        self.post_message(self.Navigate(+1))
