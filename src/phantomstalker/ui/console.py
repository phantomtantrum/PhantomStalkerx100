"""Мінімалістичні віджети консолі: шапка з написом, стрічка, рядок статусу, поле вводу, підказки.

Усі кольори — імена ANSI з палітри терміналу користувача (див. core/theme.py).
"""

from __future__ import annotations

from rich.box import ROUNDED
from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Input, Static

from phantomstalker import __version__
from phantomstalker.core.commands import Command, Say
from phantomstalker.core.persona import PersonaEngine
from phantomstalker.core.theme import ERROR, MUTED, TEXT, current
from phantomstalker.core import wordmark

BORDER = MUTED
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def welcome(location: str, available_width: int = 120) -> RenderableType:
    theme = current()
    fits = available_width >= wordmark.width() + 8
    logo = wordmark.render(style=TEXT) if fits else wordmark.render_compact(style=TEXT)
    info = Text()
    info.append(f"v{__version__}", style=MUTED)
    info.append("  ·  ", style=MUTED)
    info.append("/help", style=f"bold {theme.accent}")
    info.append(" — команди  ·  ", style=MUTED)
    info.append("@ім'я", style=f"bold {theme.accent}")
    info.append(" — нотатки про людину\n", style=MUTED)
    info.append(location, style=MUTED)
    return Panel(Group(logo, Text(""), info), box=ROUNDED, border_style=BORDER, expand=False,
                 padding=(1, 3))


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
    """Шапка з написом QUANTPHANTOM; перебудовується під ширину вікна."""

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

    def action_complete(self) -> None:
        self.post_message(self.Complete())

    def action_older(self) -> None:
        self.post_message(self.Navigate(-1))

    def action_newer(self) -> None:
        self.post_message(self.Navigate(+1))
