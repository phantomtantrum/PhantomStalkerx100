"""Кольори інтерфейсу — лише з палітри терміналу користувача.

Жодних hex-кольорів: усе задається іменами ANSI («default», «bright_black», «cyan»…),
тож світла чи темна тема терміналу, Solarized, Dracula тощо підхоплюються автоматично.
Другорядний текст — стиль «dim» (а не сірий колір: у деяких темах «bright_black» темніший за текст).
За замовчуванням інтерфейс монохромний; акцент можна змінити командою /color.
"""

from __future__ import annotations

from dataclasses import dataclass

TEXT = "default"          # основний колір тексту терміналу
MUTED = "dim"             # другорядний текст: приглушений колір тексту, коректний у будь-якій темі
ERROR = "red"
GAIN = "green"
LOSS = "red"


@dataclass(frozen=True)
class Theme:
    name: str
    label: str
    accent: str  # ім'я ANSI-кольору (Rich)

    @property
    def textual_accent(self) -> str:
        """Те саме ім'я у форматі Textual CSS."""
        return f"ansi_{self.accent}"


THEMES: dict[str, Theme] = {
    t.name: t
    for t in (
        Theme("mono", "монохром (колір тексту терміналу)", "default"),
        Theme("cyan", "бірюзовий", "cyan"),
        Theme("blue", "синій", "blue"),
        Theme("magenta", "пурпуровий", "magenta"),
        Theme("green", "зелений", "green"),
        Theme("yellow", "жовтий", "yellow"),
    )
}
DEFAULT_THEME = "mono"


def get_theme(name: str | None) -> Theme:
    return THEMES.get((name or "").strip().casefold(), THEMES[DEFAULT_THEME])


_current: Theme = THEMES[DEFAULT_THEME]


def current() -> Theme:
    """Активна тема (її читає інтерфейс під час рендеру)."""
    return _current


def set_current(name: str | None) -> Theme:
    global _current
    _current = get_theme(name)
    return _current
