"""Інтерфейс бере кольори лише з палітри терміналу."""

import re
from pathlib import Path

from rich.color import Color

from phantomstalker.core import wordmark
from phantomstalker.core.theme import THEMES, get_theme, set_current

SRC = Path(__file__).parents[1] / "src"


def test_no_hardcoded_hex_colors_in_source():
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"['\"]#[0-9A-Fa-f]{6}['\"]", text), path
        assert "$foreground" not in text, path


def test_muted_text_is_dim_not_a_fixed_gray():
    from phantomstalker.core.theme import MUTED

    assert MUTED == "dim"


def test_theme_accents_are_terminal_palette_colors():
    for theme in THEMES.values():
        color = Color.parse(theme.accent)
        assert color.is_default or color.number is not None and color.number < 16, theme


def test_default_theme_is_monochrome_and_unknown_falls_back():
    assert get_theme(None).accent == "default"
    assert get_theme("silver").name == "mono"  # старі налаштування не ламаються
    assert set_current("cyan").textual_accent == "ansi_cyan"
    set_current("mono")


def test_wordmark_renders_quantphantom():
    rows = wordmark.pixels()
    assert len(rows) == 6 and all(len(r) == wordmark.width() for r in rows)
    text = wordmark.render()
    assert len(text.plain.splitlines()) == 3
    assert set(text.plain) <= set("▀▄█ \n")
    assert wordmark.width() <= 76  # влазить у термінал 80 колонок разом з рамкою
    assert wordmark.render_compact().plain.replace(" ", "") == "QUANTPHANTOM"
