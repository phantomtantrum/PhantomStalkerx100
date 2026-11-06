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


def test_logo_is_bloody_phantom_stalker():
    assert len(wordmark.PHANTOM) == len(wordmark.STALKER) == len(wordmark.ONE_LINE) == 9
    assert wordmark.width(wordmark.PHANTOM) <= 80 and wordmark.width(wordmark.STALKER) <= 80  # як на TAAG, w=80
    assert set("".join(wordmark.ONE_LINE)) <= set("█▓▒░▄▀▐▌ ")
    one = wordmark.render(200).plain.splitlines()
    two = wordmark.render(100).plain.splitlines()
    assert len(one) == 9 and len(two) == 19  # PHANTOM, порожній рядок, STALKER
    assert wordmark.render(40).plain == "P H A N T O M  ·  S T A L K E R"
