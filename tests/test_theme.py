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


def test_logo_ansi_regular_layouts():
    assert len(wordmark.PHANTOM) == len(wordmark.STALKER) == len(wordmark.ONE_LINE) == 5
    assert set("".join(wordmark.ONE_LINE)) <= {"█", " "}
    assert len(wordmark.render(200).plain.splitlines()) == 5      # в один рядок
    assert len(wordmark.render(100).plain.splitlines()) == 11     # PHANTOM, порожній, STALKER
    assert wordmark.render(40).plain == "P H A N T O M  ·  S T A L K E R"


def test_decrypt_animation_reveals_logo():
    final = wordmark.render(100).plain
    start = wordmark.render(100, progress=0.0, seed=42).plain
    middle = wordmark.render(100, progress=0.5, seed=42).plain
    assert wordmark.render(100, progress=1.0, seed=42).plain == final
    assert start != final and len(start) == len(final)          # той самий розмір — нічого не «стрибає»
    assert [i for i, c in enumerate(start) if c == " "] == [i for i, c in enumerate(final) if c == " "]
    same = lambda a: sum(x == y for x, y in zip(a, final) if y != " ")
    assert same(start) < same(middle) < same(final)             # літери поступово проступають
    assert any(c in wordmark.NOISE and c != "█" for c in start)
    assert wordmark.render(30, progress=0.0, seed=1).plain != wordmark.render(30).plain


def test_reveal_order_is_stable_per_position():
    assert wordmark.reveal_order(3, 2, 7) == wordmark.reveal_order(3, 2, 7)
    assert wordmark.reveal_order(3, 2, 7) != wordmark.reveal_order(4, 2, 7)
