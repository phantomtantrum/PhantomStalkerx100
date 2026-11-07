"""Логотип PHANTOM STALKER (FIGlet «ANSI Regular») з анімацією «розшифровки» на старті.

Напис згенеровано заздалегідь, тож ні шрифт, ні figlet у застосунку не потрібні.
Анімація: літери проступають крізь випадковий «шифротекст» у випадковому порядку.
Усі стилі — з палітри терміналу (колір тексту, dim, акцент теми).
"""

from __future__ import annotations

import random

from rich.text import Text

NAME = "PHANTOM STALKER"
NOISE = "█▓▒░▀▄#$%&@*+=0123456789ABCDEF"
FRAMES = 22          # кадрів анімації
FRAME_SECONDS = 0.07  # ≈1,5 с загалом

PHANTOM = [
    '██████  ██   ██  █████  ███    ██ ████████  ██████  ███    ███',
    '██   ██ ██   ██ ██   ██ ████   ██    ██    ██    ██ ████  ████',
    '██████  ███████ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██',
    '██      ██   ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██',
    '██      ██   ██ ██   ██ ██   ████    ██     ██████  ██      ██',
]

STALKER = [
    '███████ ████████  █████  ██      ██   ██ ███████ ██████',
    '██         ██    ██   ██ ██      ██  ██  ██      ██   ██',
    '███████    ██    ███████ ██      █████   █████   ██████',
    '     ██    ██    ██   ██ ██      ██  ██  ██      ██   ██',
    '███████    ██    ██   ██ ███████ ██   ██ ███████ ██   ██',
]

ONE_LINE = [
    '██████  ██   ██  █████  ███    ██ ████████  ██████  ███    ███     ███████ ████████  █████  ██      ██   ██ ███████ ██████',
    '██   ██ ██   ██ ██   ██ ████   ██    ██    ██    ██ ████  ████     ██         ██    ██   ██ ██      ██  ██  ██      ██   ██',
    '██████  ███████ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██     ███████    ██    ███████ ██      █████   █████   ██████',
    '██      ██   ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██          ██    ██    ██   ██ ██      ██  ██  ██      ██   ██',
    '██      ██   ██ ██   ██ ██   ████    ██     ██████  ██      ██     ███████    ██    ██   ██ ███████ ██   ██ ███████ ██   ██',
]


def width(rows: list[str]) -> int:
    return max(len(r) for r in rows)


def rows_for(available: int) -> list[str] | None:
    """В один рядок (широкий термінал), у два — PHANTOM / STALKER, або None (надто вузько)."""
    if available >= width(ONE_LINE):
        return ONE_LINE
    if available >= max(width(PHANTOM), width(STALKER)):
        return [*PHANTOM, "", *STALKER]
    return None


def reveal_order(x: int, y: int, seed: int) -> float:
    """Коли (0..1) клітинка «розшифровується». Залежить лише від позиції — стійко до зміни розміру."""
    return random.Random(seed * 1_000_003 + y * 4099 + x).random()


def is_revealed(x: int, y: int, seed: int, progress: float) -> bool:
    return progress >= 1 or reveal_order(x, y, seed) < progress * 1.15 - 0.1


def render(available: int = 200, style: str = "default", *, progress: float = 1.0, seed: int = 0,
           noise_style: str = "dim", spark_style: str = "bold") -> Text:
    rows = rows_for(available)
    if rows is None:
        return render_compact(style, progress=progress, seed=seed, noise_style=noise_style)
    rng = random.Random(seed * 7919 + int(progress * 1000))  # новий шум у кожному кадрі
    out = Text(no_wrap=True, overflow="crop")
    for y, row in enumerate(rows):
        if y:
            out.append("\n")
        for x, ch in enumerate(row.rstrip()):
            if ch == " ":
                out.append(" ")
            elif is_revealed(x, y, seed, progress):
                out.append(ch, style=style)
            else:
                out.append(rng.choice(NOISE), style=spark_style if rng.random() < 0.15 else noise_style)
    return out


def render_compact(style: str = "default", *, progress: float = 1.0, seed: int = 0,
                   noise_style: str = "dim") -> Text:
    """Для вузьких терміналів: розрядкований напис в один рядок (теж «розшифровується»)."""
    plain = " ".join(NAME).replace("   ", "  ·  ")
    rng = random.Random(seed * 7919 + int(progress * 1000))
    out = Text()
    for x, ch in enumerate(plain):
        if ch in " ·" or is_revealed(x, 0, seed, progress):
            out.append(ch, style=f"bold {style}")
        else:
            out.append(rng.choice(NOISE[6:]), style=noise_style)
    return out
