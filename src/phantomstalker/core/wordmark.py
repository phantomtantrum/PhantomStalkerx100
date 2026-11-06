"""Напис QUANTPHANTOM піксельним шрифтом 5×6, намальований напівблоками ▀ ▄ █.

Використовується лише колір переднього плану (без фону), тож напис завжди
в кольорі тексту терміналу користувача.
"""

from __future__ import annotations

from rich.text import Text

WORD = "QUANTPHANTOM"

FONT: dict[str, list[str]] = {
    "Q": [".###.", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"],
    "U": ["#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#"],
    "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"],
    "T": ["#####", "..#..", "..#..", "..#..", "..#..", "..#.."],
    "P": ["####.", "#...#", "#...#", "####.", "#....", "#...."],
    "H": ["#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "O": [".###.", "#...#", "#...#", "#...#", "#...#", ".###."],
    "M": ["#...#", "##.##", "#.#.#", "#...#", "#...#", "#...#"],
}
GLYPH_W, GLYPH_H, GAP = 5, 6, 1


def pixels(word: str = WORD) -> list[str]:
    """Рядки пікселів усього слова ('#' — заповнено)."""
    rows = []
    for y in range(GLYPH_H):
        rows.append(("." * GAP).join(FONT[ch][y] for ch in word))
    return rows


def width(word: str = WORD) -> int:
    return len(word) * (GLYPH_W + GAP) - GAP


def render(word: str = WORD, style: str = "default") -> Text:
    rows = pixels(word)
    out = Text(no_wrap=True, overflow="crop")
    for y in range(0, len(rows), 2):
        if y:
            out.append("\n")
        line = []
        for top, bottom in zip(rows[y], rows[y + 1], strict=True):
            line.append({(True, True): "█", (True, False): "▀", (False, True): "▄"}.get(
                (top == "#", bottom == "#"), " "))
        out.append("".join(line), style=style)
    return out


def render_compact(word: str = WORD, style: str = "default") -> Text:
    """Для вузьких терміналів: розрядкований напис в один рядок."""
    return Text(" ".join(word), style=f"bold {style}")
