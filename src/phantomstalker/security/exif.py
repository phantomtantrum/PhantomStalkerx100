"""/exif — показати й прибрати метадані з фото (GPS, модель телефона, дати) перед публікацією.

Чистий Python: JPEG (APPn/COM-сегменти) і PNG (текстові чанки, eXIf). Пікселі не змінюються.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from phantomstalker.security.report import Report, Severity, SecurityError

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_DROP = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
JPEG_KEEP_APP = {0xE0, 0xE2, 0xEE}  # JFIF, ICC-профіль кольорів, Adobe (кольорова модель)

TAGS = {0x010F: "Виробник", 0x0110: "Модель", 0x0131: "Програма", 0x0132: "Дата зміни",
        0x9003: "Дата зйомки", 0xA434: "Об'єктив", 0xA431: "Серійний номер камери",
        0x013B: "Автор", 0x8298: "Copyright"}


# --- розбір EXIF (TIFF) -----------------------------------------------------------------------
def _parse_tiff(data: bytes) -> dict[str, object]:
    if data[:2] not in (b"II", b"MM"):
        return {}
    e = "<" if data[:2] == b"II" else ">"
    result: dict[str, object] = {}

    def value(typ: int, count: int, raw: bytes) -> object:
        size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}.get(typ, 1) * count
        payload = raw if size <= 4 else data[struct.unpack(e + "I", raw)[0]:][:size]
        if typ == 2:
            return payload.split(b"\0", 1)[0].decode(errors="replace").strip()
        if typ == 3:
            return struct.unpack(e + "H" * count, payload[:2 * count])
        if typ == 4:
            return struct.unpack(e + "I" * count, payload[:4 * count])
        if typ == 5:
            nums = struct.unpack(e + "I" * (2 * count), payload[:8 * count])
            return tuple(nums[i] / nums[i + 1] if nums[i + 1] else 0 for i in range(0, len(nums), 2))
        return payload

    def ifd(offset: int, gps: bool = False) -> None:
        if offset <= 0 or offset + 2 > len(data):
            return
        (count,) = struct.unpack(e + "H", data[offset:offset + 2])
        for i in range(min(count, 512)):
            entry = data[offset + 2 + 12 * i: offset + 14 + 12 * i]
            if len(entry) < 12:
                break
            tag, typ, n = struct.unpack(e + "HHI", entry[:8])
            try:
                val = value(typ, n, entry[8:12])
            except (struct.error, IndexError):
                continue
            if gps:
                result[f"gps{tag}"] = val
            elif tag == 0x8825 and isinstance(val, tuple):
                ifd(val[0], gps=True)
            elif tag == 0x8769 and isinstance(val, tuple):
                ifd(val[0])
            elif tag in TAGS and val:
                result[TAGS[tag]] = val

    ifd(struct.unpack(e + "I", data[4:8])[0])
    lat, lon = result.pop("gps2", None), result.pop("gps4", None)
    lat_ref, lon_ref = result.pop("gps1", "N"), result.pop("gps3", "E")
    for k in [k for k in result if k.startswith("gps")]:
        result.pop(k)
    if isinstance(lat, tuple) and isinstance(lon, tuple) and len(lat) == 3 and len(lon) == 3:
        la = lat[0] + lat[1] / 60 + lat[2] / 3600
        lo = lon[0] + lon[1] / 60 + lon[2] / 3600
        la = -la if str(lat_ref).upper().startswith("S") else la
        lo = -lo if str(lon_ref).upper().startswith("W") else lo
        if la or lo:
            result["GPS"] = (round(la, 6), round(lo, 6))
    return result


# --- JPEG -----------------------------------------------------------------------------------
def _jpeg_segments(data: bytes):
    """Сегменти до SOS: (маркер, початок, кінець)."""
    if data[:2] != b"\xff\xd8":
        raise SecurityError("Пошкоджений JPEG")
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            raise SecurityError("Пошкоджений JPEG")
        marker = data[pos + 1]
        if marker == 0xD9:
            return
        if marker == 0xDA:  # SOS — далі стиснуті дані зображення
            yield marker, pos, None
            return
        (length,) = struct.unpack(">H", data[pos + 2:pos + 4])
        yield marker, pos, pos + 2 + length
        pos += 2 + length


def inspect_jpeg(data: bytes) -> tuple[dict[str, object], list[str]]:
    meta: dict[str, object] = {}
    blocks: list[str] = []
    for marker, start, end in _jpeg_segments(data):
        if end is None:
            break
        body = data[start + 4:end]
        if marker == 0xE1 and body.startswith(b"Exif\0\0"):
            blocks.append("EXIF")
            meta.update(_parse_tiff(body[6:]))
        elif marker == 0xE1 and b"ns.adobe.com/xap" in body[:64]:
            blocks.append("XMP")
        elif marker == 0xED:
            blocks.append("IPTC")
        elif marker == 0xFE:
            blocks.append("коментар")
        elif 0xE3 <= marker <= 0xEF and marker not in JPEG_KEEP_APP:
            blocks.append(f"APP{marker - 0xE0}")
    return meta, blocks


def strip_jpeg(data: bytes) -> bytes:
    out = bytearray(b"\xff\xd8")
    for marker, start, end in _jpeg_segments(data):
        if end is None:
            out += data[start:]
            return bytes(out)
        if (0xE1 <= marker <= 0xEF and marker not in JPEG_KEEP_APP) or marker == 0xFE:
            continue
        out += data[start:end]
    return bytes(out)


# --- PNG ------------------------------------------------------------------------------------
def _png_chunks(data: bytes):
    if not data.startswith(PNG_SIG):
        raise SecurityError("Пошкоджений PNG")
    pos = len(PNG_SIG)
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        end = pos + 12 + length
        yield ctype, data[pos + 8:pos + 8 + length], data[pos:end]
        pos = end
        if ctype == b"IEND":
            return


def inspect_png(data: bytes) -> tuple[dict[str, object], list[str]]:
    meta: dict[str, object] = {}
    blocks: list[str] = []
    for ctype, body, _ in _png_chunks(data):
        if ctype in PNG_DROP:
            blocks.append(ctype.decode())
            if ctype == b"eXIf":
                meta.update(_parse_tiff(body))
            elif ctype == b"tEXt":
                key, _, val = body.partition(b"\0")
                meta[key.decode(errors="replace")] = val.decode("latin-1", errors="replace")[:80]
            elif ctype == b"zTXt":
                key, _, rest = body.partition(b"\0")
                try:
                    meta[key.decode(errors="replace")] = zlib.decompress(rest[1:]).decode(errors="replace")[:80]
                except zlib.error:
                    pass
    return meta, blocks


def strip_png(data: bytes) -> bytes:
    return PNG_SIG + b"".join(raw for ctype, _, raw in _png_chunks(data) if ctype not in PNG_DROP)


# --- звіт -------------------------------------------------------------------------------------
def process(path_str: str, clean: bool = True) -> Report:
    path = Path(path_str).expanduser()
    if not path.is_file():
        raise SecurityError(f"Файл не знайдено: {path}")
    data = path.read_bytes()
    if data.startswith(b"\xff\xd8"):
        meta, blocks = inspect_jpeg(data)
        stripper, inspector = strip_jpeg, inspect_jpeg
    elif data.startswith(PNG_SIG):
        meta, blocks = inspect_png(data)
        stripper, inspector = strip_png, inspect_png
    else:
        raise SecurityError("Підтримуються JPEG і PNG. Для HEIC/WebP: exiftool -all= файл")
    r = Report(f"Метадані фото · {path.name}")
    if gps := meta.pop("GPS", None):
        lat, lon = gps  # type: ignore[misc]
        r.add(Severity.HIGH, f"GPS-координати: {lat}, {lon}",
              f"Видно, де зроблено фото: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")
    for key in ("Виробник", "Модель", "Серійний номер камери", "Об'єктив"):
        if key in meta:
            r.add(Severity.MEDIUM if key != "Об'єктив" else Severity.LOW, f"{key}: {meta.pop(key)}")
    for key, val in meta.items():
        r.add(Severity.LOW, f"{key}: {val}")
    if blocks:
        r.add(Severity.INFO, "Блоки метаданих: " + ", ".join(dict.fromkeys(blocks)))
    if not r.findings:
        r.add(Severity.OK, "Метаданих не знайдено")
        return r
    if clean:
        cleaned = stripper(data)
        dst = path.with_name(f"{path.stem}.clean{path.suffix}")
        dst.write_bytes(cleaned)
        left, left_blocks = inspector(cleaned)
        if left or left_blocks:
            r.add(Severity.MEDIUM, "Частину метаданих не вдалося прибрати", ", ".join(left_blocks))
        else:
            r.add(Severity.OK, f"Чиста копія збережена: {dst}",
                  f"{len(data) - len(cleaned):,} байт метаданих прибрано · оригінал не змінено".replace(",", " "))
        if "EXIF" in blocks:
            r.notes.append("Разом з EXIF прибрано й орієнтацію — якщо фото повернулося боком, поверни його в редакторі.")
    return r
