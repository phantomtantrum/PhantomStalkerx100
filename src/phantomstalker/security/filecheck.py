"""/file — хеші файлу, звірка з контрольною сумою, тип файлу, перевірка в MalwareBazaar."""

from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError

MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
EXECUTABLE_EXT = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".msi",
                  ".hta", ".jar", ".lnk", ".app", ".dmg", ".pkg", ".sh", ".apk"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp4"}


def hashes(path: Path) -> dict[str, str]:
    algos = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            for h in algos.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in algos.items()}


def kind(path: Path) -> str:
    with path.open("rb") as fh:
        head = fh.read(8)
    if head.startswith(b"MZ"):
        return "Windows-програма (PE)"
    if head.startswith(b"\x7fELF"):
        return "Linux-програма (ELF)"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macOS-програма (Mach-O)"
    if head.startswith(b"#!"):
        return "скрипт"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP-архів / документ Office"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "старий документ Office (OLE)"
    return "інший"


async def check(path_str: str, expected: str = "", api_key: str | None = None,
                client: httpx.AsyncClient | None = None) -> Report:
    path = Path(path_str).expanduser()
    if not path.is_file():
        raise SecurityError(f"Файл не знайдено: {path}")
    h = hashes(path)
    ftype = kind(path)
    r = Report(f"Перевірка файлу · {path.name}", summary=f"{path.stat().st_size:,} байт · {ftype}".replace(",", " "))
    r.add(Severity.INFO, "SHA-256", h["sha256"])
    r.add(Severity.INFO, "SHA-1 / MD5", f"{h['sha1']} / {h['md5']}")

    expected = expected.strip().lower()
    if expected:
        algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(expected))
        if not algo or not re.fullmatch(r"[0-9a-f]+", expected):
            r.add(Severity.LOW, "Не розпізнав формат очікуваного хешу", "Потрібен MD5, SHA-1 або SHA-256 у hex.")
        elif h[algo] == expected:
            r.add(Severity.OK, f"Контрольна сума {algo.upper()} збігається", "Файл саме той, що опублікував автор.")
        else:
            r.add(Severity.CRITICAL, f"Контрольна сума {algo.upper()} НЕ збігається",
                  "Файл пошкоджений або підмінений.", "Не запускай його; завантаж заново з офіційного сайту")

    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXT and suffixes[-2] in DOC_EXT:
        r.add(Severity.HIGH, f"Подвійне розширення «{''.join(path.suffixes[-2:])}»",
              "Класичний трюк: програма маскується під документ.", "Не відкривай файл")
    if "програма" in ftype and suffixes and suffixes[-1] in DOC_EXT:
        r.add(Severity.HIGH, f"Насправді це {ftype}, хоча розширення {suffixes[-1]}",
              "Розширення підроблене.", "Не відкривай файл")
    if ftype.startswith("ZIP"):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            if any(n.endswith("vbaProject.bin") for n in names):
                r.add(Severity.MEDIUM, "Документ містить макроси (VBA)",
                      "Макроси — частий спосіб поширення шкідливого ПЗ.", "Не вмикай макроси, якщо не впевнений у джерелі")
            exe = [n for n in names if Path(n).suffix.lower() in EXECUTABLE_EXT]
            if exe:
                r.add(Severity.MEDIUM, f"В архіві виконувані файли: {', '.join(exe[:3])}")
        except zipfile.BadZipFile:
            pass

    if api_key:
        own = client is None
        client = client or net.client()
        try:
            resp = await client.post(MALWAREBAZAAR, data={"query": "get_info", "hash": h["sha256"]},
                                     headers={"Auth-Key": api_key})
            resp.raise_for_status()
            data = resp.json()
            status = data.get("query_status")
            if status == "ok" and data.get("data"):
                info = data["data"][0]
                tags = ", ".join(info.get("tags") or [])
                r.add(Severity.CRITICAL, f"Відоме шкідливе ПЗ: {info.get('signature') or 'без назви'}",
                      f"MalwareBazaar: {info.get('file_type', '')} {tags}".strip(),
                      "Видали файл; якщо запускав — проскануй систему й зміни паролі")
            elif status in ("hash_not_found", "no_results"):
                r.add(Severity.OK, "У базі шкідливого ПЗ MalwareBazaar не знайдено",
                      "Це не гарантія безпеки — нові зразки можуть бути ще не в базі.")
            else:
                r.add(Severity.INFO, f"MalwareBazaar: {status}")
        except httpx.HTTPError as exc:
            r.add(Severity.INFO, "MalwareBazaar недоступний", net.describe_http_error(exc, "MalwareBazaar"))
        finally:
            if own:
                await client.aclose()
    else:
        r.notes.append("Для перевірки в базі шкідливого ПЗ додай безкоштовний ключ abuse.ch: /key abusech")
    return r
