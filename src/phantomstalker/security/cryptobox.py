"""/encrypt та /decrypt — шифрування тексту й файлів паролем у форматі age (age-encryption.org).

Результат сумісний з утилітою `age`: `age -d файл.age` або `age -d` для ASCII-броні.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pyrage

from phantomstalker.security.report import SecurityError

BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
END = "-----END AGE ENCRYPTED FILE-----"
MIN_PASSPHRASE = 8


def _check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise SecurityError(f"Пароль надто короткий — мінімум {MIN_PASSPHRASE} символів")


def armor(data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join([BEGIN, *lines, END]) + "\n"


def dearmor(text: str) -> bytes:
    """Приймає броню й у «склеєному» вигляді (з пробілами замість переносів)."""
    m = re.search(re.escape(BEGIN) + r"(.*?)" + re.escape(END), text, re.S)
    if not m:
        raise SecurityError("Не знайшов зашифрованого блоку (-----BEGIN AGE ENCRYPTED FILE-----)")
    body = re.sub(r"\s+", "", m.group(1))
    try:
        return base64.b64decode(body, validate=True)
    except ValueError as exc:
        raise SecurityError("Зашифрований блок пошкоджений") from exc


def encrypt_text(plaintext: str, passphrase: str) -> str:
    _check_passphrase(passphrase)
    return armor(pyrage.passphrase.encrypt(plaintext.encode("utf-8"), passphrase))


def decrypt_text(armored: str, passphrase: str) -> str:
    try:
        return pyrage.passphrase.decrypt(dearmor(armored), passphrase).decode("utf-8")
    except pyrage.DecryptError as exc:
        raise SecurityError("Не вдалося розшифрувати: неправильний пароль або пошкоджені дані") from exc


def encrypt_file(path: str | Path, passphrase: str) -> Path:
    _check_passphrase(passphrase)
    src = Path(path).expanduser()
    if not src.is_file():
        raise SecurityError(f"Файл не знайдено: {src}")
    dst = src.with_name(src.name + ".age")
    dst.write_bytes(pyrage.passphrase.encrypt(src.read_bytes(), passphrase))
    return dst


def decrypt_file(path: str | Path, passphrase: str) -> Path:
    src = Path(path).expanduser()
    if not src.is_file():
        raise SecurityError(f"Файл не знайдено: {src}")
    data = src.read_bytes()
    if data.lstrip().startswith(BEGIN.encode()):
        data = dearmor(data.decode(errors="replace"))
    try:
        plain = pyrage.passphrase.decrypt(data, passphrase)
    except pyrage.DecryptError as exc:
        raise SecurityError("Не вдалося розшифрувати: неправильний пароль або пошкоджений файл") from exc
    name = src.name[:-4] if src.name.endswith(".age") else src.name + ".decrypted"
    dst = src.with_name(name)
    if dst.exists():
        dst = dst.with_name(dst.stem + ".decrypted" + dst.suffix)
    dst.write_bytes(plain)
    return dst


def looks_like_path(value: str) -> bool:
    value = value.strip()
    if not value or "\n" in value or len(value) > 1024 or value.startswith("-----BEGIN"):
        return False
    try:
        return Path(value).expanduser().is_file()
    except (OSError, ValueError):  # надто довга назва, недопустимі символи тощо
        return False
