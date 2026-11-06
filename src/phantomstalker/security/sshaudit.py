"""/ssh — аудит теки ~/.ssh: ключі, права доступу, authorized_keys, config."""

from __future__ import annotations

import base64
import os
import stat
import struct
from pathlib import Path

from phantomstalker.security.report import Report, Severity, score


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", data[offset:offset + 4])
    start = offset + 4
    return data[start:start + length], start + length


def public_key_info(line: str) -> tuple[str, int | None, str] | None:
    """`ssh-rsa AAAA... comment` → (тип, біти, коментар)."""
    parts = line.strip().split()
    for i, part in enumerate(parts):  # у authorized_keys перед ключем можуть бути опції
        if part.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
                key_type, offset = _read_string(blob, 0)
            except (ValueError, struct.error):
                return None
            kind = key_type.decode(errors="replace")
            bits: int | None = None
            if kind == "ssh-rsa":
                _e, offset = _read_string(blob, offset)
                n, _ = _read_string(blob, offset)
                bits = int.from_bytes(n, "big").bit_length()
            elif kind == "ssh-dss":
                p, _ = _read_string(blob, offset)
                bits = int.from_bytes(p, "big").bit_length()
            elif kind.startswith("ecdsa-"):
                bits = int(kind.rsplit("nistp", 1)[-1]) if "nistp" in kind else None
            elif "ed25519" in kind:
                bits = 256
            return kind, bits, " ".join(parts[i + 2:])
    return None


def private_key_encrypted(text: str) -> bool | None:
    """True/False — чи захищений приватний ключ паролем; None — невідомий формат."""
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(ln for ln in text.splitlines() if ln and not ln.startswith("-----"))
        try:
            blob = base64.b64decode(body)
        except ValueError:
            return None
        magic = b"openssh-key-v1\0"
        if not blob.startswith(magic):
            return None
        cipher, _ = _read_string(blob, len(magic))
        return cipher != b"none"
    if "ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text:
        return True
    if "PRIVATE KEY" in text:
        return False
    return None


def _strength(r: Report, where: str, kind: str, bits: int | None) -> None:
    if kind == "ssh-dss":
        r.add(Severity.HIGH, f"{where}: застарілий DSA-ключ", "DSA вимкнено в сучасному OpenSSH.",
              "ssh-keygen -t ed25519 — і заміни ключ на серверах")
    elif kind == "ssh-rsa" and bits and bits < 2048:
        r.add(Severity.HIGH, f"{where}: RSA лише {bits} біт", "Такий ключ вважається зламним.",
              "ssh-keygen -t ed25519")
    elif kind == "ssh-rsa" and bits and bits < 3072:
        r.add(Severity.LOW, f"{where}: RSA {bits} біт", "Поки прийнятно, але краще ed25519.",
              "ssh-keygen -t ed25519")
    else:
        label = f"{kind} {bits} біт" if bits and "ed25519" not in kind else kind
        r.add(Severity.OK, f"{where}: {label}")


def _loose(path: Path) -> bool:
    return os.name == "posix" and bool(path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))


def audit_ssh(ssh_dir: str | Path | None = None) -> Report:
    root = Path(ssh_dir).expanduser() if ssh_dir else Path.home() / ".ssh"
    r = Report(f"Аудит SSH · {root}")
    if not root.is_dir():
        r.add(Severity.INFO, "Теки ~/.ssh немає", "SSH-ключів на цьому комп'ютері не знайдено.")
        r.score = 100
        return r
    if _loose(root):
        r.add(Severity.MEDIUM, "Тека ~/.ssh доступна іншим користувачам", "", f"chmod 700 {root}")

    for path in sorted(p for p in root.iterdir() if p.is_file()):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "PRIVATE KEY" in text:
            if _loose(path):
                r.add(Severity.HIGH, f"{path.name}: приватний ключ доступний іншим", "",
                      f"chmod 600 {path}")
            encrypted = private_key_encrypted(text)
            if encrypted is False:
                r.add(Severity.MEDIUM, f"{path.name}: приватний ключ без пароля",
                      "Хто отримає файл — отримає доступ до всіх твоїх серверів.",
                      f"ssh-keygen -p -f {path}")
            elif encrypted:
                r.add(Severity.OK, f"{path.name}: приватний ключ захищено паролем")
        elif path.suffix == ".pub":
            info = public_key_info(text)
            if info:
                _strength(r, path.name, info[0], info[1])

    auth = root / "authorized_keys"
    if auth.is_file():
        entries = [ln for ln in auth.read_text(errors="replace").splitlines()
                   if ln.strip() and not ln.startswith("#")]
        r.add(Severity.INFO, f"authorized_keys: {len(entries)} ключ(ів) мають доступ до цього комп'ютера",
              "Переконайся, що знаєш кожен із них.")
        for i, line in enumerate(entries, 1):
            info = public_key_info(line)
            if info:
                name = info[2] or f"запис №{i}"
                kind, bits, _ = info
                if kind == "ssh-dss" or (kind == "ssh-rsa" and bits and bits < 2048):
                    _strength(r, f"authorized_keys ({name})", kind, bits)

    config = root / "config"
    if config.is_file():
        text = config.read_text(errors="replace").lower()
        if "stricthostkeychecking no" in text:
            r.add(Severity.MEDIUM, "config: StrictHostKeyChecking no",
                  "Ти не помітиш підміни сервера (атака «людина посередині»).",
                  "Прибери цей рядок або обмеж його конкретним хостом")
        if "forwardagent yes" in text:
            r.add(Severity.LOW, "config: ForwardAgent yes",
                  "Адміністратор віддаленого сервера зможе використати твої ключі.",
                  "Вмикай лише для довірених хостів або використовуй ProxyJump")

    if not r.findings:
        r.add(Severity.OK, "SSH-ключів не знайдено", "Тека є, але ключів і authorized_keys у ній немає.")
    r.score = score(r.findings)
    r.summary = f"Проблем: {len(r.issues)}" if r.issues else "SSH налаштовано добре"
    return r
