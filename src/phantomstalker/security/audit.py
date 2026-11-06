"""/audit — перевірка захищеності власного комп'ютера (Linux, macOS, Windows).

Лише читає стан системи: нічого не змінює. Команди запускаються через інжектований
runner, тож логіку легко тестувати.
"""

from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from phantomstalker.security.report import Report, Severity, score

Runner = Callable[[list[str]], tuple[int, str] | None]
Reader = Callable[[str], str | None]

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    11211: "Memcached", 2375: "Docker API", 5000: "dev-сервер", 8080: "HTTP (alt)",
}


def run_command(cmd: list[str]) -> tuple[int, str] | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def read_file(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


@dataclass
class System:
    os: str  # "linux" | "darwin" | "windows"
    run: Runner = run_command
    read: Reader = read_file


# --- окремі перевірки --------------------------------------------------------------
def check_firewall(s: System, r: Report) -> None:
    title = "Фаєрвол"
    if s.os == "linux":
        ufw = s.run(["ufw", "status"])
        if ufw and "status: active" in ufw[1].lower():
            r.add(Severity.OK, f"{title} увімкнено (ufw)")
            return
        fwd = s.run(["firewall-cmd", "--state"])
        if fwd and fwd[1].strip() == "running":
            r.add(Severity.OK, f"{title} увімкнено (firewalld)")
            return
        if ufw and "root" in ufw[1].lower():
            r.add(Severity.INFO, f"{title}: потрібні права root, щоб перевірити ufw",
                  "Запусти phantomstalker через sudo або перевір вручну: sudo ufw status")
            return
        if ufw is None and fwd is None:
            r.add(Severity.MEDIUM, f"{title} не знайдено",
                  "Не виявлено ні ufw, ні firewalld.", "sudo apt install ufw && sudo ufw enable")
            return
        r.add(Severity.HIGH, f"{title} вимкнено", "Вхідні з'єднання ніщо не фільтрує.",
              "sudo ufw default deny incoming && sudo ufw enable")
    elif s.os == "darwin":
        out = s.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if out and "enabled" in out[1].lower():
            r.add(Severity.OK, f"{title} увімкнено")
        elif out:
            r.add(Severity.HIGH, f"{title} вимкнено", "",
                  "System Settings → Network → Firewall → увімкнути")
        else:
            r.add(Severity.INFO, f"{title}: не вдалося перевірити")
    elif s.os == "windows":
        out = s.run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if not out:
            r.add(Severity.INFO, f"{title}: не вдалося перевірити")
        elif out[1].upper().count("OFF") == 0:
            r.add(Severity.OK, f"{title} увімкнено для всіх профілів")
        else:
            r.add(Severity.HIGH, f"{title} вимкнено щонайменше для одного профілю", "",
                  "netsh advfirewall set allprofiles state on")


def check_disk_encryption(s: System, r: Report) -> None:
    title = "Шифрування диска"
    if s.os == "linux":
        out = s.run(["lsblk", "-o", "TYPE", "-n"])
        if out is None:
            r.add(Severity.INFO, f"{title}: не вдалося перевірити")
        elif "crypt" in out[1].split():
            r.add(Severity.OK, f"{title} увімкнено (LUKS)")
        else:
            r.add(Severity.HIGH, f"{title} не виявлено",
                  "Якщо ноутбук вкрадуть, дані можна прочитати без пароля.",
                  "Увімкни LUKS під час перевстановлення або зашифруй домашню теку (fscrypt)")
    elif s.os == "darwin":
        out = s.run(["fdesetup", "status"])
        if out and "filevault is on" in out[1].lower():
            r.add(Severity.OK, f"{title} увімкнено (FileVault)")
        elif out:
            r.add(Severity.HIGH, f"{title} вимкнено (FileVault)", "",
                  "System Settings → Privacy & Security → FileVault → Turn On")
        else:
            r.add(Severity.INFO, f"{title}: не вдалося перевірити")
    elif s.os == "windows":
        out = s.run(["manage-bde", "-status", "C:"])
        if out and re.search(r"protection on|захист увімкнено", out[1], re.I):
            r.add(Severity.OK, f"{title} увімкнено (BitLocker)")
        elif out and out[0] == 0:
            r.add(Severity.HIGH, f"{title} вимкнено (BitLocker)", "", "manage-bde -on C:")
        else:
            r.add(Severity.INFO, f"{title}: не вдалося перевірити (потрібні права адміністратора)")


def check_updates(s: System, r: Report) -> None:
    if s.os != "linux":
        r.add(Severity.INFO, "Оновлення ОС: перевір вручну",
              "macOS: System Settings → General → Software Update; Windows: Windows Update")
        return
    out = s.run(["apt", "list", "--upgradable"])
    if out and out[0] == 0:
        pending = [ln for ln in out[1].splitlines() if "/" in ln and "upgradable" in ln]
        security = [ln for ln in pending if "security" in ln]
        if not pending:
            r.add(Severity.OK, "Система оновлена")
        elif security:
            r.add(Severity.HIGH, f"Безпекових оновлень, що очікують: {len(security)}",
                  f"Усього оновлень: {len(pending)}", "sudo apt update && sudo apt upgrade")
        else:
            r.add(Severity.LOW, f"Оновлень, що очікують: {len(pending)}", "",
                  "sudo apt update && sudo apt upgrade")
        return
    out = s.run(["dnf", "check-update", "-q"])
    if out is not None:
        if out[0] == 100:
            r.add(Severity.MEDIUM, "Є оновлення, що очікують", "", "sudo dnf upgrade")
        elif out[0] == 0:
            r.add(Severity.OK, "Система оновлена")
        return
    r.add(Severity.INFO, "Оновлення ОС: не вдалося перевірити")


_ADDR = re.compile(r"(\*|\[?[0-9a-fA-F:.]+\]?|localhost)[:.](\d+)$")


def _listening(s: System) -> list[tuple[str, int, str]] | None:
    """[(адреса, порт, процес)] або None, якщо не вдалося."""
    result: list[tuple[str, int, str]] = []
    if s.os == "windows":
        out = s.run(["netstat", "-ano"])
        if not out:
            return None
        for line in out[1].splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("TCP", "UDP") and ("LISTENING" in parts or parts[0] == "UDP"):
                m = _ADDR.search(parts[1])
                if m:
                    result.append((m.group(1), int(m.group(2)), parts[-1]))
        return result
    out = s.run(["ss", "-tulnpH"]) if s.os == "linux" else None
    if out and out[0] == 0:
        for line in out[1].splitlines():
            parts = line.split()
            if len(parts) >= 5:
                m = _ADDR.search(parts[4])
                if m:
                    proc = re.search(r'"([^"]+)"', line)
                    result.append((m.group(1), int(m.group(2)), proc.group(1) if proc else ""))
        return result
    out = s.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    if not out:
        return None
    for line in out[1].splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 9:
            m = _ADDR.search(parts[8])
            if m:
                result.append((m.group(1), int(m.group(2)), parts[0]))
    return result


def _is_local(addr: str) -> bool:
    addr = addr.strip("[]")
    return addr.startswith("127.") or addr in ("::1", "localhost") or addr.startswith("%lo")


def check_ports(s: System, r: Report) -> None:
    entries = _listening(s)
    if entries is None:
        r.add(Severity.INFO, "Відкриті порти: не вдалося перевірити")
        return
    exposed = sorted({(port, proc) for addr, port, proc in entries if not _is_local(addr)})
    if not exposed:
        r.add(Severity.OK, "Назовні не слухає жоден сервіс",
              f"Локальних сервісів: {len(entries)}" if entries else "")
        return
    for port, proc in exposed:
        name = RISKY_PORTS.get(port)
        who = f" ({proc})" if proc else ""
        if name:
            r.add(Severity.HIGH, f"Порт {port} [{name}] відкритий для мережі{who}",
                  "Такі сервіси часто атакують ботами.",
                  "Прив'яжи сервіс до 127.0.0.1 або закрий порт у фаєрволі")
        else:
            r.add(Severity.LOW, f"Порт {port} відкритий для мережі{who}", "",
                  "Переконайся, що цей сервіс справді має бути доступний іззовні")


def check_sshd(s: System, r: Report) -> None:
    if s.os == "windows":
        return
    text = s.read("/etc/ssh/sshd_config")
    if text is None:
        r.add(Severity.OK, "SSH-сервер не налаштований")
        return
    conf = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition(" ")
            conf.setdefault(key.lower(), value.strip().lower())
    if conf.get("permitrootlogin") == "yes":
        r.add(Severity.HIGH, "SSH дозволяє вхід під root", "",
              "У /etc/ssh/sshd_config: PermitRootLogin no")
    if conf.get("passwordauthentication", "yes") == "yes":
        r.add(Severity.MEDIUM, "SSH приймає вхід за паролем",
              "Паролі можна підбирати; ключі значно надійніші.",
              "Налаштуй вхід за ключем, потім PasswordAuthentication no")
    if conf.get("permitemptypasswords") == "yes":
        r.add(Severity.CRITICAL, "SSH дозволяє порожні паролі", "", "PermitEmptyPasswords no")
    if conf.get("permitrootlogin") != "yes" and conf.get("passwordauthentication") == "no":
        r.add(Severity.OK, "SSH-сервер налаштований безпечно")


def check_autologin(s: System, r: Report) -> None:
    if s.os == "linux":
        for path in ("/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"):
            text = s.read(path) or ""
            if re.search(r"^\s*AutomaticLoginEnable\s*=\s*true", text, re.M | re.I):
                r.add(Severity.MEDIUM, "Увімкнено автоматичний вхід (GDM)", "",
                      f"У {path}: AutomaticLoginEnable=false")
                return
        text = s.read("/etc/lightdm/lightdm.conf") or ""
        if re.search(r"^\s*autologin-user\s*=\s*\S+", text, re.M):
            r.add(Severity.MEDIUM, "Увімкнено автоматичний вхід (LightDM)", "",
                  "Прибери autologin-user з /etc/lightdm/lightdm.conf")
            return
        r.add(Severity.OK, "Автоматичний вхід вимкнено")
    elif s.os == "darwin":
        out = s.run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
        if out and out[0] == 0 and out[1].strip():
            r.add(Severity.MEDIUM, "Увімкнено автоматичний вхід", "",
                  "System Settings → Users & Groups → Automatically log in as → Off")
        else:
            r.add(Severity.OK, "Автоматичний вхід вимкнено")


def check_macos_protections(s: System, r: Report) -> None:
    if s.os != "darwin":
        return
    out = s.run(["csrutil", "status"])
    if out and "enabled" in out[1].lower():
        r.add(Severity.OK, "System Integrity Protection увімкнено")
    elif out:
        r.add(Severity.HIGH, "System Integrity Protection вимкнено", "",
              "У режимі Recovery: csrutil enable")
    out = s.run(["spctl", "--status"])
    if out and "enabled" in out[1].lower():
        r.add(Severity.OK, "Gatekeeper увімкнено")
    elif out:
        r.add(Severity.MEDIUM, "Gatekeeper вимкнено", "", "sudo spctl --master-enable")


CHECKS = [check_firewall, check_disk_encryption, check_updates, check_ports, check_sshd,
          check_autologin, check_macos_protections]


def audit(system: System | None = None) -> Report:
    s = system or System(platform.system().lower())
    names = {"linux": "Linux", "darwin": "macOS", "windows": "Windows"}
    report = Report(f"Аудит системи · {names.get(s.os, s.os)}")
    for check in CHECKS:
        try:
            check(s, report)
        except Exception as exc:  # одна зламана перевірка не валить увесь аудит
            report.add(Severity.INFO, f"{check.__name__}: помилка перевірки", type(exc).__name__)
    report.score = score(report.findings)
    issues = report.issues
    report.summary = (f"Проблем: {len(issues)}" if issues else "Серйозних проблем не знайдено")
    report.notes.append("Аудит лише читає стан системи й нічого не змінює.")
    return report
