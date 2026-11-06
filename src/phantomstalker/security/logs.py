"""/logs — розбір журналів автентифікації (auth.log, secure, journalctl): підбір паролів, підозрілі входи."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from phantomstalker.security.audit import Runner, run_command
from phantomstalker.security.report import Report, Severity, score

FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)")
INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
SUDO_FAIL = re.compile(r"sudo:.*(?:incorrect password attempts|authentication failure)")

DEFAULT_LOGS = ("/var/log/auth.log", "/var/log/secure")
BRUTE_THRESHOLD = 10


def analyze(text: str, source: str = "журнал") -> Report:
    failures: Counter[str] = Counter()
    users_tried: dict[str, set[str]] = defaultdict(set)
    accepted: list[tuple[str, str, str]] = []
    sudo_failures = 0
    for line in text.splitlines():
        if m := FAILED.search(line):
            user, ip = m.groups()
            failures[ip] += 1
            users_tried[ip].add(user)
        elif m := INVALID.search(line):
            users_tried[m.group(2)].add(m.group(1) or "?")
        elif m := ACCEPTED.search(line):
            accepted.append(m.groups())
        elif SUDO_FAIL.search(line):
            sudo_failures += 1

    r = Report(f"Аналіз журналу · {source}")
    for method, user, ip in accepted:
        if failures.get(ip, 0) >= 3:
            r.add(Severity.CRITICAL, f"Успішний вхід {user}@ з {ip} після {failures[ip]} невдалих спроб",
                  "Схоже, пароль підібрали.",
                  "Негайно зміни пароль, перевір ~/.ssh/authorized_keys і процеси, заблокуй IP")
    for _method, user, ip in accepted:
        if user == "root":
            r.add(Severity.HIGH, f"Вхід під root з {ip}", "", "PermitRootLogin no у sshd_config")
            break
    password_logins = [a for a in accepted if a[0] == "password"]
    if password_logins:
        r.add(Severity.LOW, f"Входів за паролем: {len(password_logins)}", "",
              "Перейди на вхід за SSH-ключем і вимкни PasswordAuthentication")

    brute = [(ip, n) for ip, n in failures.most_common() if n >= BRUTE_THRESHOLD]
    for ip, n in brute[:10]:
        users = ", ".join(sorted(users_tried[ip])[:5])
        r.add(Severity.HIGH, f"Підбір пароля з {ip}: {n} спроб", f"Логіни: {users}",
              f"sudo ufw deny from {ip}; встанови fail2ban")
    if len(brute) > 10:
        r.add(Severity.HIGH, f"…і ще {len(brute) - 10} IP з масовими спробами")
    total = sum(failures.values())
    if total and not brute:
        r.add(Severity.LOW, f"Невдалих спроб входу: {total}", f"З {len(failures)} IP")
    if sudo_failures:
        r.add(Severity.MEDIUM if sudo_failures >= 3 else Severity.LOW,
              f"Невдалих спроб sudo: {sudo_failures}", "Хтось вводив неправильний пароль sudo.")
    if accepted:
        ips = sorted({a[2] for a in accepted})
        r.add(Severity.INFO, f"Успішних входів: {len(accepted)}", "IP: " + ", ".join(ips[:8]))
    if not r.findings:
        r.add(Severity.OK, "Подій входу не знайдено або все спокійно")
    r.score = score(r.findings)
    r.summary = f"Невдалих спроб: {total} · успішних входів: {len(accepted)}"
    return r


def load(path: str | None, run: Runner = run_command) -> tuple[str, str]:
    """(текст, джерело). Без шляху — стандартні журнали або journalctl."""
    candidates = [path] if path else list(DEFAULT_LOGS)
    for candidate in candidates:
        p = Path(candidate).expanduser()
        try:
            return p.read_text(encoding="utf-8", errors="replace"), str(p)
        except PermissionError as exc:
            if path:
                raise PermissionError(f"Немає прав читати {p} — спробуй через sudo") from exc
        except OSError:
            if path:
                raise FileNotFoundError(f"Файл не знайдено: {p}") from None
    out = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "7 days ago", "--no-pager", "-q"])
    if out and out[0] == 0 and out[1].strip():
        return out[1], "journalctl (7 днів)"
    raise FileNotFoundError("Журнали не знайдено. Вкажи шлях: /logs /шлях/до/auth.log")
