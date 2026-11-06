"""/secrets — пошук API-ключів, токенів і приватних ключів у власних теках і в історії git.

Знайдені значення ніколи не показуються повністю — лише маска «abcd…wxyz».
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from phantomstalker.security.report import Report, Severity, score

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", "target", ".idea"}
MAX_FILE = 1_000_000
MAX_HISTORY = 30_000_000
PLACEHOLDER = re.compile(r"example|changeme|change_me|xxxx|your[_-]|<[^>]+>|\$\{|\{\{|dummy|test|sample|placeholder|\*\*\*", re.I)


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    group: int = 0


R = re.compile
RULES = [
    Rule("Приватний ключ", R(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), Severity.CRITICAL),
    Rule("AWS Access Key", R(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    Rule("AWS Secret Key", R(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), Severity.CRITICAL, 1),
    Rule("GitHub токен", R(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), Severity.HIGH),
    Rule("GitLab токен", R(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), Severity.HIGH),
    Rule("Slack токен", R(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    Rule("Slack webhook", R(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), Severity.MEDIUM),
    Rule("Stripe live-ключ", R(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL),
    Rule("Google API ключ", R(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH),
    Rule("Anthropic API ключ", R(r"\bsk-ant-[A-Za-z0-9\-_]{20,}"), Severity.HIGH),
    Rule("OpenAI API ключ", R(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}"), Severity.HIGH),
    Rule("Telegram bot токен", R(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), Severity.HIGH),
    Rule("Discord токен", R(r"\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}\b"), Severity.HIGH),
    Rule("JWT", R(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), Severity.MEDIUM),
    Rule("Приватний ключ гаманця", R(r"(?i)(?:private[_ ]?key|priv[_ ]?key|secret[_ ]?key)\W{0,5}['\"]?(?:0x)?([0-9a-f]{64})\b"), Severity.CRITICAL, 1),
    Rule("Пароль у коді", R(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"), Severity.MEDIUM, 1),
    Rule("Рядок підключення з паролем", R(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s/]{4,})@"), Severity.HIGH, 1),
]


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 12:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]}"


@dataclass
class Hit:
    rule: Rule
    masked: str
    where: str
    line: int | None = None
    commit: str | None = None


def scan_text(text: str, where: str) -> list[Hit]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group)
                if PLACEHOLDER.search(value):
                    continue
                if rule.name == "Пароль у коді" and (value.startswith(("os.", "env", "process.")) or value.isupper()):
                    continue
                shown = m.group(0).strip("-").replace("BEGIN ", "") if rule.name == "Приватний ключ" else mask(value)
                hits.append(Hit(rule, shown, where, lineno))
    return hits


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(1024)
    except OSError:
        return True


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def scan_tree(root: Path) -> tuple[list[Hit], int, list[str]]:
    hits, count, env_files = [], 0, []
    for path in iter_files(root):
        rel = str(path.relative_to(root)) if path != root else path.name
        if path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith(("example", "sample", "template"))):
            env_files.append(rel)
        try:
            if path.stat().st_size > MAX_FILE or _is_binary(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        hits.extend(scan_text(text, rel))
    return hits, count, env_files


def _git(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout[:MAX_HISTORY].decode("utf-8", errors="replace")


def scan_history(root: Path) -> list[Hit]:
    out = _git(root, "log", "-p", "--all", "--no-color", "-U0", "--format=commit %H")
    if not out:
        return []
    hits: list[Hit] = []
    commit, current = "", ""
    for line in out.splitlines():
        if line.startswith("commit "):
            commit = line[7:15]
        elif line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            for hit in scan_text(line[1:], current):
                hit.line, hit.commit = None, commit
                hits.append(hit)
    return hits


def tracked(root: Path, rel: str) -> bool:
    return _git(root, "ls-files", "--error-unmatch", rel) is not None


def scan(path: str | Path = ".") -> Report:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Немає такого шляху: {root}")
    r = Report(f"Пошук секретів · {root}")
    tree_hits, files, env_files = scan_tree(root)
    is_repo = root.is_dir() and (root / ".git").exists()
    history_hits = scan_history(root) if is_repo else []

    seen: set[tuple[str, str]] = set()
    for hit in tree_hits:
        key = (hit.rule.name, hit.masked)
        if key in seen:
            continue
        seen.add(key)
        r.add(hit.rule.severity, f"{hit.rule.name}: {hit.masked}", f"{hit.where}:{hit.line}",
              "Відклич ключ у сервісі, винеси в змінні середовища або менеджер секретів")
    for hit in history_hits:
        key = (hit.rule.name, hit.masked)
        if key in seen:
            continue
        seen.add(key)
        r.add(hit.rule.severity, f"{hit.rule.name} в історії git: {hit.masked}",
              f"{hit.where}, коміт {hit.commit} — файл уже виправлено, але ключ лишився в історії",
              "Відклич ключ; потім вичисти історію: git filter-repo --replace-text")
    for rel in env_files:
        if is_repo and tracked(root, rel):
            r.add(Severity.HIGH, f"Файл {rel} закомічено в git", "У .env зазвичай лежать секрети.",
                  f"git rm --cached {rel} і додай .env у .gitignore")
    if not r.findings:
        r.add(Severity.OK, "Секретів не знайдено")
    r.score = score(r.findings)
    history = f" · історію git перевірено" if is_repo else ""
    r.summary = f"Перевірено файлів: {files}{history}"
    r.notes.append("Значення приховано маскою — повністю їх не видно ніде, і нікуди вони не надсилаються.")
    return r
