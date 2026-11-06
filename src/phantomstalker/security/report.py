"""Уніфікований звіт інструментів безпеки."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    OK = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return {
            Severity.OK: "ок",
            Severity.INFO: "інфо",
            Severity.LOW: "низький",
            Severity.MEDIUM: "середній",
            Severity.HIGH: "високий",
            Severity.CRITICAL: "критичний",
        }[self]


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    title: str
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    score: int | None = None
    notes: list[str] = field(default_factory=list)
    checklist: bool = False  # план дій: показувати як список кроків, а не як знахідки

    def add(self, severity: Severity, title: str, detail: str = "", fix: str = "") -> Finding:
        finding = Finding(severity, title, detail, fix)
        self.findings.append(finding)
        return finding

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.OK)

    @property
    def issues(self) -> list[Finding]:
        return [f for f in self.findings if f.severity >= Severity.LOW]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -int(f.severity))

    def to_text(self) -> str:
        """Текстова версія для пояснення від ШІ (без секретів — їх тут немає за побудовою)."""
        lines = [self.title]
        if self.summary:
            lines.append(self.summary)
        if self.score is not None:
            lines.append(f"Оцінка: {self.score}/100")
        for f in self.sorted_findings():
            lines.append(f"- [{f.severity.label}] {f.title}")
            if f.detail:
                lines.append(f"  {f.detail}")
            if f.fix:
                lines.append(f"  Виправлення: {f.fix}")
        lines += [f"Примітка: {n}" for n in self.notes]
        return "\n".join(lines)


PENALTY = {Severity.CRITICAL: 30, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 4}


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(PENALTY.get(f.severity, 0) for f in findings))


class SecurityError(Exception):
    """Помилка з повідомленням для користувача."""
