"""Modelos de datos. El secreto encontrado nunca se guarda completo: solo
sus primeros caracteres, igual que WebScan hace con los que encuentra en HTML."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {0: "Informativo", 1: "Baja", 2: "Media", 3: "Alta", 4: "Crítica"}[int(self)]


@dataclass
class Finding:
    kind: str                  # nombre del tipo de secreto (ej. "Clave de AWS")
    severity: Severity
    commit: str                 # hash corto
    author: str
    date: str
    file: str
    line_number: int
    evidence: str                # valor truncado, nunca completo
    still_in_head: bool          # ¿sigue expuesto en la versión actual, o solo en el historial?
    detection: str = "firma"     # "firma" | "entropía"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        return d


@dataclass
class ScanResult:
    repo_path: str
    started_at: str
    finished_at: str = ""
    commits_scanned: int = 0
    truncated: bool = False
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.commit, f.file))

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "commits_scanned": self.commits_scanned,
            "truncated": self.truncated,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }
