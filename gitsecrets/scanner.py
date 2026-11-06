"""Recorre el historial de un repositorio git y revisa, en cada commit,
solo las LÍNEAS AGREGADAS respecto a su commit padre (no todo el archivo
completo en cada versión: así se sabe exactamente en qué commit se
introdujo cada secreto, y no se repite el mismo hallazgo commit tras
commit mientras el secreto sigue sin tocarse)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import git

from . import patterns
from .models import Finding, ScanResult, Severity

DEFAULT_MAX_COMMITS = 500
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _added_lines(diff_bytes: bytes) -> list[tuple[int, str]]:
    """[(número de línea en la versión nueva, contenido)] de un diff unificado."""
    try:
        text = diff_bytes.decode("utf-8", errors="replace") if isinstance(diff_bytes, bytes) else diff_bytes
    except Exception:
        return []
    out: list[tuple[int, str]] = []
    line_no = 0
    for line in text.splitlines():
        if line.startswith("@@"):
            m = HUNK_HEADER.match(line)
            line_no = int(m.group(1)) - 1 if m else line_no
            continue
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            line_no += 1
            out.append((line_no, line[1:]))
        elif not line.startswith("-"):
            line_no += 1
    return out


def scan_line(line: str) -> list[tuple[str, str, str]]:
    """Devuelve [(tipo, valor_completo, metodo)] para cada coincidencia en la línea."""
    matches: list[tuple[str, str, str]] = []
    for kind, rx in patterns.KNOWN_PATTERNS.items():
        m = rx.search(line)
        if m:
            matches.append((kind, m.group(0), "firma"))
    for m in patterns.GENERIC_ASSIGNMENT.finditer(line):
        name, value = m.group(1), m.group(2)
        if patterns.looks_random(value):
            matches.append((f"Posible secreto ({name})", value, "entropía"))
    return matches


def _still_in_head(repo: git.Repo, path: str, value: str) -> bool:
    try:
        blob = repo.head.commit.tree / path
        content = blob.data_stream.read().decode("utf-8", errors="replace")
        return value in content
    except Exception:
        return False


def scan_repo(repo_path: str, max_commits: int = DEFAULT_MAX_COMMITS, all_branches: bool = False) -> ScanResult:
    result = ScanResult(repo_path=repo_path, started_at=_now())
    try:
        repo = git.Repo(repo_path)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError) as exc:
        result.errors.append(f"No es un repositorio git válido: {exc}")
        result.finished_at = _now()
        return result

    try:
        commits = list(repo.iter_commits("--all" if all_branches else "HEAD"))
    except Exception as exc:
        result.errors.append(f"No se pudo leer el historial (¿repositorio vacío?): {exc}")
        result.finished_at = _now()
        return result

    if len(commits) > max_commits:
        result.truncated = True
        commits = commits[:max_commits]
    result.commits_scanned = len(commits)

    for commit in commits:
        parent = commit.parents[0] if commit.parents else None
        try:
            diffs = parent.diff(commit, create_patch=True) if parent else commit.diff(git.NULL_TREE, create_patch=True)
        except Exception as exc:
            result.errors.append(f"Commit {commit.hexsha[:8]}: no se pudo generar el diff ({exc})")
            continue

        for d in diffs:
            path = d.b_path or d.a_path
            if path is None or d.diff is None:
                continue
            for line_no, content in _added_lines(d.diff):
                for kind, value, method in scan_line(content):
                    result.findings.append(Finding(
                        kind=kind,
                        severity=Severity.CRITICAL if method == "firma" else Severity.HIGH,
                        commit=commit.hexsha[:8], author=commit.author.name,
                        date=commit.committed_datetime.isoformat(),
                        file=path, line_number=line_no,
                        evidence=value[:6] + "…(truncado)",
                        still_in_head=_still_in_head(repo, path, value),
                        detection=method))

    result.finished_at = _now()
    return result
