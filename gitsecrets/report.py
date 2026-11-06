"""Reportes en texto, JSON y HTML. El valor del secreto nunca se muestra
completo (ya llega truncado desde scanner.py); el reporte solo lo escapa
además, por si acaso."""
from __future__ import annotations

import json
from html import escape

from .models import ScanResult, Severity

COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#c2410c", "LOW": "#a16207", "INFO": "#475569"}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def to_text(result: ScanResult) -> str:
    lines = [f"Repositorio    : {result.repo_path}",
              f"Commits        : {result.commits_scanned}" + (" (truncado, hay más)" if result.truncated else ""),
              "Resumen        : " + (", ".join(f"{k}={v}" for k, v in result.summary().items() if v) or "sin hallazgos"),
              ""]
    for f in result.sorted_findings():
        estado = "SIGUE EN HEAD" if f.still_in_head else "solo en el historial (ya removido)"
        lines.append(f"[{f.severity.label.upper()}] {f.kind}  ({f.detection})")
        lines.append(f"    Archivo  : {f.file}:{f.line_number}")
        lines.append(f"    Commit   : {f.commit}  por {f.author}  el {f.date}")
        lines.append(f"    Estado   : {estado}")
        lines.append(f"    Evidencia: {f.evidence}")
        lines.append("")
    for e in result.errors:
        lines.append(f"[!] {e}")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    summ = result.summary()
    chips = "".join(
        f'<span class="chip" style="background:{COLORS[k]}">{Severity[k].label}: {v}</span>'
        for k, v in summ.items() if v) or "<span>Sin hallazgos</span>"

    cards = []
    for f in result.sorted_findings():
        col = COLORS[f.severity.name]
        estado = ('<span class="warn">Sigue en HEAD</span>' if f.still_in_head
                  else '<span class="ok">Solo en el historial (ya removido)</span>')
        cards.append(
            f'<article style="border-left:6px solid {col}"><h3><span class="sev" style="background:{col}">'
            f'{f.severity.label}</span> {escape(f.kind)} <small>({escape(f.detection)})</small></h3>'
            f'<p><strong>Archivo:</strong> {escape(f.file)}:{f.line_number}</p>'
            f'<p><strong>Commit:</strong> {escape(f.commit)} por {escape(f.author)} el {escape(f.date)}</p>'
            f'<p>{estado}</p>'
            f'<pre>{escape(f.evidence)}</pre></article>')
    errs = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
    errs = f"<h2>Advertencias</h2><ul>{errs}</ul>" if errs else ""

    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GitSecrets - {escape(result.repo_path)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}}
h1{{margin-bottom:.2rem}} .meta{{color:#475569}}
.chip{{color:#fff;padding:.2rem .6rem;border-radius:999px;margin-right:.4rem;font-size:.85rem}}
article{{background:#fff;padding:1rem 1.2rem;margin:1rem 0;border-radius:8px;box-shadow:0 1px 3px #0001}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.8rem;vertical-align:middle}}
pre{{background:#f1f5f9;padding:.6rem;border-radius:6px;overflow:auto;white-space:pre-wrap}}
.warn{{color:#b91c1c;font-weight:600}} .ok{{color:#16a34a;font-weight:600}}
</style></head><body>
<h1>Reporte GitSecrets</h1>
<p class="meta">{escape(result.repo_path)} · {result.commits_scanned} commits revisados{' (truncado)' if result.truncated else ''}</p>
<p>{chips}</p>
<h2>Hallazgos ({len(result.findings)})</h2>
{''.join(cards) or '<p>No se detectaron secretos en el historial revisado.</p>'}
{errs}
</body></html>"""
