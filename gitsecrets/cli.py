"""Interfaz de línea de comandos: gitsecrets scan <ruta-al-repo>"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import to_html, to_json, to_text
from .scanner import DEFAULT_MAX_COMMITS, scan_repo

LEGAL = ("Revisa el historial de un repositorio git local en busca de secretos olvidados "
         "(claves, tokens, contraseñas). Solo lee tu propio repositorio o uno que hayas "
         "clonado; no se conecta a ningún servidor.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gitsecrets", description=LEGAL)
    p.add_argument("--version", action="version", version=f"gitsecrets {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Escanea el historial de un repositorio")
    s.add_argument("repo", help="Ruta a un repositorio git local (ya clonado)")
    s.add_argument("--all-branches", action="store_true", help="Revisa todas las ramas, no solo HEAD")
    s.add_argument("--max-commits", type=int, default=DEFAULT_MAX_COMMITS,
                   help=f"Límite de commits a revisar (por defecto {DEFAULT_MAX_COMMITS})")
    s.add_argument("--format", choices=["text", "json", "html"], default="text")
    s.add_argument("-o", "--output", help="Archivo de salida (por defecto stdout)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    result = scan_repo(args.repo, max_commits=args.max_commits, all_branches=args.all_branches)

    if args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = to_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Reporte guardado en {args.output}")
    else:
        print(out)
    return 2 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
