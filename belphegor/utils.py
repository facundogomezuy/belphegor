"""Helpers de presentación, detección de comodín y guardado de resultados.

Todo opera sobre `Finding` (ver models.py), no sobre la salida cruda de ningún
motor: así la lógica de acá sirve igual para gobuster, ffuf o lo que venga.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from rich.table import Table

from ._console import err, out
from .models import Finding

# Si un único par (status, size) cubre esta fracción o más de los resultados con
# ambos campos, lo tratamos como probable respuesta comodín (WAF, catch-all,
# fallback de SPA…). Es una heurística de patrón, no una certeza.
WILDCARD_THRESHOLD = 0.7

# Con pocos resultados, "el 70% comparte status/size" no dice nada. Por debajo de
# este piso no clasificamos.
MIN_RESULTS_FOR_WILDCARD = 5


# --------------------------------------------------------------------------- #
# Presentación
# --------------------------------------------------------------------------- #
def print_results_table(results: list[Finding], title: str = "Resultados") -> None:
    """Muestra los hallazgos en una tabla rich (va a stdout: es el resultado)."""
    if not results:
        out.print("[dim]— sin hallazgos —[/dim]")
        return

    table = Table(title=title, header_style="bold magenta", expand=False)
    table.add_column("#", style="dim", justify="right", no_wrap=True)
    table.add_column("Hallazgo", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right", style="dim")

    for i, f in enumerate(results, 1):
        status = str(f.status)
        status_style = _status_style(status)
        table.add_row(
            str(i),
            f.path or f.raw,
            f"[{status_style}]{status}[/{status_style}]" if status else "",
            str(f.size),
        )

    out.print(table)


def render_results(
    results: list[Finding], title: str = "Resultados"
) -> tuple[list[Finding], list[Finding], Optional[dict]]:
    """Imprime la tabla separando hallazgos de probable ruido comodín.

    Devuelve (hallazgos, ruido, comodín) para que el caller decida qué guardar o
    cómo seguir. No borra nada.
    """
    hallazgos, ruido, wildcard = split_wildcard_noise(results)

    print_results_table(hallazgos, title=title)

    if wildcard is not None:
        pct = round(wildcard["fraction"] * 100)
        out.print(
            f"[dim]— filtrados como probable comodín: {wildcard['count']} "
            f"con status {wildcard['status']} · size {wildcard['size']} "
            f"({pct}% de las respuestas con status/size) —[/dim]"
        )

    return hallazgos, ruido, wildcard


def _status_style(status: str) -> str:
    """Color según el rango del status HTTP."""
    if not status.isdigit():
        return "white"
    code = int(status)
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "yellow"
    if 400 <= code < 500:
        return "red"
    if 500 <= code < 600:
        return "bold red"
    return "white"


# --------------------------------------------------------------------------- #
# Detección de comodín
# --------------------------------------------------------------------------- #
def detect_wildcard(results: list[Finding]) -> Optional[dict]:
    """Busca un par (status, size) dominante entre los hallazgos.

    Solo mira los que tienen ambos campos (dir/vhost; dns no aplica). Si el par
    más repetido cubre >= WILDCARD_THRESHOLD de esos items, lo devuelve como
    probable comodín. Es una heurística sobre el patrón, no una certeza.
    """
    pairs = [(f.status, f.size) for f in results if f.status and f.size]
    if len(pairs) < MIN_RESULTS_FOR_WILDCARD:
        return None

    (status, size), count = Counter(pairs).most_common(1)[0]
    fraction = count / len(pairs)
    if fraction < WILDCARD_THRESHOLD:
        return None

    return {
        "status": status,
        "size": size,
        "count": count,
        "total": len(pairs),
        "fraction": fraction,
    }


def split_wildcard_noise(
    results: list[Finding],
) -> tuple[list[Finding], list[Finding], Optional[dict]]:
    """Separa `results` en (hallazgos, ruido, comodín) sin descartar nada."""
    wildcard = detect_wildcard(results)
    if wildcard is None:
        return results, [], None

    hallazgos: list[Finding] = []
    ruido: list[Finding] = []
    for f in results:
        if f.status == wildcard["status"] and f.size == wildcard["size"]:
            ruido.append(f)
        else:
            hallazgos.append(f)
    return hallazgos, ruido, wildcard


# --------------------------------------------------------------------------- #
# Serialización / guardado
# --------------------------------------------------------------------------- #
def iter_jsonl(results: list[Finding]) -> Iterator[str]:
    """Una línea JSON por hallazgo (formato JSONL, ideal para pipear)."""
    for f in results:
        yield json.dumps(f.to_dict(), ensure_ascii=False)


def save_results(
    results: list[Finding],
    path: str,
    fmt: str = "txt",
    meta: Optional[dict] = None,
) -> None:
    """Guarda los resultados en disco (txt / json / jsonl)."""
    fmt = fmt.lower()
    meta = dict(meta or {})
    meta.setdefault("generated_at", datetime.now(timezone.utc).isoformat())

    if fmt == "json":
        payload = {"meta": meta, "results": [f.to_dict() for f in results]}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    elif fmt == "jsonl":
        with open(path, "w", encoding="utf-8") as fh:
            for linea in iter_jsonl(results):
                fh.write(linea + "\n")
    else:  # txt
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Belphegor — resultados de enumeración\n")
            for k, v in meta.items():
                fh.write(f"# {k}: {v}\n")
            fh.write("#\n")
            for f in results:
                fh.write(f.raw + "\n")

    # Mensaje de guardado = diagnóstico → stderr (no ensucia un pipe).
    err.print(f"[green][+] Guardado en[/green] [bold]{path}[/bold] ({fmt})")


def iter_nonempty(lines: Iterable[str]) -> Iterator[str]:
    """Filtra líneas vacías, útil para pipes."""
    for ln in lines:
        if ln.strip():
            yield ln
