"""Helpers de output y guardado de resultados."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Iterable

from rich.console import Console
from rich.table import Table

console = Console()

# gobuster usa el logger estándar de Go para sus mensajes fatales (p.ej. el
# aviso de precheck de wildcard), que siempre vienen prefijados con
# "YYYY/MM/DD HH:MM:SS ". Nunca es un hallazgo, así que lo tratamos como ruido
# en parse_gobuster_line.
_GOBUSTER_LOG_PREFIX = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\b")


def print_results_table(results: list[dict], title: str = "Resultados") -> None:
    """Muestra los resultados parseados en una tabla rich.

    `results` es una lista de dicts con al menos la clave 'raw' (la línea
    original de gobuster) y, cuando se pudo parsear, 'path'/'status'/'size'.
    """
    if not results:
        console.print("[dim]— sin hallazgos —[/dim]")
        return

    table = Table(title=title, header_style="bold magenta", expand=False)
    table.add_column("#", style="dim", justify="right", no_wrap=True)
    table.add_column("Hallazgo", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right", style="dim")

    for i, item in enumerate(results, 1):
        status = str(item.get("status", ""))
        status_style = _status_style(status)
        table.add_row(
            str(i),
            item.get("path", item.get("raw", "")),
            f"[{status_style}]{status}[/{status_style}]" if status else "",
            str(item.get("size", "")),
        )

    console.print(table)


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


def save_results(
    results: list[dict],
    path: str,
    fmt: str = "txt",
    meta: dict | None = None,
) -> None:
    """Guarda los resultados en disco.

    Args:
        results: lista de hallazgos (dicts).
        path:    archivo de salida.
        fmt:     'txt' (una línea por hallazgo) o 'json' (estructurado).
        meta:    metadata opcional (target, modo, wordlist, timestamp) que se
                 incluye en el header txt / en el objeto json.
    """
    fmt = fmt.lower()
    meta = meta or {}
    meta.setdefault("generated_at", datetime.now(timezone.utc).isoformat())

    if fmt == "json":
        payload = {"meta": meta, "results": results}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    else:  # txt
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Belphegor — resultados de enumeración\n")
            for k, v in meta.items():
                fh.write(f"# {k}: {v}\n")
            fh.write("#\n")
            for item in results:
                fh.write(item.get("raw", "") + "\n")

    console.print(f"[green][+] Guardado en[/green] [bold]{path}[/bold] ({fmt})")


def parse_gobuster_line(line: str, mode: str) -> dict | None:
    """Intenta parsear una línea de salida de gobuster en un dict.

    gobuster no da un formato 100% estable entre modos/versiones, así que si no
    matcheamos algo con pinta de hallazgo devolvemos None y el caller decide.
    Siempre guardamos la línea cruda en 'raw' cuando sí es un hallazgo.
    """
    stripped = line.strip()
    if not stripped:
        return None

    if _GOBUSTER_LOG_PREFIX.match(stripped):
        return None

    # Líneas de progreso/infra de gobuster que no son hallazgos.
    noise_prefixes = (
        "=", "Gobuster", "[+]", "[*]", "Progress:", "Starting", "Finished",
        "by OJ", "---", "Error:", "[ERROR]",
    )
    if stripped.startswith(noise_prefixes):
        return None

    item: dict = {"raw": stripped}

    # dir:    /admin (Status: 301) [Size: 313] [--> /admin/]
    # dns:    Found: sub.dominio.com
    # vhost:  Found: vhost.dominio.com (Status: 200) [Size: 1234]
    if mode == "dns":
        # En dns los hallazgos suelen venir como "Found: <sub>".
        if stripped.lower().startswith("found:"):
            item["path"] = stripped.split(":", 1)[1].strip()
            return item
        # Algunas versiones imprimen el subdominio pelado.
        item["path"] = stripped
        return item

    # dir / vhost: extraemos path, status y size si están.
    text = stripped
    if text.lower().startswith("found:"):
        text = text.split(":", 1)[1].strip()

    item["path"] = text.split(" ")[0] if text else stripped

    if "Status:" in stripped:
        try:
            after = stripped.split("Status:", 1)[1]
            item["status"] = after.strip().split(")")[0].strip().split()[0]
        except (IndexError, ValueError):
            pass
    if "Size:" in stripped:
        try:
            after = stripped.split("Size:", 1)[1]
            item["size"] = after.strip().split("]")[0].strip().split()[0]
        except (IndexError, ValueError):
            pass

    return item


def is_wildcard_precheck_error(line: str) -> bool:
    """True si la línea es el error fatal de gobuster por precheck de wildcard.

    Antes de arrancar, gobuster le pega a una URL random para ver si el
    target devuelve el mismo status/tamaño para cualquier cosa (catch-all
    403, WAF, vhost comodín, etc.). Si es así, aborta con este mensaje en vez
    de escanear — y sin esto, esa línea se cuela como un hallazgo trucho.
    """
    lowered = line.lower()
    return (
        "the server returns a status code that matches" in lowered
        or "please exclude the response length or the status code" in lowered
    )


def iter_nonempty(lines: Iterable[str]) -> Iterable[str]:
    """Filtra líneas vacías, útil para pipes."""
    for ln in lines:
        if ln.strip():
            yield ln
