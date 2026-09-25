"""Belphegor — entry point.

Modo dual:
  - Sin argumentos → menú interactivo.
  - Con flags     → ejecuta el módulo directo (scripteable).
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from . import banner, __version__
from .engines import ENGINES
from .preflight import check_tools, ToolMissingError, TargetError
from .modules import enum_gobuster
from .modules.enum_gobuster import (
    EnumConfig, MODES, THREADS_DEFAULT, LEVELS, DEFAULT_LEVEL, LEVEL_DESC,
)

console = Console()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="belphegor",
        description="Belphegor — recon & enumeration toolkit (bug bounty / pentest).",
        epilog="Sin argumentos entra al menú interactivo.",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"belphegor {__version__}",
    )
    # -v es global: sirve tanto para `belphegor -v` (menú interactivo con
    # verbose) como para `belphegor enum ... -v` (CLI). El subparser lo repite
    # con default=SUPPRESS para no pisar este valor cuando va antes del
    # subcomando (ver build de `enum`).
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="Mostrar cada hallazgo en vivo, apenas aparece (útil en CTF). "
             "Sin subcomando, entra al menú interactivo con verbose activado.",
    )
    sub = parser.add_subparsers(dest="command")

    # ---- enum (gobuster) -------------------------------------------------- #
    enum = sub.add_parser(
        "enum",
        help="Enumeración de contenido con gobuster (dir/vhost/dns).",
    )
    enum.add_argument("target", help="Dominio o URL objetivo (ej: pepito.com).")
    enum.add_argument(
        "-m", "--mode", choices=MODES, required=True,
        help="Modo de gobuster.",
    )
    enum.add_argument(
        "-L", "--level", choices=LEVELS, default=DEFAULT_LEVEL,
        help=f"Nivel de wordlist: basic/full/deep (default {DEFAULT_LEVEL}). "
             f"Se ignora si pasás -w.",
    )
    enum.add_argument(
        "-w", "--wordlist",
        help="Wordlist propia (tiene prioridad sobre --level).",
    )
    enum.add_argument(
        "-t", "--threads", type=int, default=THREADS_DEFAULT,
        help=f"Hilos (default {THREADS_DEFAULT}).",
    )
    enum.add_argument("--delay", help="Delay entre requests (pasa a gobuster --delay).")
    enum.add_argument("-x", "--extensions", help="Extensiones para modo dir (php,html,bak).")
    enum.add_argument("-s", "--status-include", help="Status codes a incluir (gobuster -s).")
    enum.add_argument("-b", "--status-exclude", help="Status codes a excluir (gobuster -b).")
    enum.add_argument(
        "--exclude-length",
        help="Tamaño(s) de respuesta a excluir (gobuster --exclude-length).",
    )
    enum.add_argument(
        "--auto-filter", action="store_true",
        help="Si se detecta una respuesta comodín, re-correr solo excluyendo "
             "su tamaño (sin preguntar).",
    )
    enum.add_argument(
        "--protocol", choices=["http", "https"],
        help="Forzar esquema y saltear la autodetección.",
    )
    enum.add_argument("-o", "--output", help="Archivo donde guardar resultados.")
    enum.add_argument(
        "--format", choices=["txt", "json", "jsonl"], default="txt",
        help="Formato del archivo de salida (default txt).",
    )
    enum.add_argument(
        "--engine", choices=ENGINES, default="gobuster",
        help="Motor de escaneo (default gobuster).",
    )
    enum.add_argument(
        "--json", action="store_true",
        help="Emitir los hallazgos como JSONL por stdout, para pipear "
             "(el diagnóstico va a stderr). Se activa solo también si stdout "
             "no es una terminal.",
    )
    enum.add_argument(
        "--no-install", action="store_true",
        help="No ofrecer instalar herramientas faltantes (útil para scripts/CI).",
    )
    # Mismo dest que el flag global. default=SUPPRESS: si acá no viene -v, no
    # escribe nada en el namespace, así no pisa un -v que haya ido antes del
    # subcomando (belphegor -v enum ...). Si viene, lo activa.
    enum.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Mostrar cada hallazgo en vivo, apenas aparece (útil en CTF, "
             "donde querés reaccionar rápido). Por defecto van todos juntos a "
             "la tabla final.",
    )
    return parser


def run_enum_from_args(args: argparse.Namespace) -> int:
    cfg = EnumConfig(
        target=args.target,
        mode=args.mode,
        wordlist=args.wordlist,
        level=args.level,
        threads=args.threads,
        delay=args.delay,
        extensions=args.extensions,
        status_include=args.status_include,
        status_exclude=args.status_exclude,
        exclude_length=args.exclude_length,
        force_scheme=args.protocol,
        output=args.output,
        out_format=args.format,
        no_install=args.no_install,
        auto_filter=args.auto_filter,
        verbose=args.verbose,
        engine=args.engine,
        # JSONL por stdout si se pidió --json, o si stdout no es una terminal
        # (redirección / pipe): así la salida se integra a un pipeline sola.
        stdout_json=args.json or not sys.stdout.isatty(),
    )
    try:
        enum_gobuster.run(cfg, interactive=False)
        return 0
    except (ToolMissingError, TargetError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        return 1


# --------------------------------------------------------------------------- #
# Menú interactivo
# --------------------------------------------------------------------------- #
MENU = """\
[bold cyan]1[/bold cyan]) Reconocimiento pasivo      [dim](próximamente)[/dim]
[bold cyan]2[/bold cyan]) Descubrimiento activo      [dim](próximamente)[/dim]
[bold cyan]3[/bold cyan]) Enumeración de contenido   [green](gobuster)[/green]
[bold cyan]4[/bold cyan]) Salir\
"""


def interactive_menu(verbose: bool = False) -> int:
    while True:
        console.print(Panel(MENU, title="[bold]Menú principal[/bold]", border_style="cyan"))
        if verbose:
            console.print("[dim]— modo verbose activo (-v): los hallazgos se "
                          "muestran en vivo durante el escaneo —[/dim]")
        choice = Prompt.ask("Elegí una opción", choices=["1", "2", "3", "4"], default="3")

        if choice == "1":
            _coming_soon("Reconocimiento pasivo")
        elif choice == "2":
            _coming_soon("Descubrimiento activo")
        elif choice == "3":
            _interactive_enum(verbose=verbose)
        elif choice == "4":
            console.print("[dim]Hasta la próxima.[/dim]")
            return 0


def _coming_soon(name: str) -> None:
    console.print(
        Panel(
            f"[yellow]{name}[/yellow] todavía no está implementado.\n"
            f"[dim]Está en el roadmap para las próximas etapas de Belphegor.[/dim]",
            title="[bold]Próximamente[/bold]",
            border_style="yellow",
        )
    )
    console.print()


def _interactive_enum(verbose: bool = False) -> None:
    console.print()
    target = Prompt.ask("[bold]Objetivo[/bold] (dominio o URL)")
    if not target.strip():
        console.print("[red]Target vacío, cancelo.[/red]\n")
        return

    mode = Prompt.ask("Modo", choices=list(MODES), default="dir")

    # Selección de wordlist: por nivel (numerado) o ruta propia.
    level, wordlist = _ask_wordlist()

    threads_raw = Prompt.ask("Hilos", default=str(THREADS_DEFAULT))
    try:
        threads = int(threads_raw)
    except ValueError:
        threads = THREADS_DEFAULT
        console.print(f"[yellow]Valor inválido, uso {THREADS_DEFAULT} hilos.[/yellow]")

    delay = Prompt.ask("Delay entre requests [dim](Enter = ninguno)[/dim]", default="").strip() or None

    extensions = None
    if mode == "dir":
        extensions = Prompt.ask(
            "Extensiones [dim](ej php,html,bak — Enter = ninguna)[/dim]", default=""
        ).strip() or None

    protocol = None
    if mode != "dns":
        proto_raw = Prompt.ask(
            "Forzar protocolo", choices=["auto", "http", "https"], default="auto"
        )
        protocol = None if proto_raw == "auto" else proto_raw

    cfg = EnumConfig(
        target=target.strip(),
        mode=mode,
        wordlist=wordlist,
        level=level,
        threads=threads,
        delay=delay,
        extensions=extensions,
        force_scheme=protocol,
        verbose=verbose,
    )

    # Todas las pautas elegidas: limpio la consola y dejo solo el nombre
    # grande + este resumen del escaneo antes de arrancar gobuster.
    wl_desc = f"wordlist propia ({wordlist})" if wordlist else f"nivel [bold]{level}[/bold]"
    extras = "".join(
        part for part in (
            f" · delay {delay}" if delay else "",
            f" · ext {extensions}" if extensions else "",
            f" · proto {protocol}" if protocol else "",
            " · [green]verbose[/green]" if verbose else "",
        )
    )
    summary = (
        f"[bold cyan]Escaneo[/bold cyan] · gobuster [green]{mode}[/green] → "
        f"[bold]{target.strip()}[/bold]\n"
        f"[dim]{wl_desc} · {threads} hilos{extras}[/dim]"
    )
    banner.render_scan_header(summary)

    try:
        enum_gobuster.run(cfg, interactive=True)
    except (ToolMissingError, TargetError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
    console.print()


def _ask_wordlist() -> tuple[str, str | None]:
    """Pregunta nivel o wordlist propia. Devuelve (level, wordlist_or_None).

    Opciones:
      1) basic   2) full   3) deep   4) wordlist propia (ruta)

    Si elige propia, `level` queda en el default (se ignora al haber wordlist)
    y se devuelve la ruta. Si no, `wordlist` es None y manda el nivel.
    """
    console.print("\n[bold]Wordlist[/bold] — elegí un nivel o pasá la tuya:")
    for i, lvl in enumerate(LEVELS, 1):
        console.print(f"  [cyan]{i}[/cyan]) {lvl:6} [dim]— {LEVEL_DESC[lvl]}[/dim]")
    console.print(f"  [cyan]{len(LEVELS) + 1}[/cyan]) propia [dim]— pasar una ruta a mano[/dim]")

    choices = [str(i) for i in range(1, len(LEVELS) + 2)]
    pick = Prompt.ask("Opción", choices=choices, default="1")

    idx = int(pick)
    if idx <= len(LEVELS):
        return LEVELS[idx - 1], None

    # Opción "propia": pedir ruta.
    path = Prompt.ask("  Ruta a tu wordlist").strip()
    if not path:
        console.print("[yellow]No pasaste ruta, uso nivel basic.[/yellow]")
        return DEFAULT_LEVEL, None
    return DEFAULT_LEVEL, path


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    parser = build_parser()
    args = parser.parse_args(argv)

    # Modo CLI (scripteable): nada de banner ni chequeos de arranque, para no
    # ensuciar la salida de pipes / CI / redirecciones. ensure_tool ya valida
    # gobuster dentro del módulo cuando hace falta.
    if args.command == "enum":
        return run_enum_from_args(args)

    # Sin subcomando → menú interactivo: acá sí va el banner completo y el
    # chequeo de herramientas (avisa faltantes pero no corta).
    banner.render_banner()
    check_tools()
    console.print()
    try:
        return interactive_menu(verbose=args.verbose)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
