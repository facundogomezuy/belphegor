"""Belphegor — entry point.

Modo dual:
  - Sin argumentos → menú interactivo.
  - Con flags     → ejecuta el módulo directo (scripteable).
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.prompt import Confirm, Prompt

from . import banner, __version__
from .engines import ENGINES
from .preflight import check_tools, ToolMissingError, TargetError
from .modules import enumeration
from .modules.enumeration import (
    EnumConfig, MODES, THREADS_DEFAULT, LEVELS, DEFAULT_LEVEL, LEVEL_DESC,
)

console = Console()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="belphegor",
        description="Belphegor — enumeración de contenido / web fuzzing (bug bounty / pentest).",
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
        "-r", "--recursive", action="store_true",
        help="Recursar en los directorios encontrados (solo modo dir).",
    )
    enum.add_argument(
        "--depth", type=int, default=2,
        help="Profundidad máxima de recursión con -r (default 2).",
    )
    enum.add_argument(
        "--calibrate", action="store_true",
        help="Antes de escanear (modo dir), pegar a rutas random para detectar "
             "un catch-all/comodín y excluir su tamaño automáticamente.",
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

    # ---- chain (dns → vivos → dir) --------------------------------------- #
    chain = sub.add_parser(
        "chain",
        help="Encadenar: subdominios (dns) → hosts vivos → enumeración de directorios.",
    )
    chain.add_argument("domain", help="Dominio objetivo (ej: pepito.com).")
    chain.add_argument(
        "-L", "--level", choices=LEVELS, default=DEFAULT_LEVEL,
        help=f"Nivel de wordlist para ambas fases (default {DEFAULT_LEVEL}).",
    )
    chain.add_argument("--dns-wordlist", help="Wordlist propia para la fase dns.")
    chain.add_argument("--dir-wordlist", help="Wordlist propia para la fase dir.")
    chain.add_argument(
        "-t", "--threads", type=int, default=THREADS_DEFAULT,
        help=f"Hilos (default {THREADS_DEFAULT}).",
    )
    chain.add_argument(
        "--engine", choices=ENGINES, default="gobuster",
        help="Motor para la fase dir (dns siempre usa gobuster).",
    )
    chain.add_argument(
        "-r", "--recursive", action="store_true",
        help="Recursar en los directorios encontrados en cada host.",
    )
    chain.add_argument(
        "--depth", type=int, default=2,
        help="Profundidad máxima de recursión con -r (default 2).",
    )
    chain.add_argument(
        "--calibrate", action="store_true",
        help="Auto-calibrar comodín en cada host antes del dir scan.",
    )
    chain.add_argument("-x", "--extensions", help="Extensiones para la fase dir (php,html,bak).")
    chain.add_argument(
        "--max-hosts", type=int, default=25,
        help="Máximo de hosts vivos a fuzzear (control de scope, default 25).",
    )
    chain.add_argument("-o", "--output", help="Archivo donde guardar resultados.")
    chain.add_argument(
        "--format", choices=["txt", "json", "jsonl"], default="txt",
        help="Formato del archivo de salida (default txt).",
    )
    chain.add_argument(
        "--json", action="store_true",
        help="Emitir los hallazgos como JSONL por stdout (auto si no hay terminal).",
    )
    chain.add_argument(
        "--no-install", action="store_true",
        help="No ofrecer instalar herramientas faltantes (útil para scripts/CI).",
    )
    chain.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="Mostrar cada hallazgo en vivo durante los dir scans.",
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
        recursive=args.recursive,
        depth=args.depth,
        calibrate=args.calibrate,
        # JSONL por stdout si se pidió --json, o si stdout no es una terminal
        # (redirección / pipe): así la salida se integra a un pipeline sola.
        stdout_json=args.json or not sys.stdout.isatty(),
    )
    try:
        enumeration.run(cfg, interactive=False)
        return 0
    except (ToolMissingError, TargetError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        return 1


def run_chain_from_args(args: argparse.Namespace) -> int:
    from .modules import chain

    cfg = chain.ChainConfig(
        domain=args.domain,
        level=args.level,
        dns_wordlist=args.dns_wordlist,
        dir_wordlist=args.dir_wordlist,
        threads=args.threads,
        engine=args.engine,
        recursive=args.recursive,
        depth=args.depth,
        calibrate=args.calibrate,
        extensions=args.extensions,
        max_hosts=args.max_hosts,
        output=args.output,
        out_format=args.format,
        no_install=args.no_install,
        verbose=args.verbose,
        stdout_json=args.json or not sys.stdout.isatty(),
    )
    try:
        chain.run_chain(cfg, interactive=False)
        return 0
    except (ToolMissingError, TargetError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
        return 1


# --------------------------------------------------------------------------- #
# Modo interactivo
# --------------------------------------------------------------------------- #
def run_interactive(verbose: bool = False) -> int:
    """Modo interactivo: enumerar un target o encadenar un dominio."""
    if verbose:
        console.print("[dim]— modo verbose activo (-v): los hallazgos se muestran "
                      "en vivo durante el escaneo —[/dim]")
    console.print(
        "\n[bold]¿Qué querés hacer?[/bold]\n"
        "  [cyan]1[/cyan]) Enumerar un target (dir / vhost / dns)\n"
        "  [cyan]2[/cyan]) Encadenar un dominio [dim](subdominios → hosts vivos → dir)[/dim]"
    )
    if Prompt.ask("Opción", choices=["1", "2"], default="1") == "2":
        _interactive_chain(verbose=verbose)
    else:
        _interactive_enum(verbose=verbose)
    return 0


def _interactive_chain(verbose: bool = False) -> None:
    from .modules import chain

    console.print()
    domain = Prompt.ask("[bold]Dominio[/bold] (ej pepito.com)").strip()
    if not domain:
        console.print("[red]Dominio vacío, cancelo.[/red]\n")
        return

    console.print("\n[bold]Nivel de wordlist[/bold] (para las fases dns y dir):")
    for i, lvl in enumerate(LEVELS, 1):
        console.print(f"  [cyan]{i}[/cyan]) {lvl:6} [dim]— {LEVEL_DESC[lvl]}[/dim]")
    pick = Prompt.ask("Opción", choices=[str(i) for i in range(1, len(LEVELS) + 1)], default="1")
    level = LEVELS[int(pick) - 1]

    try:
        max_hosts = int(Prompt.ask("Máximo de hosts vivos a fuzzear", default="25").strip())
    except ValueError:
        max_hosts = 25

    try:
        depth = int(Prompt.ask(
            "Profundidad recursiva en dir [dim](0 = sin recursión)[/dim]", default="0"
        ).strip())
    except ValueError:
        depth = 0
    calibrate = Confirm.ask("¿Calibrar comodín en cada host? [dim](recomendado)[/dim]", default=True)

    cfg = chain.ChainConfig(
        domain=domain, level=level, threads=THREADS_DEFAULT,
        recursive=depth > 0, depth=depth if depth > 0 else 2,
        calibrate=calibrate, max_hosts=max_hosts, verbose=verbose,
    )
    console.print()
    try:
        chain.run_chain(cfg, interactive=True)
    except (ToolMissingError, TargetError) as exc:
        console.print(f"[bold red][!] {exc}[/bold red]")
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
    recursive = False
    depth = 2
    calibrate = False
    if mode == "dir":
        extensions = Prompt.ask(
            "Extensiones [dim](ej php,html,bak — Enter = ninguna)[/dim]", default=""
        ).strip() or None
        depth_raw = Prompt.ask(
            "Profundidad recursiva [dim](0 = sin recursión)[/dim]", default="0"
        ).strip()
        try:
            depth = int(depth_raw)
        except ValueError:
            depth = 0
        recursive = depth > 0
        calibrate = Confirm.ask(
            "¿Calibrar comodín antes de escanear? [dim](recomendado)[/dim]", default=True
        )

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
        recursive=recursive,
        depth=depth if depth > 0 else 2,
        calibrate=calibrate,
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
            f" · [magenta]recursivo (depth {depth})[/magenta]" if recursive else "",
            " · [blue]calibrar[/blue]" if calibrate else "",
        )
    )
    summary = (
        f"[bold cyan]Escaneo[/bold cyan] · gobuster [green]{mode}[/green] → "
        f"[bold]{target.strip()}[/bold]\n"
        f"[dim]{wl_desc} · {threads} hilos{extras}[/dim]"
    )
    banner.render_scan_header(summary)

    try:
        enumeration.run(cfg, interactive=True)
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
    if args.command == "chain":
        return run_chain_from_args(args)

    # Sin subcomando → menú interactivo: acá sí va el banner completo y el
    # chequeo de herramientas (avisa faltantes pero no corta).
    banner.render_banner()
    check_tools()
    console.print()
    try:
        return run_interactive(verbose=args.verbose)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrumpido.[/dim]")
        return 130
    except EOFError:
        # Sin más input (Ctrl+D o stdin agotado): salida limpia, no traceback.
        console.print("\n[dim]Entrada terminada, salgo.[/dim]")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
