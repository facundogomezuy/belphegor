"""Módulo de enumeración de contenido (dir/vhost/dns).

Orquesta un motor de escaneo (backend) intercambiable — hoy gobuster, mañana
ffuf — a través de la interfaz `Scanner` (ver engines.py). Este módulo es
agnóstico del motor: resuelve el target y la wordlist, le pide al Scanner el
comando y el parseo, y trabaja siempre con `Finding`.

Flujo:
  1. Elegir motor + verificar su herramienta externa.
  2. Preflight del target (DNS + autodetección de esquema; dns no necesita esquema).
  3. Resolver la wordlist (default por nivel, o la propia del usuario).
  4. Ejecutar con streaming (spinner) y manejo limpio de Ctrl+C.
  5. Detección de comodín + presentación: tabla (stdout) o JSONL (stdout,
     modo --json), con todo el diagnóstico por stderr.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .._console import err
from ..engines import Scanner, get_scanner
from ..models import Finding
from ..preflight import Target, build_target, ensure_tool, TargetError
from ..utils import (
    iter_jsonl,
    mark_interesting,
    render_results,
    save_results,
    split_wildcard_noise,
)

MODES = ("dir", "vhost", "dns")

LEVELS = ("basic", "full", "deep")
DEFAULT_LEVEL = "basic"

# Wordlists por (modo, nivel): lista de rutas candidatas, se usa la primera que
# exista (SecLists varía entre Kali y BlackArch).
WORDLISTS: dict[str, dict[str, list[str]]] = {
    "dir": {
        "basic": [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "full": [
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        ],
        "deep": [
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        ],
    },
    "dns": {
        "basic": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "full": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "deep": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        ],
    },
    "vhost": {
        "basic": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "full": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        "deep": [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
            "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        ],
    },
}

LEVEL_DESC = {
    "basic": "rápido, primer vistazo (lista chica)",
    "full": "cobertura media, lo más usado en bug bounty",
    "deep": "exhaustivo y agresivo (lista grande, tarda y hace ruido)",
}

THREADS_DEFAULT = 10
THREADS_WARN_ABOVE = 50


@dataclass
class EnumConfig:
    """Configuración de una corrida de enumeración."""

    target: str
    mode: str
    wordlist: Optional[str] = None        # -w: wordlist propia; tiene prioridad
    level: str = DEFAULT_LEVEL            # -L: preset basic/full/deep
    threads: int = THREADS_DEFAULT
    delay: Optional[str] = None          # ej "50ms", pasa directo a --delay
    extensions: Optional[str] = None     # solo modo dir, ej "php,html,bak"
    status_include: Optional[str] = None  # gobuster -s
    status_exclude: Optional[str] = None  # gobuster -b
    exclude_length: Optional[str] = None  # gobuster --exclude-length
    force_scheme: Optional[str] = None    # --protocol http|https
    output: Optional[str] = None
    out_format: str = "txt"
    no_install: bool = False              # --no-install: no ofrecer auto-instalar
    auto_filter: bool = False             # --auto-filter: re-correr si hay comodín
    verbose: bool = False                 # -v: imprimir cada hallazgo en vivo (CTF)
    engine: str = "gobuster"             # --engine: motor de escaneo
    stdout_json: bool = False            # emitir JSONL por stdout (pipe / --json)
    recursive: bool = False               # -r: recursar en directorios (solo dir)
    depth: int = 2                        # --depth: profundidad máxima de recursión
    calibrate: bool = False               # --calibrate: auto-detectar comodín antes
    _resolved_target: Optional[Target] = field(default=None, repr=False)


# --------------------------------------------------------------------------- #
# Wordlists
# --------------------------------------------------------------------------- #
def find_existing_wordlist(candidates: list[str]) -> Optional[str]:
    """Devuelve la primera ruta candidata que exista como archivo, o None."""
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def resolve_wordlist(cfg: EnumConfig) -> str:
    """Devuelve la wordlist a usar, validando que exista.

    Precedencia: -w del usuario > preset por nivel. Raises TargetError si no hay
    ninguna utilizable.
    """
    if cfg.wordlist:
        if not os.path.isfile(cfg.wordlist):
            raise TargetError(f"la wordlist «{cfg.wordlist}» no existe.")
        return cfg.wordlist

    candidates = WORDLISTS[cfg.mode][cfg.level]
    found = find_existing_wordlist(candidates)
    if found is not None:
        return found

    tried = "\n".join(f"      - {p}" for p in candidates)
    raise TargetError(
        f"no encontré una wordlist para modo {cfg.mode} nivel «{cfg.level}».\n"
        f"    Busqué en:\n{tried}\n"
        f"    Instalá SecLists (apt install seclists) o pasá una propia con "
        f"-w /ruta/a/wordlist.txt"
    )


def count_wordlist_lines(path: str) -> int:
    """Cuenta las líneas no vacías de la wordlist (solo informativo)."""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return sum(1 for line in fh if line.strip())


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #
def _preflight(cfg: EnumConfig) -> None:
    """Resuelve el target y lo cachea en la config (diagnóstico → stderr)."""
    tgt = build_target(cfg.target, force_scheme=cfg.force_scheme)
    cfg._resolved_target = tgt

    detail = f"[bold]{tgt.host}[/bold] → {tgt.ip}"
    if cfg.mode != "dns":
        detail += f"  ·  esquema: [cyan]{tgt.scheme}[/cyan]"
    err.print(Panel(detail, title="[green]Preflight OK[/green]", border_style="green"))


def _calibrate(cfg: EnumConfig) -> None:
    """Auto-calibra el comodín y, si lo detecta, setea exclude_length de entrada."""
    from ..preflight import calibrate_wildcard

    err.print("[dim]Calibrando comodín (rutas random)…[/dim]")
    assert cfg._resolved_target is not None
    baseline = calibrate_wildcard(cfg._resolved_target.url)
    if baseline is not None:
        cfg.exclude_length = baseline["size"]
        err.print(
            f"[yellow][~][/yellow] Calibración: el server responde igual a rutas "
            f"inexistentes (status {baseline['status']} · size {baseline['size']}) — "
            f"excluyo ese tamaño de entrada (--exclude-length {baseline['size']})."
        )
    else:
        err.print("[dim]Calibración: sin comodín evidente.[/dim]")


# --------------------------------------------------------------------------- #
# Corrida principal
# --------------------------------------------------------------------------- #
def run(cfg: EnumConfig, interactive: bool = False) -> list[Finding]:
    """Ejecuta el módulo completo. Devuelve la lista de hallazgos."""
    if cfg.mode not in MODES:
        raise TargetError(f"modo inválido: «{cfg.mode}» (usá dir / vhost / dns).")
    if cfg.level not in LEVELS:
        raise TargetError(f"nivel inválido: «{cfg.level}» (usá basic / full / deep).")
    try:
        scanner = get_scanner(cfg.engine)
    except ValueError as exc:
        raise TargetError(str(exc))

    # 1. La herramienta del motor tiene que estar. Si falta, ensure_tool ofrece
    #    instalarla (salvo --no-install) antes de cortar.
    ensure_tool(scanner.tool, no_install=cfg.no_install)

    # 2. Preflight del target.
    _preflight(cfg)

    # 3. Wordlist.
    wordlist = resolve_wordlist(cfg)
    origin = "propia" if cfg.wordlist else f"nivel {cfg.level}"
    total_words = count_wordlist_lines(wordlist)
    err.print(f"[dim]Wordlist ({origin}): {wordlist} — {total_words} rutas[/dim]")

    # 4. Aviso por hilos altos (no corta).
    if cfg.threads > THREADS_WARN_ABOVE:
        err.print(
            f"[bold yellow]⚠️  {cfg.threads} hilos es agresivo[/bold yellow] "
            f"[yellow]— asegurate que el scope del programa lo permita antes de "
            f"martillar el target.[/yellow]"
        )

    # 4.5. Auto-calibración de comodín (opcional, solo dir): si el server
    #      responde igual a rutas random, excluimos ese tamaño de entrada.
    if cfg.calibrate and cfg.mode == "dir" and not cfg.exclude_length:
        _calibrate(cfg)

    # 5. Ejecución: recursiva (solo dir) o de una pasada.
    cmd: Optional[list[str]] = None
    if cfg.recursive and cfg.mode == "dir":
        results = _run_recursive(scanner, cfg, wordlist)
        recursive_run = True
    else:
        if cfg.recursive:
            err.print("[yellow][~] --recursive solo aplica en modo dir; lo ignoro.[/yellow]")
        cmd = scanner.build_command(cfg, wordlist)
        err.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")
        results = _stream_scan(scanner, cmd, cfg.mode, verbose=cfg.verbose)
        recursive_run = False

    # 6. Marcar hallazgos jugosos (Fase 5: inteligencia sobre resultados).
    mark_interesting(results)

    # 7. Presentación + manejo de comodín.
    if cfg.stdout_json:
        _, _, wildcard = split_wildcard_noise(results)
        if wildcard is not None and cfg.auto_filter and not recursive_run:
            results = _rerun_filtered(scanner, cfg, cmd, wildcard)
            mark_interesting(results)
            _, _, wildcard = split_wildcard_noise(results)
        _emit_jsonl(results)
        if wildcard is not None:
            _warn_wildcard(wildcard, cmd)
    else:
        err.print()
        _, _, wildcard = render_results(results, title="Hallazgos")
        if wildcard is not None and not recursive_run:
            results = _handle_wildcard_filter(scanner, cfg, cmd, results, wildcard, interactive)
        elif wildcard is not None:
            _warn_wildcard(wildcard, None)

    # 8. Guardado a archivo (si corresponde).
    _handle_output(cfg, results, interactive, wordlist)

    return results


def _emit_jsonl(results: list[Finding]) -> None:
    """Escribe los hallazgos como JSONL en stdout (para pipear)."""
    for linea in iter_jsonl(results):
        sys.stdout.write(linea + "\n")
    sys.stdout.flush()


def _warn_wildcard(wildcard: dict, cmd: Optional[list[str]]) -> None:
    """Aviso de comodín por stderr (no ensucia el JSONL de stdout)."""
    pct = round(wildcard["fraction"] * 100)
    base = (
        f"[yellow][~][/yellow] Probable comodín: {wildcard['count']} resultados con "
        f"status {wildcard['status']} · size {wildcard['size']} ({pct}%)."
    )
    if cmd is not None:
        sugerencia = " ".join(cmd + ["--exclude-length", str(wildcard["size"])])
        base += f" Filtralos con: [bold]{sugerencia}[/bold] [dim](o --auto-filter)[/dim]"
    else:
        base += (
            f" Volvé a correr con [bold]--exclude-length {wildcard['size']}[/bold] "
            f"[dim](o --auto-filter)[/dim] para filtrarlos."
        )
    err.print(base)


def _rerun_filtered(
    scanner: Scanner, cfg: EnumConfig, cmd: list[str], wildcard: dict
) -> list[Finding]:
    """Re-corre excluyendo el size del comodín (diagnóstico → stderr)."""
    pct = round(wildcard["fraction"] * 100)
    refiltered = cmd + ["--exclude-length", str(wildcard["size"])]
    err.print(
        f"[yellow][~][/yellow] comodín detectado (status {wildcard['status']} · "
        f"size {wildcard['size']}, {pct}%) — re-corriendo con --auto-filter."
    )
    err.print(f"[dim]$ {' '.join(refiltered)}[/dim]\n")
    return _stream_scan(scanner, refiltered, cfg.mode, verbose=cfg.verbose)


def _handle_wildcard_filter(
    scanner: Scanner,
    cfg: EnumConfig,
    cmd: list[str],
    results: list[Finding],
    wildcard: dict,
    interactive: bool,
) -> list[Finding]:
    """Sugiere u ofrece re-correr excluyendo el size del comodín (modo humano)."""
    pct = round(wildcard["fraction"] * 100)
    refiltered = cmd + ["--exclude-length", str(wildcard["size"])]
    suggestion = " ".join(refiltered)

    def _rerun() -> list[Finding]:
        err.print(f"[dim]$ {suggestion}[/dim]\n")
        new_results = _stream_scan(scanner, refiltered, cfg.mode, verbose=cfg.verbose)
        err.print()
        render_results(new_results, title="Hallazgos (filtrado)")
        return new_results

    if interactive:
        from rich.prompt import Confirm

        ask = (
            f"\n¿Volver a correr excluyendo status {wildcard['status']} · size "
            f"{wildcard['size']} ({wildcard['count']} resultados, {pct}%) con "
            f"--exclude-length {wildcard['size']}?"
        )
        if Confirm.ask(ask, default=False):
            return _rerun()
        return results

    if cfg.auto_filter:
        err.print(
            f"[yellow][~][/yellow] comodín detectado (status {wildcard['status']} · "
            f"size {wildcard['size']}, {pct}%) — re-corriendo con --auto-filter."
        )
        return _rerun()

    err.print(
        f"[yellow][~][/yellow] Probable comodín: {wildcard['count']} resultados con "
        f"status {wildcard['status']} · size {wildcard['size']} ({pct}%). "
        f"Para filtrarlos, volvé a correr con:\n"
        f"    [bold]{suggestion}[/bold]\n"
        f"    [dim](o pasá --auto-filter para que belphegor lo haga solo)[/dim]"
    )
    return results


# --------------------------------------------------------------------------- #
# Recursión (modo dir)
# --------------------------------------------------------------------------- #
# Tope duro de escaneos para que la recursión no explote en un target grande.
RECURSION_MAX_SCANS = 60


def _looks_like_dir(f: Finding) -> bool:
    """True si el hallazgo parece un directorio en el que vale la pena entrar.

    - Si conocemos el destino del redirect (gobuster): es dir si termina en '/'
      (un 301 a /index.php, por ejemplo, NO es dir).
    - Si no lo conocemos (ffuf no lo expone): un 301/302 hacia una ruta sin
      extensión es casi siempre un directorio sin la barra final; un 200 sin
      extensión también.
    No recursamos en 401/403 (suelen bloquear) para no gastar escaneos al pedo.
    """
    last = f.path.rstrip("/").rsplit("/", 1)[-1]
    has_ext = "." in last

    if f.redirect:
        return f.redirect.rstrip().endswith("/")
    if f.status in ("301", "302") and last != "" and not has_ext:
        return True
    if f.status == "200" and last != "" and not has_ext:
        return True
    return False


def _full_path(base_url: str, rel_path: str) -> str:
    """Ruta absoluta desde el host: base_path + rel_path (para el output agregado)."""
    base_path = urlsplit(base_url).path.rstrip("/")
    rel = rel_path if rel_path.startswith("/") else "/" + rel_path
    return base_path + rel


def _child_base(base_url: str, full_path: str) -> str:
    """URL base para escanear dentro de `full_path`."""
    parts = urlsplit(base_url)
    return urlunsplit((parts.scheme, parts.netloc, full_path.rstrip("/") + "/", "", ""))


def _norm_base(url: str) -> str:
    return url.rstrip("/")


def _run_recursive(scanner: Scanner, cfg: EnumConfig, wordlist: str) -> list[Finding]:
    """Escanea en anchura (BFS): cada directorio encontrado se vuelve a escanear.

    Reescribe el path de cada hallazgo a su ruta absoluta desde el host, deduplica
    por ruta, respeta `cfg.depth` y corta en RECURSION_MAX_SCANS.
    """
    root = cfg._resolved_target.url  # type: ignore[union-attr]
    queue: list[tuple[str, int]] = [(root, 0)]
    seen_bases = {_norm_base(root)}
    seen_paths: set[str] = set()
    findings: list[Finding] = []
    scans = 0

    while queue:
        if scans >= RECURSION_MAX_SCANS:
            err.print(
                f"[yellow][~] tope de recursión ({RECURSION_MAX_SCANS} escaneos) "
                f"alcanzado — corto acá.[/yellow]"
            )
            break
        base, depth = queue.pop(0)
        scans += 1
        shown = urlsplit(base).path or "/"
        err.print(f"[cyan]▸[/cyan] escaneando [bold]{shown}[/bold] [dim](depth {depth})[/dim]")

        cmd = scanner.build_command(cfg, wordlist, base_url=base)
        batch = _stream_scan(scanner, cmd, cfg.mode, verbose=cfg.verbose)

        for f in batch:
            f.path = _full_path(base, f.path)
            if f.path in seen_paths:
                continue
            seen_paths.add(f.path)
            findings.append(f)
            if depth < cfg.depth and _looks_like_dir(f):
                child = _child_base(base, f.path)
                if _norm_base(child) not in seen_bases:
                    seen_bases.add(_norm_base(child))
                    queue.append((child, depth + 1))

    err.print(f"[dim]Recursión: {scans} escaneos, {len(findings)} hallazgos únicos.[/dim]")
    return findings


# --------------------------------------------------------------------------- #
# Streaming del subprocess
# --------------------------------------------------------------------------- #
def _format_hit(f: Finding) -> str:
    """Formatea un hallazgo para imprimirlo en vivo (modo verbose)."""
    parts = [f"  [green]›[/green] [cyan]{f.path or f.raw}[/cyan]"]
    if f.status:
        parts.append(f"[{_status_color(f.status)}]{f.status}[/{_status_color(f.status)}]")
    if f.size:
        parts.append(f"[dim]{f.size}b[/dim]")
    return "  ".join(parts)


def _status_color(status: str) -> str:
    from ..utils import _status_style
    return _status_style(status)


def _stream_scan(
    scanner: Scanner, cmd: list[str], mode: str, verbose: bool = False
) -> list[Finding]:
    """Corre el motor leyendo stdout, con spinner (todo el ruido va a stderr).

    Los hallazgos se acumulan y van a la tabla/JSONL final. Con verbose además
    se imprimen en vivo (por stderr, para no ensuciar un JSONL en stdout). Ctrl+C
    mata el subprocess para no dejar procesos colgados.
    """
    results: list[Finding] = []
    fatal_line: Optional[str] = None
    proc: Optional[subprocess.Popen] = None
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if scanner.merge_stderr else subprocess.DEVNULL,
            text=True,
            bufsize=1,  # line-buffered
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        assert proc.stdout is not None
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Escaneando…[/cyan]"),
            TextColumn("[green]{task.fields[hits]}[/green] posibles hallazgos"),
            TimeElapsedColumn(),
            console=err,
            transient=True,
        ) as progress:
            task = progress.add_task("scan", hits=0)
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                if scanner.is_fatal_precheck(line):
                    fatal_line = line.strip()
                    progress.console.print(f"  [bold red]![/bold red] {line}")
                    continue
                parsed = scanner.parse_line(line, mode)
                if parsed is not None:
                    results.append(parsed)
                    progress.update(task, hits=len(results))
                    if verbose:
                        progress.console.print(_format_hit(parsed))
        proc.wait()
    except KeyboardInterrupt:
        err.print("\n[bold yellow][!] Ctrl+C — cortando el escaneo…[/bold yellow]")
        _kill(proc)
        err.print("[yellow][*] Proceso terminado. Resultados parciales abajo.[/yellow]")
    except FileNotFoundError:
        raise TargetError(f"{cmd[0]} no se pudo ejecutar (¿está en el PATH?).")
    finally:
        _kill(proc)

    if fatal_line is not None:
        raise TargetError(
            "el target devuelve el mismo status/tamaño para una URL inexistente "
            "al azar (típico de un catch-all 403, un WAF, o un vhost comodín) — "
            "el motor abortó el precheck de wildcard antes de escanear en serio.\n"
            f"    Detalle: {fatal_line}\n"
            "    Probá:\n"
            "      - excluir ese status con -b/--status-exclude (ej: 403,404)\n"
            "      - confirmar a mano con curl si es un WAF o el 403 es real"
        )

    elapsed = time.monotonic() - start
    err.print(f"[dim]Listo en {elapsed:.1f}s — {len(results)} posibles hallazgos.[/dim]")

    returncode = proc.returncode if proc is not None else None
    if returncode not in (0, None) and not results:
        err.print(
            f"[yellow][~] el motor terminó con código {returncode} y no hubo "
            f"hallazgos parseables — revisá el output de arriba.[/yellow]"
        )

    return results


def _kill(proc: Optional[subprocess.Popen]) -> None:
    """Mata el subprocess (y su grupo) si sigue vivo."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=5)
    except (ProcessLookupError, PermissionError):
        pass
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError):
            pass


# --------------------------------------------------------------------------- #
# Guardado a archivo
# --------------------------------------------------------------------------- #
def _handle_output(cfg: EnumConfig, results: list[Finding], interactive: bool,
                   wordlist: str) -> None:
    """Guarda resultados según flags o, en modo interactivo, preguntando."""
    meta = {
        "target": cfg.target,
        "mode": cfg.mode,
        "engine": cfg.engine,
        "level": cfg.level if not cfg.wordlist else "custom",
        "wordlist": wordlist,
        "threads": cfg.threads,
    }
    if cfg._resolved_target is not None:
        meta["resolved_ip"] = cfg._resolved_target.ip
        if cfg.mode != "dns":
            meta["scheme"] = cfg._resolved_target.scheme

    if cfg.output:
        save_results(results, cfg.output, cfg.out_format, meta)
        return

    if interactive and results:
        from rich.prompt import Confirm, Prompt

        if Confirm.ask("\n¿Guardar resultados en un archivo?", default=False):
            path = Prompt.ask("  Archivo de salida", default="belphegor_out.txt")
            fmt = Prompt.ask("  Formato", choices=["txt", "json", "jsonl"], default="txt")
            save_results(results, path, fmt, meta)
