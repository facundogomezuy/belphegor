"""Módulo de enumeración de contenido: wrapper de gobuster (dir/vhost/dns).

Flujo:
  1. Preflight del target (resolución DNS + autodetección de protocolo) — salvo
     en modo dns, donde gobuster trabaja sobre el dominio pelado y no necesita
     esquema http/https.
  2. Resolución de la wordlist (default según modo, o la que pase el usuario).
  3. Armado del comando gobuster.
  4. Ejecución con streaming de stdout en tiempo real y manejo limpio de Ctrl+C.
  5. Parseo de resultados + tabla rich + guardado opcional.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from ..preflight import Target, build_target, ensure_tool, TargetError
from ..utils import (
    is_wildcard_precheck_error,
    parse_gobuster_line,
    render_results,
    save_results,
)

console = Console()

MODES = ("dir", "vhost", "dns")

LEVELS = ("basic", "full", "deep")
DEFAULT_LEVEL = "basic"

# Wordlists por (modo, nivel). Cada entrada es una LISTA de rutas candidatas:
# los nombres/ubicaciones de SecLists varían entre Kali y BlackArch, así que
# probamos en orden y usamos la primera que exista. Si ninguna está, se avisa
# y se sugiere pasar -w con una wordlist propia.
#
# Niveles:
#   basic → barrido rápido, primer vistazo (listas chicas)
#   full  → cobertura media, lo más usado en bug bounty
#   deep  → exhaustivo/agresivo (listas grandes, tarda y hace ruido)
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

# Descripciones legibles de cada nivel, para el menú interactivo.
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
    force_scheme: Optional[str] = None    # --protocol http|https
    output: Optional[str] = None
    out_format: str = "txt"
    no_install: bool = False              # --no-install: no ofrecer auto-instalar
    _resolved_target: Optional[Target] = field(default=None, repr=False)


def find_existing_wordlist(candidates: list[str]) -> Optional[str]:
    """Devuelve la primera ruta candidata que exista como archivo, o None."""
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def resolve_wordlist(cfg: EnumConfig) -> str:
    """Devuelve la wordlist a usar, validando que exista.

    Precedencia:
      1. -w del usuario (si la pasó) → gana siempre, se ignora el nivel.
      2. Nivel (basic/full/deep) → busca entre las rutas candidatas del modo
         la primera que exista.

    Raises:
        TargetError: si no hay wordlist utilizable.
    """
    # 1. Wordlist propia: prioridad absoluta.
    if cfg.wordlist:
        if not os.path.isfile(cfg.wordlist):
            raise TargetError(f"la wordlist «{cfg.wordlist}» no existe.")
        return cfg.wordlist

    # 2. Preset por nivel: probar rutas candidatas.
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


def build_command(cfg: EnumConfig, wordlist: str) -> list[str]:
    """Arma la lista de argumentos para subprocess según el modo."""
    cmd: list[str] = ["gobuster", cfg.mode]

    if cfg.mode == "dir":
        tgt = cfg._resolved_target
        assert tgt is not None
        cmd += ["-u", tgt.url]
    elif cfg.mode == "vhost":
        tgt = cfg._resolved_target
        assert tgt is not None
        cmd += ["-u", tgt.url, "--append-domain"]
    else:  # dns
        cmd += ["-d", _dns_domain(cfg)]

    cmd += ["-w", wordlist, "-t", str(cfg.threads)]

    if cfg.delay:
        cmd += ["--delay", cfg.delay]
    if cfg.mode == "dir" and cfg.extensions:
        cmd += ["-x", cfg.extensions]
    if cfg.status_include:
        cmd += ["-s", cfg.status_include]
    if cfg.status_exclude:
        cmd += ["-b", cfg.status_exclude]

    # Salida sin colores ANSI de gobuster para que nuestro parseo sea limpio.
    cmd += ["--no-color"]
    return cmd


def _dns_domain(cfg: EnumConfig) -> str:
    """En modo dns usamos el host pelado (sin esquema)."""
    if cfg._resolved_target is not None:
        return cfg._resolved_target.host
    # Fallback defensivo: limpiar esquema si vino.
    return cfg.target.replace("https://", "").replace("http://", "").strip("/")


def _preflight(cfg: EnumConfig) -> None:
    """Corre el preflight del target y lo cachea en la config.

    En modo dns no necesitamos esquema http/https, pero igual resolvemos el
    host para dar feedback temprano si el dominio no existe.
    """
    tgt = build_target(cfg.target, force_scheme=cfg.force_scheme)
    cfg._resolved_target = tgt

    detail = f"[bold]{tgt.host}[/bold] → {tgt.ip}"
    if cfg.mode != "dns":
        detail += f"  ·  esquema: [cyan]{tgt.scheme}[/cyan]"
    console.print(
        Panel(detail, title="[green]Preflight OK[/green]", border_style="green")
    )


def run(cfg: EnumConfig, interactive: bool = False) -> list[dict]:
    """Ejecuta el módulo completo. Devuelve la lista de hallazgos parseados.

    Args:
        cfg:         configuración de la corrida.
        interactive: si True y no se especificó output, pregunta al final si
                     quiere guardar y a dónde.
    """
    if cfg.mode not in MODES:
        raise TargetError(f"modo inválido: «{cfg.mode}» (usá dir / vhost / dns).")
    if cfg.level not in LEVELS:
        raise TargetError(f"nivel inválido: «{cfg.level}» (usá basic / full / deep).")

    # 1. La herramienta tiene que estar sí o sí antes de seguir. Si falta,
    #    ensure_tool ofrece instalarla (salvo --no-install) antes de cortar.
    ensure_tool("gobuster", no_install=cfg.no_install)

    # 2. Preflight del target.
    _preflight(cfg)

    # 3. Wordlist (por -w propia, o resuelta desde el nivel).
    wordlist = resolve_wordlist(cfg)
    origin = "propia" if cfg.wordlist else f"nivel {cfg.level}"
    console.print(f"[dim]Wordlist ({origin}): {wordlist}[/dim]")

    # 4. Aviso por hilos altos (no corta).
    if cfg.threads > THREADS_WARN_ABOVE:
        console.print(
            f"[bold yellow]⚠️  {cfg.threads} hilos es agresivo[/bold yellow] "
            f"[yellow]— asegurate que el scope del programa de bug bounty lo "
            f"permita antes de martillar el target.[/yellow]"
        )

    cmd = build_command(cfg, wordlist)
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")

    results = _stream_gobuster(cmd, cfg.mode)

    console.print()
    render_results(results, title=f"gobuster {cfg.mode} — {cfg.target}")

    # 5. Guardado.
    _handle_output(cfg, results, interactive, wordlist)

    return results


def _stream_gobuster(cmd: list[str], mode: str) -> list[dict]:
    """Corre gobuster capturando stdout en tiempo real.

    Imprime cada línea a medida que llega y maneja Ctrl+C matando el subprocess
    para no dejar procesos colgados.
    """
    results: list[dict] = []
    fatal_line: Optional[str] = None
    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # line-buffered
            # Grupo de proceso propio para poder matar todo el árbol con la señal.
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if is_wildcard_precheck_error(line):
                # gobuster aborta: el target devuelve el mismo status/tamaño
                # para una URL inexistente (catch-all 403, WAF, vhost
                # comodín...). No es un hallazgo, es el motivo del fracaso.
                fatal_line = line.strip()
                console.print(f"  [bold red]![/bold red] {line}")
                continue
            parsed = parse_gobuster_line(line, mode)
            if parsed is not None:
                results.append(parsed)
                console.print(f"  [green]›[/green] {line}")
            else:
                # Línea de infra/progreso: la mostramos tenue para dar señal de vida.
                console.print(f"  [dim]{line}[/dim]")
        proc.wait()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Ctrl+C — cortando gobuster…[/bold yellow]")
        _kill(proc)
        console.print("[yellow][*] Proceso terminado. Resultados parciales abajo.[/yellow]")
    except FileNotFoundError:
        # Por las dudas, aunque ensure_tool ya debería haberlo agarrado.
        raise TargetError("gobuster no se pudo ejecutar (¿está en el PATH?).")
    finally:
        _kill(proc)

    if fatal_line is not None:
        raise TargetError(
            "el target devuelve el mismo status/tamaño para una URL "
            "inexistente al azar (típico de un catch-all 403, un WAF, o un "
            "vhost comodín) — gobuster abortó el precheck de wildcard antes "
            "de escanear en serio.\n"
            f"    Detalle de gobuster: {fatal_line}\n"
            "    Probá:\n"
            "      - excluir ese status con -b/--status-exclude (ej: 403,404)\n"
            "      - confirmar a mano con curl si es un WAF o el 403 es real"
        )

    returncode = proc.returncode if proc is not None else None
    if returncode not in (0, None) and not results:
        console.print(
            f"[yellow][~] gobuster terminó con código {returncode} y no hubo "
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


def _handle_output(cfg: EnumConfig, results: list[dict], interactive: bool,
                   wordlist: str) -> None:
    """Guarda resultados según flags o, en modo interactivo, preguntando."""
    meta = {
        "target": cfg.target,
        "mode": cfg.mode,
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
            fmt = Prompt.ask(
                "  Formato", choices=["txt", "json"], default="txt"
            )
            save_results(results, path, fmt, meta)
