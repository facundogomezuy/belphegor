"""Encadenamiento: subdominios (dns) → hosts vivos → enumeración de directorios.

Orquesta piezas que ya existen, sin reimplementar nada:
  1. un escaneo dns para descubrir subdominios del dominio,
  2. un probe HTTP para quedarse solo con los que están vivos (con tope de scope),
  3. un dir scan sobre cada host vivo.

Es "content discovery" de punta a punta, dentro del mismo dominio de la
herramienta (no es recon de otro tipo). Todo el diagnóstico va a stderr; el
resultado (tabla o JSONL) a stdout.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

from .._console import err
from ..models import Finding
from ..preflight import TargetError, probe_alive
from ..utils import iter_jsonl, mark_interesting, print_results_table, save_results
from . import enumeration as enum


@dataclass
class ChainConfig:
    """Configuración de una corrida de encadenamiento."""

    domain: str
    level: str = enum.DEFAULT_LEVEL
    dns_wordlist: Optional[str] = None    # override wordlist de la fase dns
    dir_wordlist: Optional[str] = None    # override wordlist de la fase dir
    threads: int = enum.THREADS_DEFAULT
    engine: str = "gobuster"              # motor de la fase dir (dns siempre gobuster)
    recursive: bool = False
    depth: int = 2
    calibrate: bool = False
    extensions: Optional[str] = None
    max_hosts: int = 25                   # tope de scope: hosts vivos a fuzzear
    output: Optional[str] = None
    out_format: str = "txt"
    no_install: bool = False
    stdout_json: bool = False
    verbose: bool = False


def _subdomains(findings: list[Finding], domain: str) -> list[str]:
    """Saca los FQDN de subdominios de los hallazgos dns, deduplicados y en orden."""
    subs: list[str] = []
    seen: set[str] = set()
    for f in findings:
        host = f.path.strip().rstrip(".")
        if not host:
            continue
        if not host.endswith(domain):
            host = f"{host}.{domain}"
        if host in seen:
            continue
        seen.add(host)
        subs.append(host)
    return subs


def run_chain(cfg: ChainConfig, interactive: bool = False) -> list[Finding]:
    """Corre el pipeline dns → vivos → dir y devuelve los hallazgos agregados."""
    # --- Fase 1: subdominios por DNS -------------------------------------- #
    err.print(f"[bold cyan]▸ Fase 1[/bold cyan] — subdominios de [bold]{cfg.domain}[/bold] (dns)")
    dns_cfg = enum.EnumConfig(
        target=cfg.domain, mode="dns", wordlist=cfg.dns_wordlist, level=cfg.level,
        threads=cfg.threads, engine="gobuster",  # ffuf no hace fuerza bruta de DNS
        no_install=cfg.no_install, verbose=cfg.verbose,
    )
    try:
        dns_findings = enum.scan(dns_cfg).findings
    except TargetError as exc:
        err.print(f"[yellow][~] no pude enumerar subdominios: {exc}[/yellow]")
        dns_findings = []
    subs = _subdomains(dns_findings, cfg.domain)
    err.print(f"[dim]  {len(subs)} subdominios encontrados.[/dim]")

    # --- Fase 2: cuáles están vivos (incluye el dominio raíz) ------------- #
    # Se prueba en paralelo: con muchos subdominios, hacerlo en serie (cada probe
    # con su timeout) sería carísimo. Se preserva el orden de los candidatos y se
    # corta al llegar a --max-hosts vivos.
    err.print("[bold cyan]▸ Fase 2[/bold cyan] — probando cuáles están vivos (HTTP)")
    candidates: list[str] = []
    seen_hosts: set[str] = set()
    for host in [cfg.domain] + subs:
        if host not in seen_hosts:
            seen_hosts.add(host)
            candidates.append(host)

    alive = []
    workers = max(1, min(cfg.threads, len(candidates)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, tgt in zip(candidates, pool.map(probe_alive, candidates)):
            if tgt is not None:
                alive.append(tgt)
                err.print(f"  [green]✓[/green] {tgt.scheme}://{host}")
                if len(alive) >= cfg.max_hosts:
                    err.print(
                        f"[yellow][~] tope de {cfg.max_hosts} hosts vivos alcanzado "
                        f"(--max-hosts) — no fuzzeo más.[/yellow]"
                    )
                    break
    err.print(f"[dim]  {len(alive)} hosts vivos.[/dim]")

    # --- Fase 3: dir scan por host vivo ----------------------------------- #
    err.print(f"[bold cyan]▸ Fase 3[/bold cyan] — enumerando directorios en {len(alive)} host(s)")
    all_findings: list[Finding] = []
    for tgt in alive:
        err.print(f"[cyan]  →[/cyan] {tgt.url}")
        dir_cfg = enum.EnumConfig(
            target=tgt.url, mode="dir", wordlist=cfg.dir_wordlist, level=cfg.level,
            threads=cfg.threads, engine=cfg.engine, extensions=cfg.extensions,
            recursive=cfg.recursive, depth=cfg.depth, calibrate=cfg.calibrate,
            no_install=cfg.no_install, verbose=cfg.verbose, force_scheme=tgt.scheme,
        )
        try:
            batch = enum.scan(dir_cfg).findings
        except TargetError as exc:
            err.print(f"    [yellow][~] {exc}[/yellow]")
            continue
        base = tgt.url.rstrip("/")
        for f in batch:
            f.path = f"{base}{f.path}"  # ruta absoluta con host, para el agregado
            all_findings.append(f)

    mark_interesting(all_findings)

    # --- Presentación ----------------------------------------------------- #
    if cfg.stdout_json:
        for linea in iter_jsonl(all_findings):
            sys.stdout.write(linea + "\n")
        sys.stdout.flush()
    else:
        err.print()
        print_results_table(
            all_findings, title=f"Hallazgos — {cfg.domain} ({len(alive)} hosts vivos)"
        )

    # --- Guardado --------------------------------------------------------- #
    if cfg.output:
        save_results(all_findings, cfg.output, cfg.out_format,
                     {"domain": cfg.domain, "hosts_vivos": len(alive), "engine": cfg.engine})

    return all_findings
