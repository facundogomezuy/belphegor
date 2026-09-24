"""Auto-instalación opcional y consentida de herramientas externas.

Filosofía (importante en una tool de seguridad): NUNCA instalar nada en
silencio. El flujo es siempre:
  1. Detectar el gestor de paquetes de la distro.
  2. Armar el comando EXACTO que se ejecutaría.
  3. Mostrárselo al usuario y pedir confirmación explícita (default = NO).
  4. Solo si acepta, ejecutar — con streaming para que vea qué pasa.
  5. Si dice que no, si no hay gestor soportado, o si falla → volver al
     mensaje de instalación manual de siempre, sin romper.

sudo se agrega solo si no somos root. Si no hay sudo disponible y no somos
root, se avisa y se cae al modo manual.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()


# --------------------------------------------------------------------------- #
# Detección del gestor de paquetes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PackageManager:
    """Un gestor de paquetes y cómo se instala con él."""

    name: str            # 'apt', 'pacman', ...
    binary: str          # binario a buscar en el PATH
    install_args: list[str]  # args de instalación no interactivos

    def install_command(self, package: str, use_sudo: bool) -> list[str]:
        cmd = [self.binary, *self.install_args, package]
        if use_sudo:
            cmd = ["sudo", *cmd]
        return cmd


# Orden de preferencia. El primero cuyo binario exista en el PATH gana.
# -y / --noconfirm hacen la instalación no interactiva (ya pedimos confirmación
# nosotros antes).
_MANAGERS: list[PackageManager] = [
    PackageManager("apt", "apt-get", ["install", "-y"]),
    PackageManager("apt", "apt", ["install", "-y"]),
    PackageManager("pacman", "pacman", ["-S", "--noconfirm"]),
    PackageManager("dnf", "dnf", ["install", "-y"]),
    PackageManager("yum", "yum", ["install", "-y"]),
    PackageManager("zypper", "zypper", ["install", "-y"]),
    PackageManager("apk", "apk", ["add"]),
]

# Nombre del paquete por gestor cuando difiere del nombre de la herramienta.
# gobuster se llama igual en todos los repos donde está, así que por ahora
# alcanza con un default, pero dejamos el mapa listo para casos futuros.
_PACKAGE_NAMES: dict[str, dict[str, str]] = {
    # "herramienta": {"gestor": "nombre-del-paquete"}
    # ej: "gobuster": {"apk": "gobuster"},
}


def detect_package_manager() -> Optional[PackageManager]:
    """Devuelve el primer gestor de paquetes disponible, o None."""
    for mgr in _MANAGERS:
        if shutil.which(mgr.binary):
            return mgr
    return None


def _package_for(tool: str, mgr: PackageManager) -> str:
    """Nombre del paquete de `tool` para el gestor dado (default: el mismo)."""
    return _PACKAGE_NAMES.get(tool, {}).get(mgr.name, tool)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _sudo_available() -> bool:
    return shutil.which("sudo") is not None


# --------------------------------------------------------------------------- #
# Flujo de instalación consentida
# --------------------------------------------------------------------------- #
def offer_install(tool: str, assume_no: bool = False) -> bool:
    """Ofrece instalar `tool` de forma consentida. Devuelve True si quedó instalada.

    Args:
        tool:      herramienta a instalar (ej 'gobuster').
        assume_no: si True (flag --no-install o entorno no interactivo), ni
                   siquiera pregunta: devuelve False directo. Útil para
                   pipelines donde no querés prompts.

    Returns:
        True  → la herramienta quedó instalada y disponible en el PATH.
        False → el usuario declinó, no hay gestor, o la instalación falló.
                En todos esos casos el caller cae al mensaje manual.
    """
    if assume_no:
        return False

    # Sin TTY no tiene sentido preguntar (scripts, cron, CI): no instalamos.
    if not _stdin_is_interactive():
        return False

    mgr = detect_package_manager()
    if mgr is None:
        console.print(
            "[yellow][~] No pude detectar un gestor de paquetes soportado "
            "(apt/pacman/dnf/zypper/apk). Instalá la herramienta a mano.[/yellow]"
        )
        return False

    use_sudo = not _is_root()
    if use_sudo and not _sudo_available():
        console.print(
            "[yellow][~] Haría falta sudo para instalar y no está disponible. "
            "Corré como root o instalá la herramienta a mano.[/yellow]"
        )
        return False

    package = _package_for(tool, mgr)
    cmd = mgr.install_command(package, use_sudo)
    cmd_str = " ".join(cmd)

    # Mostramos el comando EXACTO antes de pedir permiso. Nada de sorpresas.
    console.print(
        Panel(
            f"[bold]{tool}[/bold] no está instalado.\n\n"
            f"Comando a ejecutar:\n  [cyan]{cmd_str}[/cyan]"
            + ("\n\n[dim]Se te va a pedir la contraseña de sudo.[/dim]" if use_sudo else ""),
            title="[yellow]¿Instalar la herramienta?[/yellow]",
            border_style="yellow",
        )
    )

    if not Confirm.ask(f"¿Instalar {tool} ahora?", default=False):
        console.print("[dim]Ok, no instalo nada. Instalalo a mano cuando quieras.[/dim]")
        return False

    ok = _run_install(cmd, cmd_str)
    if not ok:
        return False

    # Verificamos que efectivamente haya quedado en el PATH.
    if shutil.which(tool) is None:
        console.print(
            f"[yellow][~] La instalación terminó pero no encuentro «{tool}» en el "
            f"PATH. Revisá manualmente.[/yellow]"
        )
        return False

    console.print(f"[green][+] {tool} instalado y disponible.[/green]")
    return True


def _run_install(cmd: list[str], cmd_str: str) -> bool:
    """Ejecuta el comando de instalación con streaming. True si exit code 0."""
    console.print(f"[dim]$ {cmd_str}[/dim]")
    try:
        proc = subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Instalación cancelada por el usuario.[/yellow]")
        return False
    except FileNotFoundError:
        console.print("[red][!] No se pudo ejecutar el gestor de paquetes.[/red]")
        return False

    if proc.returncode != 0:
        console.print(
            f"[red][!] La instalación falló (exit code {proc.returncode}). "
            f"Probá a mano: {cmd_str}[/red]"
        )
        return False
    return True


def _stdin_is_interactive() -> bool:
    """True si hay una terminal real para preguntar."""
    try:
        import sys

        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False
