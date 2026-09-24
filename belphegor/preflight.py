"""Chequeo de herramientas externas y validación/normalización del target.

Este módulo agrupa dos responsabilidades del preflight:
  - Verificar que las herramientas externas que necesitan los módulos estén
    instaladas (por ahora solo `gobuster`).
  - Normalizar el dominio/URL que pasa el usuario, resolver DNS y autodetectar
    el protocolo (http/https) antes de dispararle a gobuster.
"""

from __future__ import annotations

import shutil
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urlunparse

import urllib3
from rich.console import Console

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# En pentesting es normal toparse con certificados self-signed. Silenciamos el
# warning de urllib3 porque abajo usamos verify=False a propósito.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Herramientas externas que puede necesitar cada módulo. Al crecer la tool,
# se suman entradas acá y el chequeo de arranque las recorre.
REQUIRED_TOOLS = {
    "gobuster": "apt install gobuster · pacman -S gobuster · dnf install gobuster",
}


# --------------------------------------------------------------------------- #
# Chequeo de herramientas externas
# --------------------------------------------------------------------------- #
def tool_installed(tool: str) -> bool:
    """True si `tool` está en el PATH."""
    return shutil.which(tool) is not None


def check_tools() -> list[str]:
    """Recorre REQUIRED_TOOLS y devuelve la lista de las que faltan.

    Imprime un warning en rojo por cada faltante, pero NO corta el flujo:
    el menú se muestra igual. El corte real ocurre recién cuando el usuario
    elige un módulo que depende de una herramienta ausente (ver ensure_tool).
    """
    missing: list[str] = []
    for tool, hint in REQUIRED_TOOLS.items():
        if not tool_installed(tool):
            missing.append(tool)
            console.print(
                f"[bold red][!] {tool} no encontrado[/bold red] "
                f"[dim]— instalar con: {hint}[/dim]"
            )
    return missing


def ensure_tool(tool: str, offer_install_if_missing: bool = True,
                no_install: bool = False) -> None:
    """Corta con un mensaje claro si `tool` no está instalada.

    Se llama justo antes de ejecutar el subprocess que depende de la
    herramienta, no al arrancar. Si falta y `offer_install_if_missing` está
    activo, primero ofrece instalarla de forma consentida (ver installer.py);
    solo corta si el usuario declina o la instalación no prospera.

    Args:
        tool: herramienta requerida.
        offer_install_if_missing: si True, ofrece auto-instalar antes de cortar.
        no_install: si True, no ofrece nada (flag --no-install / no interactivo).
    """
    if tool_installed(tool):
        return

    if offer_install_if_missing:
        # Import local para no crear un ciclo a nivel de módulo.
        from .installer import offer_install

        if offer_install(tool, assume_no=no_install):
            return  # quedó instalada, seguimos

    hint = REQUIRED_TOOLS.get(tool, f"instalá {tool} y volvé a intentar")
    raise ToolMissingError(
        f"{tool} no está instalado y este módulo lo necesita.\n"
        f"    Instalá con: {hint}"
    )


class ToolMissingError(RuntimeError):
    """La herramienta externa requerida no está disponible."""


class TargetError(RuntimeError):
    """No se pudo validar/resolver el target."""


# --------------------------------------------------------------------------- #
# Normalización y validación del target
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """Resultado del preflight de un objetivo.

    Attributes:
        raw:      lo que escribió el usuario, tal cual.
        host:     hostname pelado (sin esquema, sin path), lo que se resuelve
                  por DNS y lo que se le pasa a gobuster en modo dns/vhost.
        scheme:   'http' o 'https' (resuelto o forzado).
        url:      URL completa con esquema, para gobuster modo dir.
        ip:       IP a la que resolvió el host.
    """

    raw: str
    host: str
    scheme: str
    url: str
    ip: str


def _extract_host(target: str) -> tuple[str, Optional[str]]:
    """Devuelve (host, scheme_forzado_por_el_usuario).

    Si el usuario ya escribió el esquema, lo respetamos y lo devolvemos como
    segundo elemento. Si no, scheme queda en None y lo autodetectamos después.
    """
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path, parsed.scheme.lower() or None
    # Dominio pelado, posiblemente con path (pepito.com/algo) → nos quedamos
    # solo con el netloc/host.
    parsed = urlparse(f"//{target}")
    return parsed.netloc or target, None


def _resolve(host: str) -> str:
    """Resuelve DNS. Lanza TargetError si no resuelve."""
    # gethostbyname no maneja el puerto; lo sacamos si vino pegado (host:8080).
    hostname = host.split(":")[0]
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise TargetError(
            f"no se pudo resolver «{hostname}», revisá que esté bien escrito "
            f"(¿typo?, ¿te falta el dominio completo?)"
        )


def _probe_scheme(host: str, timeout: float = 5.0) -> str:
    """Autodetecta el esquema: prueba HTTPS y cae a HTTP si no contesta.

    Cualquier respuesta HTTP (incluso 401/403/404) cuenta como "el servicio
    está ahí". Si tras un redirect el esquema final cambia, nos quedamos con
    el final.
    """
    if requests is None:
        # Sin requests no podemos probar; asumimos https como el default más
        # seguro/común hoy.
        console.print(
            "[yellow][~] requests no está instalado; asumo https "
            "(instalá requests para autodetección real).[/yellow]"
        )
        return "https"

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                verify=False,  # self-signed es esperable en pentesting
                allow_redirects=True,
            )
            # Si hubo redirects, el esquema final puede haber cambiado.
            final_scheme = urlparse(resp.url).scheme.lower()
            return final_scheme or scheme
        except requests.exceptions.RequestException:
            continue

    # Ninguno de los dos contestó. Devolvemos http como último recurso; el host
    # ya resolvió por DNS, así que dejamos que gobuster lo intente igual.
    console.print(
        "[yellow][~] ni https ni http respondieron al probe; sigo con http.[/yellow]"
    )
    return "http"


def build_target(target: str, force_scheme: Optional[str] = None) -> Target:
    """Corre el preflight completo sobre `target` y devuelve un Target.

    Pasos:
      1. Extrae el host (respeta el esquema si el usuario lo puso).
      2. Resuelve DNS (corta si no resuelve).
      3. Determina el esquema: forzado por flag > puesto por el usuario >
         autodetectado.

    Raises:
        TargetError: si no resuelve el DNS o el esquema forzado es inválido.
    """
    host, user_scheme = _extract_host(target)
    if not host:
        raise TargetError("target vacío o mal formado.")

    ip = _resolve(host)

    if force_scheme:
        force_scheme = force_scheme.lower()
        if force_scheme not in ("http", "https"):
            raise TargetError(
                f"--protocol inválido: «{force_scheme}» (usá http o https)."
            )
        scheme = force_scheme
    elif user_scheme in ("http", "https"):
        scheme = user_scheme
    else:
        scheme = _probe_scheme(host)

    url = urlunparse((scheme, host, "", "", "", ""))
    return Target(raw=target, host=host, scheme=scheme, url=url, ip=ip)
