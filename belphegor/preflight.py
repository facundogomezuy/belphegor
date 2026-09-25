"""Chequeo de herramientas externas y validación/normalización del target.

Este módulo agrupa dos responsabilidades del preflight:
  - Verificar que las herramientas externas que necesitan los módulos estén
    instaladas (por ahora solo `gobuster`).
  - Normalizar el dominio/URL que pasa el usuario, resolver DNS y autodetectar
    el protocolo (http/https) antes de dispararle a gobuster.
"""

from __future__ import annotations

import random
import shutil
import socket
import string
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

# Todo lo que imprime preflight es diagnóstico → va a stderr, para no ensuciar
# un pipe cuando el resultado (JSONL) sale por stdout.
console = Console(stderr=True)

# Herramientas externas que puede necesitar cada módulo. Al crecer la tool,
# se suman entradas acá y el chequeo de arranque las recorre.
# Herramientas que se chequean al arrancar (avisos no-fatales).
REQUIRED_TOOLS = {
    "gobuster": "apt install gobuster · pacman -S gobuster · dnf install gobuster",
}

# Hints de instalación para cualquier herramienta que un motor pueda pedir
# (incluye motores alternativos como ffuf, que no se chequean al arranque).
TOOL_HINTS = {
    "gobuster": "apt install gobuster · pacman -S gobuster · dnf install gobuster",
    "ffuf": "apt install ffuf · pacman -S ffuf · go install github.com/ffuf/ffuf/v2@latest",
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

    hint = TOOL_HINTS.get(tool, f"instalá {tool} y volvé a intentar")
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


def _extract_host(target: str) -> tuple[str, Optional[str], str]:
    """Devuelve (host, scheme_forzado_por_el_usuario, path).

    - host:   netloc (host[:port]) pelado.
    - scheme: si el usuario ya escribió el esquema, lo respetamos; si no, None
              y lo autodetectamos después.
    - path:   base path si el usuario lo puso (ej '/app' en host/app), para no
              descartarlo silenciosamente en modo dir. '' si no hay.
    """
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        return host, parsed.scheme.lower() or None, path
    # Dominio pelado, posiblemente con path (pepito.com/algo).
    parsed = urlparse(f"//{target}")
    return parsed.netloc or target, None, parsed.path


def _split_host_port(host: str) -> tuple[str, Optional[str]]:
    """Separa host y puerto, soportando IPv6 con brackets.

    Ejemplos:
      'ejemplo.com'      -> ('ejemplo.com', None)
      'ejemplo.com:8080' -> ('ejemplo.com', '8080')
      '127.0.0.1:8000'   -> ('127.0.0.1', '8000')
      '[::1]:8080'       -> ('::1', '8080')
      '::1'              -> ('::1', None)   # IPv6 pelado, sin puerto
    """
    host = host.strip()
    if host.startswith("["):  # IPv6 con brackets, con o sin puerto
        addr, _, rest = host[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
        return addr, (port or None)
    # Más de un ':' sin brackets → IPv6 pelado (no tiene puerto separable a mano).
    if host.count(":") > 1:
        return host, None
    if ":" in host:
        h, _, p = host.partition(":")
        return h, (p or None)
    return host, None


def _resolve(host: str) -> str:
    """Resuelve DNS (IPv4 o IPv6). Lanza TargetError si no resuelve.

    Usa getaddrinfo (no gethostbyname) para soportar IPv6 y hosts con puerto.
    Preferimos una IPv4 cuando el host tiene ambas, por máxima compatibilidad
    con gobuster y el resto del tooling.
    """
    hostname, _ = _split_host_port(host)
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise TargetError(
            f"no se pudo resolver «{hostname}», revisá que esté bien escrito "
            f"(¿typo?, ¿te falta el dominio completo?)"
        )
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return infos[0][4][0]


def _hostport_for_url(host: str) -> str:
    """Devuelve host[:port] listo para meter en una URL, con brackets si es IPv6."""
    addr, port = _split_host_port(host)
    if ":" in addr and not addr.startswith("["):  # IPv6 pelado → necesita brackets
        addr = f"[{addr}]"
    return f"{addr}:{port}" if port else addr


def _probe_scheme(host: str, timeout: float = 5.0) -> str:
    """Autodetecta el esquema: prueba HTTPS y cae a HTTP si no contesta.

    Usa HEAD (no GET) para no descargar el body: solo nos importa si el
    servicio contesta. Cualquier respuesta HTTP (incluso 401/403/404/405)
    cuenta como "el servicio está ahí". Si tras un redirect el esquema final
    cambia, nos quedamos con el final.
    """
    if requests is None:
        # Sin requests no podemos probar; asumimos https como el default más
        # seguro/común hoy.
        console.print(
            "[yellow][~] requests no está instalado; asumo https "
            "(instalá requests para autodetección real).[/yellow]"
        )
        return "https"

    netloc = _hostport_for_url(host)
    for scheme in ("https", "http"):
        url = f"{scheme}://{netloc}"
        try:
            resp = requests.head(
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
    host, user_scheme, path = _extract_host(target)
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

    # Preservamos el base path (si lo hubo) para no descartarlo en modo dir.
    url = urlunparse((scheme, _hostport_for_url(host), path, "", "", ""))
    return Target(raw=target, host=host, scheme=scheme, url=url, ip=ip)


# --------------------------------------------------------------------------- #
# Auto-calibración de comodín
# --------------------------------------------------------------------------- #
def _random_path(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def calibrate_wildcard(
    base_url: str, samples: int = 3, timeout: float = 5.0
) -> Optional[dict]:
    """Detecta un catch-all pegándole a rutas random antes de escanear.

    Pide `samples` rutas inexistentes al azar. Si el server responde a TODAS con
    el mismo (status, tamaño) y ese status no es 404, es un comodín: devuelve
    {"status", "size"} para excluir ese tamaño del escaneo. Devuelve None si no
    hay patrón, si el status consistente es 404 (comportamiento normal), o si no
    se puede probar.
    """
    if requests is None:
        return None

    statuses: list[int] = []
    sizes: list[int] = []
    base = base_url.rstrip("/")
    for _ in range(samples):
        url = f"{base}/{_random_path()}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        except requests.exceptions.RequestException:
            return None
        statuses.append(resp.status_code)
        sizes.append(len(resp.content))

    if len(set(statuses)) == 1 and len(set(sizes)) == 1:
        status = statuses[0]
        if status == 404:
            return None  # 404 consistente = comportamiento normal, no comodín
        return {"status": str(status), "size": str(sizes[0])}
    return None
