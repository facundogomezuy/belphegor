"""Motores de escaneo (backends) detrás de una interfaz común.

Belphegor no reimplementa el fuzzing: orquesta motores ya probados. Cada motor
(gobuster hoy; ffuf en el roadmap) implementa `Scanner`, que sabe tres cosas:

  - armar el comando externo a partir de la config,
  - parsear cada línea de salida a un `Finding` normalizado,
  - reconocer su error fatal de precheck de comodín (si lo tiene).

El orquestador (modules/enum_gobuster.py) es agnóstico del motor: pide un
Scanner con `get_scanner(nombre)` y trabaja siempre con `Finding`.
"""

from __future__ import annotations

import re
import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from .models import Finding

if TYPE_CHECKING:  # solo para anotaciones; evita el ciclo de import en runtime
    from .modules.enum_gobuster import EnumConfig


class Scanner(ABC):
    """Interfaz que implementa cada motor de escaneo."""

    name: str = "base"    # identificador (--engine)
    tool: str = ""        # binario externo requerido en el PATH

    def available(self) -> bool:
        """True si el binario del motor está instalado."""
        return shutil.which(self.tool) is not None

    @abstractmethod
    def build_command(self, cfg: "EnumConfig", wordlist: str) -> list[str]:
        """Arma la lista de argumentos para subprocess según la config."""

    @abstractmethod
    def parse_line(self, line: str, mode: str) -> Optional[Finding]:
        """Traduce una línea de salida a un Finding, o None si no es un hallazgo."""

    def is_fatal_precheck(self, line: str) -> bool:
        """True si la línea es el error fatal de precheck de comodín del motor."""
        return False


# --------------------------------------------------------------------------- #
# gobuster
# --------------------------------------------------------------------------- #
# El logger estándar de Go prefija sus mensajes fatales con un timestamp
# "YYYY/MM/DD HH:MM:SS ". Nunca es un hallazgo.
_GOBUSTER_LOG_PREFIX = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\b")

_GOBUSTER_NOISE_PREFIXES = (
    "=", "Gobuster", "[+]", "[*]", "Progress:", "Starting", "Finished",
    "by OJ", "---", "Error:", "[ERROR]",
)


def parse_gobuster_line(line: str, mode: str) -> Optional[Finding]:
    """Parsea una línea de gobuster a Finding (o None si no es un hallazgo)."""
    stripped = line.strip()
    if not stripped:
        return None
    if _GOBUSTER_LOG_PREFIX.match(stripped):
        return None
    if stripped.startswith(_GOBUSTER_NOISE_PREFIXES):
        return None

    f = Finding(raw=stripped, source="gobuster")

    # dns: los hallazgos vienen como "Found: <sub>" (o el subdominio pelado).
    if mode == "dns":
        if stripped.lower().startswith("found:"):
            f.path = stripped.split(":", 1)[1].strip()
        else:
            f.path = stripped
        return f

    # dir / vhost: "/admin (Status: 301) [Size: 313] [--> /admin/]"
    text = stripped
    if text.lower().startswith("found:"):
        text = text.split(":", 1)[1].strip()

    path = text.split(" ")[0] if text else stripped
    # gobuster 3.x emite el path sin barra inicial en modo dir; se la devolvemos
    # (vhost es un hostname, no lleva barra).
    if mode == "dir" and path and not path.startswith(("/", "http://", "https://")):
        path = "/" + path
    f.path = path

    if "Status:" in stripped:
        try:
            after = stripped.split("Status:", 1)[1]
            f.status = after.strip().split(")")[0].strip().split()[0]
        except (IndexError, ValueError):
            pass
    if "Size:" in stripped:
        try:
            after = stripped.split("Size:", 1)[1]
            f.size = after.strip().split("]")[0].strip().split()[0]
        except (IndexError, ValueError):
            pass
    if "-->" in stripped:
        f.redirect = stripped.split("-->", 1)[1].strip().rstrip("]").strip()

    return f


def is_gobuster_precheck_error(line: str) -> bool:
    """True si la línea es el error fatal de gobuster por precheck de wildcard.

    Antes de arrancar, gobuster le pega a una URL random para ver si el target
    devuelve el mismo status/tamaño para cualquier cosa (catch-all 403, WAF,
    vhost comodín…). Si es así, aborta con este mensaje en vez de escanear.
    """
    lowered = line.lower()
    return (
        "the server returns a status code that matches" in lowered
        or "please exclude the response length or the status code" in lowered
    )


class GobusterScanner(Scanner):
    """Backend gobuster (dir / vhost / dns)."""

    name = "gobuster"
    tool = "gobuster"

    def build_command(self, cfg: "EnumConfig", wordlist: str) -> list[str]:
        cmd: list[str] = ["gobuster", cfg.mode]

        if cfg.mode == "dir":
            assert cfg._resolved_target is not None
            cmd += ["-u", cfg._resolved_target.url]
        elif cfg.mode == "vhost":
            assert cfg._resolved_target is not None
            cmd += ["-u", cfg._resolved_target.url, "--append-domain"]
        else:  # dns
            cmd += ["-d", self._dns_domain(cfg)]

        cmd += ["-w", wordlist, "-t", str(cfg.threads)]

        if cfg.delay:
            cmd += ["--delay", cfg.delay]
        if cfg.mode == "dir" and cfg.extensions:
            cmd += ["-x", cfg.extensions]
        if cfg.status_include:
            cmd += ["-s", cfg.status_include]
        if cfg.status_exclude:
            cmd += ["-b", cfg.status_exclude]
        if cfg.exclude_length:
            cmd += ["--exclude-length", cfg.exclude_length]

        # Sin colores ANSI para que el parseo sea limpio.
        cmd += ["--no-color"]
        return cmd

    def parse_line(self, line: str, mode: str) -> Optional[Finding]:
        return parse_gobuster_line(line, mode)

    def is_fatal_precheck(self, line: str) -> bool:
        return is_gobuster_precheck_error(line)

    @staticmethod
    def _dns_domain(cfg: "EnumConfig") -> str:
        """En modo dns usamos el host pelado (sin esquema)."""
        if cfg._resolved_target is not None:
            return cfg._resolved_target.host
        return cfg.target.replace("https://", "").replace("http://", "").strip("/")


# --------------------------------------------------------------------------- #
# Registro de motores
# --------------------------------------------------------------------------- #
ENGINES = ("gobuster",)  # ffuf en el roadmap (Fase 2)

_REGISTRY: dict[str, type[Scanner]] = {
    "gobuster": GobusterScanner,
}


def get_scanner(name: str) -> Scanner:
    """Devuelve una instancia del motor pedido.

    Raises:
        ValueError: si el motor no existe.
    """
    try:
        return _REGISTRY[name]()
    except KeyError:
        disponibles = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"motor desconocido «{name}» (disponibles: {disponibles}).")
