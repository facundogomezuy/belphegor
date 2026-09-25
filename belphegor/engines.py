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
    # ¿mezclar stderr del motor en stdout? gobuster manda su error de precheck a
    # stderr y lo queremos ver; ffuf manda ahí el progreso ruidoso (con \r) que
    # ensuciaría el parseo, así que lo descarta.
    merge_stderr: bool = True

    def available(self) -> bool:
        """True si el binario del motor está instalado."""
        return shutil.which(self.tool) is not None

    @abstractmethod
    def build_command(
        self, cfg: "EnumConfig", wordlist: str, base_url: Optional[str] = None
    ) -> list[str]:
        """Arma la lista de argumentos para subprocess según la config.

        `base_url` sobreescribe la URL objetivo (modo dir): lo usa la recursión
        para escanear dentro de un subdirectorio encontrado.
        """

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

    def build_command(
        self, cfg: "EnumConfig", wordlist: str, base_url: Optional[str] = None
    ) -> list[str]:
        cmd: list[str] = ["gobuster", cfg.mode]

        if cfg.mode == "dir":
            assert cfg._resolved_target is not None
            cmd += ["-u", base_url or cfg._resolved_target.url]
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
# ffuf
# --------------------------------------------------------------------------- #
def parse_ffuf_line(line: str, mode: str) -> Optional[Finding]:
    """Parsea una línea de ffuf a Finding.

    Formato de un hallazgo de ffuf (sin -s):
        admin        [Status: 200, Size: 1234, Words: 56, Lines: 7, Duration: 12ms]
    El banner y las líneas de progreso ('::  Progress: …') se descartan.
    """
    stripped = line.strip()
    if not stripped or "[Status:" not in stripped:
        return None
    if stripped.startswith("::"):  # línea de progreso de ffuf
        return None

    before, _, after = stripped.partition("[Status:")
    path = before.strip()
    if not path:
        return None

    f = Finding(raw=stripped, source="ffuf")
    # after = "200, Size: 1234, Words: 56, Lines: 7, Duration: 12ms]"
    f.status = after.split(",", 1)[0].strip().rstrip("]").strip()
    if "Size:" in after:
        f.size = after.split("Size:", 1)[1].split(",", 1)[0].strip().rstrip("]").strip()

    if mode == "dir" and path and not path.startswith(("/", "http://", "https://")):
        path = "/" + path
    f.path = path
    return f


class FfufScanner(Scanner):
    """Backend ffuf (dir / vhost). No hace fuerza bruta de DNS (usá gobuster)."""

    name = "ffuf"
    tool = "ffuf"
    merge_stderr = False  # el progreso de ffuf va a stderr; lo descartamos

    def build_command(
        self, cfg: "EnumConfig", wordlist: str, base_url: Optional[str] = None
    ) -> list[str]:
        if cfg.mode == "dns":
            from .preflight import TargetError
            raise TargetError(
                "ffuf no hace fuerza bruta de DNS; usá --engine gobuster para modo dns."
            )

        assert cfg._resolved_target is not None
        cmd: list[str] = ["ffuf", "-w", wordlist, "-t", str(cfg.threads), "-noninteractive"]

        if cfg.mode == "dir":
            base = (base_url or cfg._resolved_target.url).rstrip("/")
            cmd += ["-u", f"{base}/FUZZ"]
            if cfg.extensions:
                exts = ",".join("." + e.lstrip(".") for e in cfg.extensions.split(","))
                cmd += ["-e", exts]
        else:  # vhost
            host = cfg._resolved_target.host
            cmd += ["-u", cfg._resolved_target.url, "-H", f"Host: FUZZ.{host}"]

        if cfg.delay:
            cmd += ["-p", cfg.delay]
        if cfg.status_include:
            cmd += ["-mc", cfg.status_include]
        if cfg.status_exclude:
            cmd += ["-fc", cfg.status_exclude]
        if cfg.exclude_length:
            cmd += ["-fs", cfg.exclude_length]

        return cmd

    def parse_line(self, line: str, mode: str) -> Optional[Finding]:
        return parse_ffuf_line(line, mode)


# --------------------------------------------------------------------------- #
# Registro de motores
# --------------------------------------------------------------------------- #
ENGINES = ("gobuster", "ffuf")

_REGISTRY: dict[str, type[Scanner]] = {
    "gobuster": GobusterScanner,
    "ffuf": FfufScanner,
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
