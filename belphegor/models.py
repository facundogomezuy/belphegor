"""Modelo de datos compartido entre motores de escaneo.

Cualquier backend (gobuster, ffuf, …) traduce su salida cruda a `Finding`, así
el resto de Belphegor —detección de comodín, tablas, JSON, y más adelante la
recursión y el encadenamiento— trabaja sobre un tipo estable y no depende de
cómo imprime cada herramienta.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """Un hallazgo de enumeración, normalizado e independiente del motor."""

    raw: str                   # línea/registro original del motor
    path: str = ""             # ruta ('/admin') o host ('api.dominio.com')
    status: str = ""           # status HTTP como string ('200'); '' si no aplica
    size: str = ""             # tamaño de la respuesta como string; '' si no aplica
    redirect: str = ""         # destino del redirect (--> …), si lo hay
    source: str = "gobuster"   # motor que lo produjo

    def to_dict(self) -> dict:
        """Dict serializable (para JSON/JSONL)."""
        return asdict(self)
