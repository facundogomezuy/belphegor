"""Banner ASCII y disclaimer de uso ético para Belphegor."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

try:
    import pyfiglet
except ImportError:  # pragma: no cover
    pyfiglet = None

console = Console()

VERSION = "0.1.0"
TAGLINE = "Recon & enumeration toolkit · bug bounty / pentesting"

DISCLAIMER = (
    "Esta herramienta es SOLO para uso en objetivos donde tengas autorización "
    "explícita (programa de bug bounty en scope, pentest contratado, laboratorio "
    "propio). Escanear sistemas sin permiso es ilegal en la mayoría de las "
    "jurisdicciones. El uso indebido es responsabilidad exclusiva de quien lo ejecuta."
)


def _big_name() -> Text:
    """El nombre 'Belphegor' en grande (figlet si está disponible)."""
    if pyfiglet is not None:
        return Text(pyfiglet.figlet_format("Belphegor", font="slant"), style="bold red")
    return Text("B E L P H E G O R", style="bold red")


def render_scan_header(summary: str) -> None:
    """Limpia la consola y deja solo el nombre grande + un resumen del escaneo.

    Se llama una vez que el usuario terminó de elegir todas las pautas en el
    menú interactivo, justo antes de arrancar gobuster. Así la fase de escaneo
    queda limpia: sin el disclaimer ni los prompts previos, solo el nombre
    arriba y una línea con qué se va a escanear (lo que antes iba en el título
    de la tabla). `summary` puede traer markup de rich.
    """
    console.clear()
    console.print(_big_name(), end="")
    console.print(Text(f"  v{VERSION}", style="dim italic"))
    console.print()
    console.print(summary)
    console.print()


def render_banner() -> None:
    """Imprime el banner grande + tagline + disclaimer."""
    console.print(_big_name(), end="")
    console.print(
        Text(f"  v{VERSION}  —  {TAGLINE}", style="dim italic"),
        justify="left",
    )
    console.print()
    console.print(
        Panel(
            Text(DISCLAIMER, style="yellow"),
            title="[bold red]⚠ Aviso legal[/bold red]",
            border_style="red",
            expand=True,
        )
    )
    console.print()
