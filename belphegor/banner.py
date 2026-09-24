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


def render_banner() -> None:
    """Imprime el banner grande + tagline + disclaimer."""
    if pyfiglet is not None:
        ascii_art = pyfiglet.figlet_format("Belphegor", font="slant")
        banner_text = Text(ascii_art, style="bold red")
    else:
        banner_text = Text("B E L P H E G O R", style="bold red")

    console.print(banner_text, end="")
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
