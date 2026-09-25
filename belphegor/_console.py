"""Consolas compartidas de Belphegor.

Regla de oro para poder pipear la salida:

  - `out`  → **stdout**, reservado para el RESULTADO: la tabla en modo normal,
             o el JSONL en modo --json.
  - `err`  → **stderr**, para TODO lo decorativo/diagnóstico (preflight, spinner,
             avisos, comando ejecutado…).

Así `belphegor ... --json | jq` recibe por el pipe solo los hallazgos, mientras
los adornos siguen viéndose en la terminal (stderr) sin ensuciar el pipe.
"""

from rich.console import Console

out = Console()
err = Console(stderr=True)
