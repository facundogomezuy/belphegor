# 🗺️ Roadmap de Belphegor

La meta: que Belphegor deje de ser "gobuster con mejor cara" y pase a ser un
**orquestador de recon con cerebro** — el motor lo ponen gobuster/ffuf; Belphegor
pone el flujo, la inteligencia sobre los resultados y una salida que se integra a
cualquier pipeline. No competimos en velocidad de fuzzing (eso ya lo hacen bien
las herramientas en Go): competimos en **qué hacemos con lo que encuentran**.

Cada fase deja algo usable por sí sola. No hay "a mitad de nada".

---

## ✅ Fase 0 — Cimientos *(hecho)*

Andamiaje que abarata todo lo demás.

- [x] **Modelo `Finding` tipado** (`models.py`) — cada motor traduce su salida a
  un tipo estable (`path`, `status`, `size`, `redirect`, `source`). El resto del
  código no depende de cómo imprime cada herramienta.
- [x] **Abstracción de motores** (`engines.py`) — interfaz `Scanner` con
  `GobusterScanner` detrás. El orquestador es agnóstico: pide un motor con
  `get_scanner(nombre)` y trabaja con `Finding`. Deja el enganche listo para ffuf.

## ✅ Fase 1 — Salida pipeable *(hecho)*

- [x] **JSONL por stdout** (`--json`, o automático cuando stdout no es una
  terminal) — una línea JSON por hallazgo, para `belphegor ... --json | jq`,
  `| httpx`, `| nuclei`.
- [x] **Separación stdout/stderr** — el resultado va a stdout; todo el
  diagnóstico (preflight, spinner, avisos) a stderr, así el pipe queda limpio.
- [x] **Formato de archivo `jsonl`** además de `txt`/`json`.

---

## ✅ Fase 2 — Backend ffuf intercambiable *(hecho)*

- [x] `FfufScanner` detrás de la misma interfaz `Scanner` (`--engine ffuf`) para
  modos dir y vhost (dns queda en gobuster).
- [x] Parser propio de la salida de ffuf, traducción de flags y manejo de su
  stderr (progreso ruidoso) por separado.

## ✅ Fase 3 — Recursión automática *(hecho)*

- [x] `-r/--recursive` + `--depth N`: al encontrar un directorio se re-escanea
  dentro. BFS por niveles, paths absolutos, dedup y tope de seguridad.

## ⏳ Fase 4 — Encadenamiento

- [ ] `subdominios → hosts vivos → dir scan` en un comando, con un probe (httpx)
  que filtre vivos antes de fuzzear.
- [ ] Control de scope: límites y confirmación en targets grandes.

> Nota: es la fase que conviene validar contra un target real con subdominios
> (no se puede testear a fondo en localhost), así que va después de las demás.

## ✅ Fase 5 — Inteligencia sobre resultados *(hecho)*

- [x] **Auto-calibración** de comodín (`--calibrate`): pega a N URLs random al
  inicio y excluye el tamaño del catch-all de entrada.
- [x] **Resaltar lo jugoso** (`/admin`, `/.git`, `.env`, backups, api…) — marcado
  con ★ en la tabla y campo `interesting` en el JSON.
- [ ] Dedup por content-hash y fingerprint básico desde headers *(pendiente)*.

---

## 🔧 Transversal

- [ ] CI con GitHub Actions corriendo `pytest` en cada push.
- [ ] Publicar en PyPI / `pipx install belphegor`.
- [ ] Archivo de config `~/.belphegor.yaml` con defaults personales (wordlist,
  engine, hilos).
- [ ] Renombrar `modules/enum_gobuster.py` → `modules/enum.py` (ya es agnóstico
  del motor; el nombre quedó por historia).
