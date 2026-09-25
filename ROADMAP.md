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

## ⏳ Fase 2 — Backend ffuf intercambiable

- [ ] `FfufScanner` detrás de la misma interfaz `Scanner` (`--engine ffuf`, con
  autodetección del que esté instalado).
- [ ] Traducir la config a `ffuf -of json` (más fácil de parsear que gobuster) y
  aprovechar sus matchers/filtros más potentes.

*Deja de depender de un solo motor y usa el mejor para cada caso.*

## ⏳ Fase 3 — Recursión automática

- [ ] Al encontrar un directorio, re-lanzar el escaneo dentro, con `--depth`,
  dedup y un tope para no explotar. Es lo que más ahorra tiempo manual.

## ⏳ Fase 4 — Encadenamiento

- [ ] `subdominios → hosts vivos → dir scan` en un comando, con un probe (httpx)
  que filtre vivos antes de fuzzear.
- [ ] Control de scope: límites y confirmación en targets grandes.

## ⏳ Fase 5 — Inteligencia sobre resultados

- [ ] **Auto-calibración** de comodín: pegar a N URLs random al inicio para el
  baseline (más robusto que la detección post-hoc actual).
- [ ] **Resaltar lo jugoso** (`/admin`, `/.git`, `.env`, backups…) y dedup por
  content-hash.
- [ ] Fingerprint básico desde headers.

---

## 🔧 Transversal

- [ ] CI con GitHub Actions corriendo `pytest` en cada push.
- [ ] Publicar en PyPI / `pipx install belphegor`.
- [ ] Archivo de config `~/.belphegor.yaml` con defaults personales (wordlist,
  engine, hilos).
- [ ] Renombrar `modules/enum_gobuster.py` → `modules/enum.py` (ya es agnóstico
  del motor; el nombre quedó por historia).
