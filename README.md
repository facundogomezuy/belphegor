<div align="center">

```
                                   ____       __      __                         
                                  / __ )___  / /___  / /_  ___  ____ _____  _____
                                 / __  / _ \/ / __ \/ __ \/ _ \/ __ `/ __ \/ ___/
                                / /_/ /  __/ / /_/ / / / /  __/ /_/ / /_/ / /    
                               /_____/\___/_/ .___/_/ /_/\___/\__, /\____/_/     
                                           /_/               /____/              
```

### 🜏 Belphegor

**Recon & enumeration toolkit para bug bounty y pentesting**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#-roadmap)

</div>

---

> [!WARNING]
> **Uso ético.** Belphegor es solo para objetivos donde tengas **autorización
> explícita** (programa de bug bounty en scope, pentest contratado, laboratorio
> propio). Escanear sin permiso es ilegal en la mayoría de las jurisdicciones.
> El uso indebido corre por tu cuenta.

Belphegor es una herramienta de reconocimiento y enumeración pensada para correr
en Linux (BlackArch / Kali). Esta es la **primera etapa** de una tool más grande:
la arquitectura ya está armada por módulos para sumar capacidades sin reescribir.

---

## 📑 Contenido

- [✨ Features](#-features)
- [📦 Instalación](#-instalación)
- [🚀 Uso](#-uso)
- [🔎 Módulo de enumeración](#-módulo-de-enumeración-gobuster)
- [🗂️ Estructura](#️-estructura)
- [🗺️ Roadmap](#️-roadmap)
- [📄 Licencia](#-licencia)

---

## ✨ Features

- 🖥️ **Modo dual** — menú interactivo si lo corrés pelado, o flags por CLI para
  scriptearlo.
- 🎨 **Salida con color** vía [`rich`](https://github.com/Textualize/rich):
  tablas, paneles y status HTTP coloreados.
- 🧪 **Preflight inteligente** — resuelve DNS y autodetecta http/https *antes* de
  disparar el escaneo, así no te comés errores crípticos de gobuster.
- 📊 **Salida limpia** — durante el escaneo, un spinner con el conteo de posibles
  hallazgos y el tiempo; al terminar, una tabla ordenada. Con `-v` además imprime
  cada hallazgo en vivo, apenas aparece (ideal para CTF).
- 🎯 **Detección de respuesta comodín** — cuando un target responde igual a todo
  (WAF, catch-all 403, SPA), separa los hallazgos que rompen el patrón del ruido
  y te ofrece re-correr filtrando por tamaño (`--exclude-length`).
- 🛡️ **Chequeo de dependencias** — avisa si falta una herramienta externa y corta
  con un mensaje claro antes de romper.
- 📥 **Auto-instalación consentida** — si falta gobuster, detecta tu gestor de
  paquetes y te ofrece instalarlo, mostrándote el comando exacto antes de correr
  nada. Nunca instala en silencio.
- 🧩 **Arquitectura modular** — pensada para sumar recon pasivo y descubrimiento
  activo como módulos nuevos.

---

## 📦 Instalación

Belphegor se instala como **comando del sistema** (`belphegor`). No hace falta
llamar a Python a mano.

```bash
git clone https://github.com/facundogomezuy/belphegor.git
cd belphegor

# Recomendado: pipx (queda aislado, no te ensucia el Python del sistema)
pipx install .

# Alternativa con pip
pip install .

# Para desarrollo (editás el código sin reinstalar, + dependencias de test)
pip install -e ".[dev]"
pytest        # corre la suite de tests
```

### Dependencias externas

| Herramienta | Para qué | Instalación |
|-------------|----------|-------------|
| `gobuster`  | Módulo de enumeración | `apt install gobuster` · `pacman -S gobuster` |
| `seclists`  | Wordlists por defecto | `apt install seclists` · [repo](https://github.com/danielmiessler/SecLists) |

> Los defaults de wordlist apuntan a rutas de **SecLists** (`/usr/share/seclists/…`).
> Si no lo tenés instalado, pasá tu propia wordlist con `-w`.
>
> Las dependencias de Python (`rich`, `pyfiglet`, `requests`) se instalan solas
> con el paquete — el `requirements.txt` está solo por comodidad; la fuente de
> verdad es `pyproject.toml`.

### 📥 Auto-instalación de herramientas

Si vas a correr un módulo y falta su herramienta externa (ej: gobuster),
Belphegor **te ofrece instalarla** en vez de solo abandonar:

1. Detecta el gestor de paquetes de tu distro (`apt` · `pacman` · `dnf` ·
   `zypper` · `apk`).
2. Te muestra el **comando exacto** que ejecutaría (con `sudo` solo si no sos
   root).
3. Instala **únicamente si confirmás** (el default es *no*).
4. Si declinás, no hay gestor soportado, o la instalación falla → cae al mensaje
   de instalación manual, sin romper.

En entornos no interactivos (scripts, CI, cron) no pregunta nunca. Y si querés
desactivar el ofrecimiento del todo, pasá `--no-install`:

```bash
belphegor enum pepito.com -m dir --no-install
```

---

## 🚀 Uso

### Menú interactivo

```bash
belphegor
```

```
╭──────────────── Menú principal ────────────────╮
│ 1) Reconocimiento pasivo      (próximamente)    │
│ 2) Descubrimiento activo      (próximamente)    │
│ 3) Enumeración de contenido   (gobuster)        │
│ 4) Salir                                        │
╰─────────────────────────────────────────────────╯
```

> 💡 `belphegor -v` entra al **mismo menú pero con verbose activado**: cada
> escaneo que lances desde ahí va mostrando los hallazgos en vivo, sin tener que
> elegir nada extra. En CLI el flag va igual: `belphegor enum pepito.com -m dir -v`.

### CLI directo (scripteable)

```bash
# Enumeración de directorios (autodetecta http/https)
belphegor enum pepito.com -m dir

# Subdominios por fuerza bruta DNS
belphegor enum pepito.com -m dns

# vhosts, forzando https y guardando en JSON
belphegor enum https://pepito.com -m vhost --protocol https -o out.json --format json

# dir con nivel medio, extensiones y 20 hilos
belphegor enum pepito.com -m dir -L full -x php,html,bak -t 20

# dir con wordlist propia (ignora el nivel)
belphegor enum pepito.com -m dir -w /ruta/wordlist.txt
```

> 💡 Sin instalar, desde el repo: `python -m belphegor` equivale al comando
> `belphegor`.

---

## 🔎 Módulo de enumeración (gobuster)

Envuelve gobuster en sus 3 modos (`dir`, `vhost`, `dns`) con un **preflight** que
evita los errores típicos antes de disparar el escaneo:

```
   input del usuario
          │
          ▼
  ┌─────────────────┐   ¿ya trae esquema?
  │ 1. Normalizar   │──────────► respetarlo
  │    dominio/URL  │
  └────────┬────────┘
           ▼
  ┌─────────────────┐   no resuelve → corta con
  │ 2. Resolver DNS │──────────► mensaje claro
  └────────┬────────┘
           ▼
  ┌─────────────────┐   HTTPS ok → https
  │ 3. Autodetectar │   timeout   → http
  │    protocolo    │   --protocol → forzar
  └────────┬────────┘
           ▼
      gobuster 🚀
```

1. **Normaliza el target** — acepta dominio pelado (`pepito.com`), con esquema
   (`https://pepito.com`), con o sin `www`. Si ponés esquema, se respeta.
2. **Resuelve DNS** con `socket.getaddrinfo()` (IPv4/IPv6). Si no resuelve, corta
   con un mensaje claro en vez de dejar que gobuster tire un error críptico.
3. **Autodetecta el protocolo** — prueba HTTPS primero (timeout ~5s,
   `verify=False` por los certificados self-signed habituales en pentest). Si
   contesta cualquier cosa, usa https; si no, cae a http. Sigue redirects y se
   queda con el esquema final.
4. `--protocol http|https` fuerza el esquema y saltea la autodetección.

### Flags principales

| Flag | Descripción |
|------|-------------|
| `target` | Dominio o URL objetivo (obligatorio) |
| `-m, --mode` | `dir` / `vhost` / `dns` (obligatorio) |
| `-L, --level` | Nivel de wordlist: `basic` / `full` / `deep` (default `basic`) |
| `-w, --wordlist` | Wordlist propia (tiene prioridad sobre `--level`) |
| `-t, --threads` | Hilos (default `10`; avisa si `> 50`) |
| `--delay` | Delay entre requests (pasa a gobuster) |
| `-x, --extensions` | Extensiones, solo modo `dir` (ej `php,html`) |
| `-s` / `-b` | Status codes a incluir / excluir |
| `--exclude-length` | Tamaño(s) de respuesta a excluir (filtra comodín) |
| `--auto-filter` | Si detecta comodín, re-corre solo excluyendo su tamaño (sin preguntar) |
| `--protocol` | Forzar `http` / `https` |
| `-v, --verbose` | Imprimir cada hallazgo en vivo (útil en CTF) |
| `-o, --output` | Archivo de salida |
| `--format` | `txt` o `json` |
| `--no-install` | No ofrecer instalar herramientas faltantes (scripts/CI) |

### 🎚️ Niveles de wordlist

En vez de acordarte rutas de SecLists, elegís un **nivel** y Belphegor resuelve la
wordlist sola. Cada nivel prueba varias rutas candidatas y usa la primera que
exista (aguanta Kali y BlackArch, que a veces las guardan distinto):

| Nivel | Para qué | Idea |
|-------|----------|------|
| `basic` *(default)* | primer vistazo, rápido | lista chica (`common.txt`) |
| `full` | cobertura media, lo más usado en bug bounty | lista media (~directory-list medium) |
| `deep` | exhaustivo y agresivo | lista grande (tarda y hace ruido) |

```bash
belphegor enum pepito.com -m dir -L full     # nivel medio
belphegor enum pepito.com -m dns -L deep     # subdominios, a fondo
```

¿No usás SecLists o querés tu propia lista? Pasá `-w` y manda la tuya (tiene
prioridad, el nivel se ignora):

```bash
belphegor enum pepito.com -m dir -w /ruta/a/mi-wordlist.txt
```

Si el nivel elegido no encuentra ninguna wordlist en tu sistema, te avisa cuáles
rutas probó y te sugiere instalar SecLists o usar `-w`.

Durante el escaneo se muestra un **spinner** con el conteo de posibles hallazgos
y el tiempo transcurrido (nada de scroll infinito); al terminar, los hallazgos
van a una **tabla con color** que separa lo que rompe el patrón del ruido comodín.
Si preferís ver cada hallazgo **apenas aparece** —por ejemplo en un CTF, donde
querés reaccionar rápido— pasá `-v`. `Ctrl+C` corta el escaneo de forma limpia
sin dejar procesos colgados.

```bash
# ver cada hallazgo en vivo, y si aparece un comodín filtrarlo solo
belphegor enum pepito.com -m dir -v --auto-filter
```

---

## 🗂️ Estructura

```
belphegor/                    # raíz del repo
├── belphegor/                # el paquete
│   ├── __init__.py
│   ├── __main__.py           # habilita python -m belphegor
│   ├── cli.py                # entry point: menú + argparse
│   ├── banner.py             # ASCII art + disclaimer
│   ├── installer.py          # auto-instalación consentida de herramientas
│   ├── preflight.py          # chequeo de herramientas + validación de target
│   ├── utils.py              # helpers de output/guardado
│   └── modules/
│       ├── __init__.py
│       └── enum_gobuster.py  # dir / vhost / dns
├── tests/                    # suite de pytest (lógica pura, sin red)
├── pyproject.toml            # metadata + entry point del comando `belphegor`
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🗺️ Roadmap

- [ ] 🕵️ **Reconocimiento pasivo** — OSINT, subdominios pasivos, etc.
- [ ] 📡 **Descubrimiento activo** — port scanning, fingerprinting.
- [x] 🔎 **Enumeración de contenido** — gobuster (dir/vhost/dns).
- [x] ✅ **Tests** — suite con `pytest` sobre parser, detección de comodín,
  resolución de wordlist y normalización de target.

---

## 📄 Licencia

Distribuido bajo licencia **MIT**. Ver [`LICENSE`](LICENSE) para más detalle.

<div align="center">

*Hecho para aprender, romper (con permiso) y aprender rompiendo.*

</div>
