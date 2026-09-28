<div align="center">

```
                                   ____       __      __                         
                                  / __ )___  / /___  / /_  ___  ____ _____  _____
                                 / __  / _ \/ / __ \/ __ \/ _ \/ __ `/ __ \/ ___/
                                / /_/ /  __/ / /_/ / / / /  __/ /_/ / /_/ / /    
                               /_____/\___/_/ .___/_/ /_/\___/\__, /\____/_/     
                                           /_/               /____/              
```

### Belphegor

**Content enumeration and web fuzzing for bug bounty and pentesting**

[![PyPI](https://img.shields.io/pypi/v/belphegor.svg)](https://pypi.org/project/belphegor/)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

<!-- DEMO: paste the asciinema/GIF here once recorded, e.g.
[![asciicast](https://asciinema.org/a/XXXXXX.svg)](https://asciinema.org/a/XXXXXX)
-->

</div>

---

> [!WARNING]
> Ethical use only. Belphegor is for targets you are explicitly authorized to
> test (a bug bounty program in scope, a contracted pentest, your own lab).
> Scanning without permission is illegal in most jurisdictions. Misuse is on you.

Belphegor is a content enumeration tool (directories, vhosts, subdomains) for
Linux. It doesn't reimplement the fuzzing engine. It drives gobuster or ffuf and
adds the workflow around them: preflight, wildcard handling, host chaining, and
output you can pipe into other tools.

---

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Enumeration](#enumeration)
- [License](#license)

---

## Features

What it adds over running gobuster or ffuf directly:

- Drives gobuster and ffuf behind one interface (`--engine`), so you switch
  engines without changing how you run it.
- Preflight resolves DNS and auto-detects http/https before the scan, so the
  engine doesn't die on a cryptic error.
- Detects and calibrates wildcard (catch-all) responses, so real hits are
  separated from the noise.
- Chains subdomains into a full scan: DNS discovery, then a liveness probe, then
  a directory scan on each live host, in one command (`belphegor chain`).
- Emits JSONL on stdout (diagnostics go to stderr), so you can pipe results into
  `jq`, `httpx` or `nuclei`.
- Flags sensitive paths in the results (`/.git`, `.env`, backups, `/admin`, …).

---

## Installation

Belphegor is published on PyPI and installs as a system command (`belphegor`):

```bash
# Recommended: pipx (isolated, keeps your system Python clean)
pipx install belphegor

# Or with pip
pip install belphegor
```

### From source (development)

```bash
git clone https://github.com/facundogomezuy/belphegor.git
cd belphegor
pip install -e ".[dev]"
pytest
```

If a required external tool is missing, belphegor offers to install it through
your package manager. It shows the exact command first and runs it only if you
confirm, never silently. Pass `--no-install` to skip that in scripts or CI.

### External dependencies

| Tool | Used for | Install |
|------|----------|---------|
| `gobuster` | default engine | `apt install gobuster` · `pacman -S gobuster` |
| `ffuf` | alternative engine (`--engine ffuf`) | `apt install ffuf` · `pacman -S ffuf` |
| `seclists` | default wordlists | `apt install seclists` · [repo](https://github.com/danielmiessler/SecLists) |

The wordlist defaults point at SecLists paths (`/usr/share/seclists/…`). If you
don't have it, pass your own list with `-w`. Python deps (`rich`, `pyfiglet`,
`requests`) are installed with the package; `requirements.txt` is there for
convenience, but `pyproject.toml` is the source of truth.

---

## Usage

Run `belphegor` with no arguments for an interactive prompt that walks you
through a scan. For scripting, use the CLI directly:

```bash
# directory enumeration (auto-detects http/https)
belphegor enum pepito.com -m dir

# subdomain brute force over DNS
belphegor enum pepito.com -m dns

# vhosts, forcing https, saving to JSON
belphegor enum https://pepito.com -m vhost --protocol https -o out.json --format json

# dir with the medium list, extensions and 20 threads
belphegor enum pepito.com -m dir -L full -x php,html,bak -t 20

# dir with a custom wordlist (ignores the level)
belphegor enum pepito.com -m dir -w /path/to/wordlist.txt

# JSONL output to pipe into other tools (diagnostics go to stderr)
belphegor enum pepito.com -m dir --json | jq -r '.path'

# recurse into each directory found, up to 3 levels
belphegor enum pepito.com -m dir -r --depth 3

# use ffuf as the engine, with wildcard calibration
belphegor enum pepito.com -m dir --engine ffuf --calibrate

# chain: subdomains -> live hosts -> dir (up to 25 hosts), with recursion
belphegor chain pepito.com -r --max-hosts 25 --json | jq -r '.path'
```

From a source checkout, `python -m belphegor` is equivalent to the `belphegor`
command.

---

## Enumeration

`belphegor enum` wraps gobuster/ffuf in three modes (`dir`, `vhost`, `dns`)
behind a preflight that catches the usual mistakes before the scan starts:

```
   user input
          │
          ▼
  ┌─────────────────┐   already has scheme?
  │ 1. Normalize    │──────────► keep it
  │    domain/URL   │
  └────────┬────────┘
           ▼
  ┌─────────────────┐   no resolution → stop with
  │ 2. Resolve DNS  │──────────► a clear message
  └────────┬────────┘
           ▼
  ┌─────────────────┐   HTTPS ok  → https
  │ 3. Detect       │   timeout   → http
  │    protocol     │   --protocol → force
  └────────┬────────┘
           ▼
       scan engine
```

1. Normalizes the target: bare domain (`pepito.com`), with scheme
   (`https://pepito.com`), with or without `www`. If you pass a scheme, it's kept.
2. Resolves DNS with `socket.getaddrinfo()` (IPv4/IPv6). If it doesn't resolve,
   it stops with a clear message instead of letting the engine throw a cryptic one.
3. Auto-detects the protocol: tries HTTPS first (~5s timeout, `verify=False` for
   the self-signed certs common in pentests). Any response means https; otherwise
   it falls back to http. It follows redirects and keeps the final scheme.
4. `--protocol http|https` forces the scheme and skips detection.

### Flags

| Flag | Description |
|------|-------------|
| `target` | Target domain or URL (required) |
| `-m, --mode` | `dir` / `vhost` / `dns` (required) |
| `-L, --level` | Wordlist level: `basic` / `full` / `deep` (default `basic`) |
| `-w, --wordlist` | Custom wordlist (overrides `--level`) |
| `-t, --threads` | Threads (default `10`; warns above `50`) |
| `--delay` | Delay between requests (passed to the engine) |
| `-x, --extensions` | Extensions, `dir` mode only (e.g. `php,html`) |
| `-s` / `-b` | Status codes to include / exclude |
| `--exclude-length` | Response size(s) to exclude (filters wildcard) |
| `--auto-filter` | On wildcard, re-run excluding its size (no prompt) |
| `--protocol` | Force `http` / `https` |
| `-v, --verbose` | Print each hit as it comes in |
| `-r, --recursive` | Recurse into found directories (`dir` mode) |
| `--depth` | Max recursion depth with `-r` (default 2) |
| `--calibrate` | Detect a catch-all before scanning and exclude its size |
| `--engine` | Scan engine: `gobuster` or `ffuf` |
| `--json` | Emit JSONL on stdout, for piping (auto when stdout isn't a TTY) |
| `-o, --output` | Output file |
| `--format` | `txt`, `json` or `jsonl` |
| `--no-install` | Don't offer to install missing tools (scripts/CI) |

### Wordlist levels

Instead of memorizing SecLists paths, pick a level and belphegor resolves the
wordlist for you. Each level tries several candidate paths and uses the first one
that exists (so it works across Kali and BlackArch, which store them differently):

| Level | For | List |
|-------|-----|------|
| `basic` *(default)* | quick first pass | small (`common.txt`) |
| `full` | medium coverage | medium (~directory-list medium) |
| `deep` | exhaustive, aggressive | large (slow, noisy) |

```bash
belphegor enum pepito.com -m dir -L full     # medium
belphegor enum pepito.com -m dns -L deep     # subdomains, thorough
```

Bring your own list with `-w`; it takes priority and the level is ignored:

```bash
belphegor enum pepito.com -m dir -w /path/to/my-wordlist.txt
```

If the chosen level finds no wordlist on your system, belphegor tells you which
paths it tried and suggests installing SecLists or using `-w`.

---

## License

MIT. See [LICENSE](LICENSE).
