"""Tests del encadenamiento dns → vivos → dir (orquestación con mocks, sin red)."""

from belphegor.models import Finding
from belphegor.modules import chain
from belphegor.modules.enumeration import ScanResult
from belphegor.preflight import Target


def _target(host, scheme="https"):
    return Target(raw=host, host=host, scheme=scheme, url=f"{scheme}://{host}", ip="1.2.3.4")


# --------------------------------------------------------------------------- #
# _subdomains
# --------------------------------------------------------------------------- #
def test_subdomains_extrae_y_dedup():
    fs = [
        Finding(raw="x", path="api.dom.com"),
        Finding(raw="x", path="api.dom.com"),   # duplicado
        Finding(raw="x", path="dev.dom.com"),
    ]
    assert chain._subdomains(fs, "dom.com") == ["api.dom.com", "dev.dom.com"]


def test_subdomains_agrega_dominio_si_falta():
    fs = [Finding(raw="x", path="api")]
    assert chain._subdomains(fs, "dom.com") == ["api.dom.com"]


# --------------------------------------------------------------------------- #
# run_chain (mockeando enum.scan y probe_alive)
# --------------------------------------------------------------------------- #
def _mock_scans(monkeypatch, dir_counter=None):
    """enum.scan: dns devuelve 2 subs; dir devuelve /admin. Cuenta dir scans."""
    def fake_scan(cfg):
        if cfg.mode == "dns":
            fs = [Finding(raw="Found: api.dom", path="api.dom"),
                  Finding(raw="Found: dev.dom", path="dev.dom")]
        else:
            if dir_counter is not None:
                dir_counter.append(cfg.target)
            fs = [Finding(raw="/admin", path="/admin", status="200")]
        return ScanResult(findings=fs, scanner=None, cmd=None, recursive=False, wordlist="w")
    monkeypatch.setattr(chain.enum, "scan", fake_scan)


def test_run_chain_agrega_por_host(monkeypatch):
    _mock_scans(monkeypatch)
    # dom (raíz) y api.dom viven; dev.dom no.
    monkeypatch.setattr(chain, "probe_alive",
                        lambda h, timeout=5.0: _target(h) if h in ("dom", "api.dom") else None)

    findings = chain.run_chain(chain.ChainConfig(domain="dom", stdout_json=True))
    paths = sorted(f.path for f in findings)
    assert paths == ["https://api.dom/admin", "https://dom/admin"]
    assert all(f.interesting for f in findings)  # /admin es jugoso


def test_run_chain_respeta_max_hosts(monkeypatch):
    dir_scans: list[str] = []
    _mock_scans(monkeypatch, dir_counter=dir_scans)
    monkeypatch.setattr(chain, "probe_alive", lambda h, timeout=5.0: _target(h))  # todos vivos

    chain.run_chain(chain.ChainConfig(domain="dom", max_hosts=2, stdout_json=True))
    # candidatos = dom + api.dom + dev.dom = 3 vivos, pero el tope corta en 2.
    assert len(dir_scans) == 2


def test_run_chain_sin_hosts_vivos(monkeypatch):
    _mock_scans(monkeypatch)
    monkeypatch.setattr(chain, "probe_alive", lambda h, timeout=5.0: None)  # ninguno vivo
    findings = chain.run_chain(chain.ChainConfig(domain="dom", stdout_json=True))
    assert findings == []
