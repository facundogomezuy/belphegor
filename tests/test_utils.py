"""Tests de parseo de salida de gobuster y detección de comodín (lógica pura)."""

from belphegor.utils import (
    _status_style,
    detect_wildcard,
    is_wildcard_precheck_error,
    parse_gobuster_line,
    split_wildcard_noise,
)


# --------------------------------------------------------------------------- #
# parse_gobuster_line
# --------------------------------------------------------------------------- #
def test_parse_dir_completo():
    item = parse_gobuster_line("/admin (Status: 301) [Size: 313] [--> /admin/]", "dir")
    assert item["path"] == "/admin"
    assert item["status"] == "301"
    assert item["size"] == "313"


def test_parse_dir_agrega_barra_inicial():
    # gobuster 3.x emite "admin" sin barra; en modo dir se la devolvemos.
    item = parse_gobuster_line("admin (Status: 200) [Size: 10]", "dir")
    assert item["path"] == "/admin"


def test_parse_vhost_no_agrega_barra():
    # vhost es un hostname, no lleva barra inicial.
    item = parse_gobuster_line("Found: panel.ejemplo.com (Status: 200) [Size: 42]", "vhost")
    assert item["path"] == "panel.ejemplo.com"
    assert item["status"] == "200"
    assert item["size"] == "42"


def test_parse_dns_found():
    item = parse_gobuster_line("Found: api.ejemplo.com", "dns")
    assert item["path"] == "api.ejemplo.com"
    assert "status" not in item


def test_parse_ruido_progreso_devuelve_none():
    assert parse_gobuster_line("Progress: 1200 / 4600", "dir") is None
    assert parse_gobuster_line("===============================", "dir") is None
    assert parse_gobuster_line("[+] Wordlist: /x/y.txt", "dir") is None


def test_parse_ruido_log_prefix_devuelve_none():
    linea = "2026/09/24 12:00:00 the server returns a status code that matches"
    assert parse_gobuster_line(linea, "dir") is None


def test_parse_linea_vacia_devuelve_none():
    assert parse_gobuster_line("   ", "dir") is None


# --------------------------------------------------------------------------- #
# detect_wildcard / split_wildcard_noise
# --------------------------------------------------------------------------- #
def _res(status, size, n, prefix="x"):
    return [{"path": f"/{prefix}{i}", "status": status, "size": size} for i in range(n)]


def test_wildcard_pocos_resultados_no_detecta():
    # Menos del mínimo → no clasifica aunque sean todos iguales.
    assert detect_wildcard(_res("200", "100", 3)) is None


def test_wildcard_detecta_par_dominante():
    res = _res("200", "359", 8) + [
        {"path": "/code", "status": "200", "size": "354"},
        {"path": "/start", "status": "200", "size": "681"},
    ]
    wc = detect_wildcard(res)
    assert wc is not None
    assert wc["status"] == "200"
    assert wc["size"] == "359"
    assert wc["count"] == 8
    assert round(wc["fraction"], 2) == 0.8


def test_wildcard_sin_dominante_no_detecta():
    # 5 pares distintos, ninguno domina.
    res = [{"path": f"/p{i}", "status": "200", "size": str(i)} for i in range(5)]
    assert detect_wildcard(res) is None


def test_split_separa_hallazgos_de_ruido():
    res = _res("200", "359", 8) + [
        {"path": "/code", "status": "200", "size": "354"},
        {"path": "/start", "status": "200", "size": "681"},
    ]
    hallazgos, ruido, wc = split_wildcard_noise(res)
    assert wc is not None
    assert sorted(h["path"] for h in hallazgos) == ["/code", "/start"]
    assert len(ruido) == 8


def test_split_sin_comodin_devuelve_todo_como_hallazgos():
    res = [{"path": f"/p{i}", "status": "200", "size": str(i)} for i in range(5)]
    hallazgos, ruido, wc = split_wildcard_noise(res)
    assert wc is None
    assert hallazgos == res
    assert ruido == []


# --------------------------------------------------------------------------- #
# is_wildcard_precheck_error
# --------------------------------------------------------------------------- #
def test_precheck_error_detecta():
    assert is_wildcard_precheck_error(
        "2026/09/24 the server returns a status code that matches the provided"
    )
    assert is_wildcard_precheck_error(
        "please exclude the response length or the status code"
    )


def test_precheck_error_negativo():
    assert not is_wildcard_precheck_error("/admin (Status: 200) [Size: 10]")


# --------------------------------------------------------------------------- #
# _status_style
# --------------------------------------------------------------------------- #
def test_status_style_por_rango():
    assert _status_style("200") == "bold green"
    assert _status_style("301") == "yellow"
    assert _status_style("403") == "red"
    assert _status_style("500") == "bold red"
    assert _status_style("abc") == "white"
