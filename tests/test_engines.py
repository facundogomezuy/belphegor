"""Tests del backend gobuster y del registro de motores."""

import pytest

from belphegor.engines import (
    GobusterScanner,
    get_scanner,
    is_gobuster_precheck_error,
    parse_gobuster_line,
)
from belphegor.models import Finding
from belphegor.modules.enum_gobuster import EnumConfig
from belphegor.preflight import Target


def _resolved(host="ejemplo.com", scheme="http"):
    return Target(raw=host, host=host, scheme=scheme,
                  url=f"{scheme}://{host}", ip="10.0.0.1")


# --------------------------------------------------------------------------- #
# parse_gobuster_line
# --------------------------------------------------------------------------- #
def test_parse_dir_completo():
    f = parse_gobuster_line("/admin (Status: 301) [Size: 313] [--> /admin/]", "dir")
    assert isinstance(f, Finding)
    assert f.path == "/admin"
    assert f.status == "301"
    assert f.size == "313"
    assert f.redirect == "/admin/"
    assert f.source == "gobuster"


def test_parse_dir_agrega_barra_inicial():
    f = parse_gobuster_line("admin (Status: 200) [Size: 10]", "dir")
    assert f.path == "/admin"


def test_parse_vhost_no_agrega_barra():
    f = parse_gobuster_line("Found: panel.ejemplo.com (Status: 200) [Size: 42]", "vhost")
    assert f.path == "panel.ejemplo.com"
    assert f.status == "200"
    assert f.size == "42"


def test_parse_dns_found():
    f = parse_gobuster_line("Found: api.ejemplo.com", "dns")
    assert f.path == "api.ejemplo.com"
    assert f.status == ""


def test_parse_ruido_devuelve_none():
    assert parse_gobuster_line("Progress: 1200 / 4600", "dir") is None
    assert parse_gobuster_line("===============================", "dir") is None
    assert parse_gobuster_line("[+] Wordlist: /x/y.txt", "dir") is None
    assert parse_gobuster_line("2026/09/24 12:00:00 the server returns...", "dir") is None
    assert parse_gobuster_line("   ", "dir") is None


def test_precheck_error():
    assert is_gobuster_precheck_error(
        "2026/09/24 the server returns a status code that matches the provided"
    )
    assert is_gobuster_precheck_error("please exclude the response length or the status code")
    assert not is_gobuster_precheck_error("/admin (Status: 200) [Size: 10]")


# --------------------------------------------------------------------------- #
# get_scanner
# --------------------------------------------------------------------------- #
def test_get_scanner_gobuster():
    s = get_scanner("gobuster")
    assert isinstance(s, GobusterScanner)
    assert s.tool == "gobuster"


def test_get_scanner_desconocido():
    with pytest.raises(ValueError):
        get_scanner("ffuf")  # todavía no implementado


# --------------------------------------------------------------------------- #
# GobusterScanner.build_command
# --------------------------------------------------------------------------- #
def test_build_command_dir_basico():
    cfg = EnumConfig(target="ejemplo.com", mode="dir")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "dir"]
    assert "-u" in cmd and "http://ejemplo.com" in cmd
    assert "-w" in cmd and "/w.txt" in cmd
    assert "--no-color" in cmd


def test_build_command_dir_extensiones():
    cfg = EnumConfig(target="ejemplo.com", mode="dir", extensions="php,html")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert cmd[cmd.index("-x") + 1] == "php,html"


def test_build_command_vhost_append_domain():
    cfg = EnumConfig(target="ejemplo.com", mode="vhost")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "vhost"]
    assert "--append-domain" in cmd


def test_build_command_dns_host_pelado():
    cfg = EnumConfig(target="ejemplo.com", mode="dns")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "dns"]
    assert cmd[cmd.index("-d") + 1] == "ejemplo.com"


def test_build_command_extensiones_solo_en_dir():
    cfg = EnumConfig(target="ejemplo.com", mode="dns", extensions="php")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert "-x" not in cmd


def test_build_command_exclude_length():
    cfg = EnumConfig(target="ejemplo.com", mode="dir", exclude_length="359")
    cfg._resolved_target = _resolved()
    cmd = GobusterScanner().build_command(cfg, "/w.txt")
    assert cmd[cmd.index("--exclude-length") + 1] == "359"
