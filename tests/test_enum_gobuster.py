"""Tests de resolución de wordlist y armado del comando gobuster (lógica pura)."""

import pytest

from belphegor.preflight import Target, TargetError
from belphegor.modules import enum_gobuster as eg
from belphegor.modules.enum_gobuster import (
    EnumConfig,
    build_command,
    count_wordlist_lines,
    find_existing_wordlist,
    resolve_wordlist,
)


def _resolved(host="ejemplo.com", scheme="http"):
    return Target(raw=host, host=host, scheme=scheme,
                  url=f"{scheme}://{host}", ip="10.0.0.1")


# --------------------------------------------------------------------------- #
# find_existing_wordlist / count_wordlist_lines
# --------------------------------------------------------------------------- #
def test_find_existing_wordlist(tmp_path):
    real = tmp_path / "w.txt"
    real.write_text("a\nb\n")
    assert find_existing_wordlist(["/no/existe", str(real)]) == str(real)
    assert find_existing_wordlist(["/no/existe/tampoco"]) is None


def test_count_wordlist_lines_ignora_vacias(tmp_path):
    w = tmp_path / "w.txt"
    w.write_text("admin\n\nlogin\n   \napi\n")
    assert count_wordlist_lines(str(w)) == 3


# --------------------------------------------------------------------------- #
# resolve_wordlist
# --------------------------------------------------------------------------- #
def test_resolve_wordlist_propia_existente(tmp_path):
    w = tmp_path / "mia.txt"
    w.write_text("x\n")
    cfg = EnumConfig(target="t", mode="dir", wordlist=str(w))
    assert resolve_wordlist(cfg) == str(w)


def test_resolve_wordlist_propia_inexistente():
    cfg = EnumConfig(target="t", mode="dir", wordlist="/no/existe.txt")
    with pytest.raises(TargetError):
        resolve_wordlist(cfg)


def test_resolve_wordlist_por_nivel(tmp_path, monkeypatch):
    w = tmp_path / "common.txt"
    w.write_text("admin\n")
    monkeypatch.setitem(eg.WORDLISTS["dir"], "basic", ["/no/existe", str(w)])
    cfg = EnumConfig(target="t", mode="dir", level="basic")
    assert resolve_wordlist(cfg) == str(w)


def test_resolve_wordlist_nivel_sin_archivos(monkeypatch):
    monkeypatch.setitem(eg.WORDLISTS["dir"], "basic", ["/no/existe/1", "/no/existe/2"])
    cfg = EnumConfig(target="t", mode="dir", level="basic")
    with pytest.raises(TargetError):
        resolve_wordlist(cfg)


# --------------------------------------------------------------------------- #
# build_command
# --------------------------------------------------------------------------- #
def test_build_command_dir_basico():
    cfg = EnumConfig(target="ejemplo.com", mode="dir")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "dir"]
    assert "-u" in cmd and "http://ejemplo.com" in cmd
    assert "-w" in cmd and "/w.txt" in cmd
    assert "--no-color" in cmd


def test_build_command_dir_con_extensiones():
    cfg = EnumConfig(target="ejemplo.com", mode="dir", extensions="php,html")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert "-x" in cmd
    assert cmd[cmd.index("-x") + 1] == "php,html"


def test_build_command_vhost_append_domain():
    cfg = EnumConfig(target="ejemplo.com", mode="vhost")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "vhost"]
    assert "--append-domain" in cmd


def test_build_command_dns_usa_host_pelado():
    cfg = EnumConfig(target="ejemplo.com", mode="dns")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert cmd[:2] == ["gobuster", "dns"]
    assert "-d" in cmd
    assert cmd[cmd.index("-d") + 1] == "ejemplo.com"


def test_build_command_extensiones_ignoradas_fuera_de_dir():
    # -x solo aplica en modo dir; en dns no debe aparecer.
    cfg = EnumConfig(target="ejemplo.com", mode="dns", extensions="php")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert "-x" not in cmd


def test_build_command_exclude_length():
    cfg = EnumConfig(target="ejemplo.com", mode="dir", exclude_length="359")
    cfg._resolved_target = _resolved()
    cmd = build_command(cfg, "/w.txt")
    assert "--exclude-length" in cmd
    assert cmd[cmd.index("--exclude-length") + 1] == "359"
