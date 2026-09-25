"""Tests de resolución de wordlist del orquestador de enumeración."""

import pytest

from belphegor.preflight import TargetError
from belphegor.modules import enum_gobuster as eg
from belphegor.modules.enum_gobuster import (
    EnumConfig,
    count_wordlist_lines,
    find_existing_wordlist,
    resolve_wordlist,
)


def test_find_existing_wordlist(tmp_path):
    real = tmp_path / "w.txt"
    real.write_text("a\nb\n")
    assert find_existing_wordlist(["/no/existe", str(real)]) == str(real)
    assert find_existing_wordlist(["/no/existe/tampoco"]) is None


def test_count_wordlist_lines_ignora_vacias(tmp_path):
    w = tmp_path / "w.txt"
    w.write_text("admin\n\nlogin\n   \napi\n")
    assert count_wordlist_lines(str(w)) == 3


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
