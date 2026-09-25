"""Tests de normalización/resolución de target (sin tocar la red real)."""

import socket

import pytest

from belphegor import preflight
from belphegor.preflight import (
    TargetError,
    _extract_host,
    _hostport_for_url,
    _split_host_port,
    build_target,
)


# --------------------------------------------------------------------------- #
# _split_host_port
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("entrada,esperado", [
    ("ejemplo.com", ("ejemplo.com", None)),
    ("ejemplo.com:8080", ("ejemplo.com", "8080")),
    ("127.0.0.1:8000", ("127.0.0.1", "8000")),
    ("[::1]:8080", ("::1", "8080")),
    ("::1", ("::1", None)),
    ("2001:db8::1", ("2001:db8::1", None)),
])
def test_split_host_port(entrada, esperado):
    assert _split_host_port(entrada) == esperado


# --------------------------------------------------------------------------- #
# _hostport_for_url
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("entrada,esperado", [
    ("ejemplo.com", "ejemplo.com"),
    ("ejemplo.com:8080", "ejemplo.com:8080"),
    ("::1", "[::1]"),
    ("[::1]:8080", "[::1]:8080"),
])
def test_hostport_for_url(entrada, esperado):
    assert _hostport_for_url(entrada) == esperado


# --------------------------------------------------------------------------- #
# _extract_host
# --------------------------------------------------------------------------- #
def test_extract_host_pelado():
    assert _extract_host("ejemplo.com") == ("ejemplo.com", None, "")


def test_extract_host_con_scheme():
    assert _extract_host("https://ejemplo.com") == ("ejemplo.com", "https", "")


def test_extract_host_preserva_path():
    host, scheme, path = _extract_host("http://ejemplo.com/app")
    assert host == "ejemplo.com"
    assert scheme == "http"
    assert path == "/app"


def test_extract_host_path_sin_scheme():
    host, scheme, path = _extract_host("ejemplo.com/app")
    assert host == "ejemplo.com"
    assert scheme is None
    assert path == "/app"


# --------------------------------------------------------------------------- #
# build_target (con resolución y probe mockeados: nada de red)
# --------------------------------------------------------------------------- #
@pytest.fixture
def sin_red(monkeypatch):
    monkeypatch.setattr(preflight, "_resolve", lambda host: "10.0.0.1")
    monkeypatch.setattr(preflight, "_probe_scheme", lambda host, timeout=5.0: "https")


def test_build_target_autodetecta_esquema(sin_red):
    tgt = build_target("ejemplo.com")
    assert tgt.host == "ejemplo.com"
    assert tgt.scheme == "https"
    assert tgt.ip == "10.0.0.1"
    assert tgt.url == "https://ejemplo.com"


def test_build_target_respeta_scheme_del_usuario(sin_red):
    tgt = build_target("http://ejemplo.com")
    assert tgt.scheme == "http"
    assert tgt.url == "http://ejemplo.com"


def test_build_target_force_scheme_gana(sin_red):
    tgt = build_target("https://ejemplo.com", force_scheme="http")
    assert tgt.scheme == "http"


def test_build_target_force_scheme_invalido(sin_red):
    with pytest.raises(TargetError):
        build_target("ejemplo.com", force_scheme="ftp")


def test_build_target_preserva_path_en_url(sin_red):
    tgt = build_target("http://ejemplo.com/app")
    assert tgt.url == "http://ejemplo.com/app"


def test_build_target_dns_no_resuelve(monkeypatch):
    def boom(hostname, *a, **k):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(TargetError):
        build_target("no-existe-jamas.invalid")


def test_resolve_prefiere_ipv4(monkeypatch):
    # getaddrinfo devuelve v6 primero y v4 después; debe elegir la v4.
    fake = [
        (socket.AF_INET6, None, None, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: fake)
    assert preflight._resolve("ejemplo.com") == "1.2.3.4"
