"""Tests de los helpers de recursión (lógica pura, sin correr escaneos)."""

from belphegor.models import Finding
from belphegor.modules.enum_gobuster import (
    _child_base,
    _full_path,
    _looks_like_dir,
)


# --------------------------------------------------------------------------- #
# _looks_like_dir
# --------------------------------------------------------------------------- #
def test_dir_por_redirect_con_barra():
    f = Finding(raw="x", path="/admin", status="301", redirect="/admin/")
    assert _looks_like_dir(f) is True


def test_no_dir_redirect_a_archivo():
    f = Finding(raw="x", path="/index", status="301", redirect="/index.php")
    assert _looks_like_dir(f) is False


def test_dir_por_200_sin_extension():
    f = Finding(raw="x", path="/panel", status="200")
    assert _looks_like_dir(f) is True


def test_no_dir_200_con_extension():
    f = Finding(raw="x", path="/robots.txt", status="200")
    assert _looks_like_dir(f) is False


def test_no_recursa_403():
    f = Finding(raw="x", path="/secret", status="403")
    assert _looks_like_dir(f) is False


# --------------------------------------------------------------------------- #
# _full_path / _child_base
# --------------------------------------------------------------------------- #
def test_full_path_desde_raiz():
    assert _full_path("http://host", "/admin") == "/admin"
    assert _full_path("http://host/", "/admin") == "/admin"


def test_full_path_anidado():
    assert _full_path("http://host/app/", "/users") == "/app/users"
    assert _full_path("http://host/app", "users") == "/app/users"


def test_child_base():
    assert _child_base("http://host/", "/admin") == "http://host/admin/"
    assert _child_base("http://host/app/", "/app/users") == "http://host/app/users/"


def test_child_base_preserva_puerto():
    assert _child_base("http://host:8080/", "/api") == "http://host:8080/api/"
