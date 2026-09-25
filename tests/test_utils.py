"""Tests de detección de comodín y serialización (sobre el modelo Finding)."""

import json

from belphegor.models import Finding
from belphegor.utils import (
    _status_style,
    detect_wildcard,
    is_interesting,
    iter_jsonl,
    mark_interesting,
    save_results,
    split_wildcard_noise,
)


def _f(status, size, path="/x"):
    return Finding(raw=f"{path} ({status}/{size})", path=path, status=status, size=size)


def _many(status, size, n, prefix="x"):
    return [_f(status, size, f"/{prefix}{i}") for i in range(n)]


# --------------------------------------------------------------------------- #
# detect_wildcard / split_wildcard_noise
# --------------------------------------------------------------------------- #
def test_wildcard_pocos_resultados_no_detecta():
    assert detect_wildcard(_many("200", "100", 3)) is None


def test_wildcard_detecta_par_dominante():
    res = _many("200", "359", 8) + [_f("200", "354", "/code"), _f("200", "681", "/start")]
    wc = detect_wildcard(res)
    assert wc is not None
    assert wc["status"] == "200"
    assert wc["size"] == "359"
    assert wc["count"] == 8
    assert round(wc["fraction"], 2) == 0.8


def test_wildcard_sin_dominante_no_detecta():
    res = [_f("200", str(i), f"/p{i}") for i in range(5)]
    assert detect_wildcard(res) is None


def test_split_separa_hallazgos_de_ruido():
    res = _many("200", "359", 8) + [_f("200", "354", "/code"), _f("200", "681", "/start")]
    hallazgos, ruido, wc = split_wildcard_noise(res)
    assert wc is not None
    assert sorted(f.path for f in hallazgos) == ["/code", "/start"]
    assert len(ruido) == 8


def test_split_sin_comodin_devuelve_todo_como_hallazgos():
    res = [_f("200", str(i), f"/p{i}") for i in range(5)]
    hallazgos, ruido, wc = split_wildcard_noise(res)
    assert wc is None
    assert hallazgos == res
    assert ruido == []


# --------------------------------------------------------------------------- #
# _status_style
# --------------------------------------------------------------------------- #
def test_status_style_por_rango():
    assert _status_style("200") == "bold green"
    assert _status_style("301") == "yellow"
    assert _status_style("403") == "red"
    assert _status_style("500") == "bold red"
    assert _status_style("abc") == "white"


# --------------------------------------------------------------------------- #
# Serialización
# --------------------------------------------------------------------------- #
def test_iter_jsonl_una_linea_por_finding():
    res = [_f("200", "10", "/a"), _f("301", "0", "/b")]
    lineas = list(iter_jsonl(res))
    assert len(lineas) == 2
    obj = json.loads(lineas[0])
    assert obj["path"] == "/a"
    assert obj["status"] == "200"
    assert obj["source"] == "gobuster"


def test_save_jsonl_a_archivo(tmp_path):
    res = [_f("200", "10", "/a"), _f("301", "0", "/b")]
    dest = tmp_path / "out.jsonl"
    save_results(res, str(dest), fmt="jsonl")
    lineas = dest.read_text().strip().split("\n")
    assert len(lineas) == 2
    assert json.loads(lineas[1])["path"] == "/b"


# --------------------------------------------------------------------------- #
# Hallazgos jugosos
# --------------------------------------------------------------------------- #
def test_is_interesting():
    assert is_interesting("/admin")
    assert is_interesting("/.git/config")
    assert is_interesting("/backup.zip")
    assert is_interesting("/api/v1/users")
    assert is_interesting("/WP-Admin")  # case-insensitive
    assert not is_interesting("/imagen.png")
    assert not is_interesting("/about")


def test_mark_interesting():
    res = [_f("200", "1", "/admin"), _f("200", "2", "/about")]
    mark_interesting(res)
    assert res[0].interesting is True
    assert res[1].interesting is False


def test_save_json_incluye_meta(tmp_path):
    res = [_f("200", "10", "/a")]
    dest = tmp_path / "out.json"
    save_results(res, str(dest), fmt="json", meta={"target": "x"})
    data = json.loads(dest.read_text())
    assert data["meta"]["target"] == "x"
    assert "generated_at" in data["meta"]
    assert data["results"][0]["path"] == "/a"
