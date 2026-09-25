"""Tests del parseo de argumentos del CLI (sin ejecutar escaneos)."""

import pytest

from belphegor.cli import build_parser


@pytest.mark.parametrize("argv,command,verbose", [
    # -v global → menú interactivo con verbose (sin subcomando).
    (["-v"], None, True),
    (["--verbose"], None, True),
    # -v después del subcomando (uso natural en CLI).
    (["enum", "host", "-m", "dir", "-v"], "enum", True),
    # -v antes del subcomando: no debe pisarse con el default del subparser.
    (["-v", "enum", "host", "-m", "dir"], "enum", True),
    # sin -v → verbose apagado.
    (["enum", "host", "-m", "dir"], "enum", False),
    (["enum", "host", "-m", "dir", "--verbose"], "enum", True),
])
def test_verbose_en_todas_las_posiciones(argv, command, verbose):
    args = build_parser().parse_args(argv)
    assert args.command == command
    assert args.verbose is verbose


def test_sin_subcomando_no_tiene_command():
    args = build_parser().parse_args([])
    assert args.command is None
    assert args.verbose is False


def test_enum_requiere_mode():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["enum", "host"])  # falta -m


def test_enum_engine_default_gobuster():
    args = build_parser().parse_args(["enum", "host", "-m", "dir"])
    assert args.engine == "gobuster"
    assert args.json is False


def test_enum_json_flag():
    args = build_parser().parse_args(["enum", "host", "-m", "dir", "--json"])
    assert args.json is True


def test_enum_engine_invalido():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["enum", "host", "-m", "dir", "--engine", "nope"])
