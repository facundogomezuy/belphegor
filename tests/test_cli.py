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


def test_enum_recursive_y_depth():
    args = build_parser().parse_args(["enum", "host", "-m", "dir", "-r", "--depth", "3"])
    assert args.recursive is True
    assert args.depth == 3


def test_enum_calibrate_flag():
    args = build_parser().parse_args(["enum", "host", "-m", "dir", "--calibrate"])
    assert args.calibrate is True


def test_chain_subcommand():
    args = build_parser().parse_args(["chain", "pepito.com", "--max-hosts", "5", "-r", "--depth", "2"])
    assert args.command == "chain"
    assert args.domain == "pepito.com"
    assert args.max_hosts == 5
    assert args.recursive is True
    assert args.depth == 2


def test_chain_defaults():
    args = build_parser().parse_args(["chain", "pepito.com"])
    assert args.engine == "gobuster"
    assert args.max_hosts == 25
    assert args.level == "basic"


def test_main_ctrl_c_sale_limpio(monkeypatch):
    import belphegor.cli as cli

    def boom(args):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "run_enum_from_args", boom)
    # Ctrl+C durante un `enum` (CLI) debe salir con 130, sin traceback.
    assert cli.main(["enum", "host", "-m", "dir"]) == 130
