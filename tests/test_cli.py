from __future__ import annotations

import pytest

from kaeru_mtk.cli import build_parser, main


def test_parser_has_all_subcommands():
    p = build_parser()
    help_text = p.format_help()
    for cmd in ("driver", "detect", "info", "auth", "socs", "exploit", "flash", "unlock-bl"):
        assert cmd in help_text


def test_help_does_not_crash():
    p = build_parser()
    p.format_help()


def test_unknown_command_exits():
    with pytest.raises(SystemExit):
        main(["this-is-not-a-command"])


def test_socs_command_runs(capsys):
    rc = main(["socs"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "MT6763" in out
    assert "MT6877" in out
    assert "0x0959" in out


def test_auth_list_runs(capsys):
    rc = main(["auth", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "MT6877.auth" in out
    assert "15 auth files bundled" in out


def test_auth_resolve_known_hwcode(capsys):
    rc = main(["auth", "resolve", "0x959"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "MT6877" in out
    assert "bundled auth" in out


def test_auth_resolve_unknown_hwcode_returns_one(capsys):
    rc = main(["auth", "resolve", "0xCAFE"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "no SoC matches" in out


def test_exploit_list_runs(capsys):
    rc = main(["exploit", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kamakiri" in out
    assert "kamakiri2" in out
    assert "carbonara" in out
    assert "heapbait" in out
