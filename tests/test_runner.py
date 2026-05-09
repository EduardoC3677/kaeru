from __future__ import annotations

from pathlib import Path

import pytest

from kaeru_mtk.runner.mtkclient import (
    MtkClientLocation,
    MtkClientNotInstalled,
    MtkClientRunner,
    locate_mtkclient,
)


def _loc(*parts: str) -> MtkClientLocation:
    return MtkClientLocation(argv0=tuple(parts), source="test")


def test_runner_builds_argv_with_no_extras():
    r = MtkClientRunner(location=_loc("mtk"))
    assert r.build_argv("printgpt", []) == ["mtk", "printgpt"]


def test_runner_inserts_auth_loader_preloader():
    r = MtkClientRunner(
        location=_loc("mtk"),
        auth=Path("/tmp/x.auth"),
        loader=Path("/tmp/da.bin"),
        preloader=Path("/tmp/pl.bin"),
    )
    argv = r.build_argv("r", ["boot", "boot.bin"])
    assert argv[:4] == ["mtk", "r", "boot", "boot.bin"]
    assert "--auth" in argv
    assert "/tmp/x.auth" in argv
    assert "--loader" in argv
    assert "/tmp/da.bin" in argv
    assert "--preloader" in argv
    assert "/tmp/pl.bin" in argv


def test_runner_uses_python_invocation_for_in_tree_script():
    r = MtkClientRunner(location=_loc("/usr/bin/python3", "/path/mtk.py"))
    assert r.build_argv("reset", [])[:3] == ["/usr/bin/python3", "/path/mtk.py", "reset"]


def test_locate_mtkclient_raises_when_absent(monkeypatch):
    monkeypatch.delenv("KAERU_MTK_BIN", raising=False)
    monkeypatch.setattr("kaeru_mtk.runner.mtkclient.shutil.which", lambda _: None)
    import sys
    monkeypatch.setitem(sys.modules, "mtkclient", None)
    with pytest.raises(MtkClientNotInstalled):
        locate_mtkclient()


def test_locate_mtkclient_uses_env_override(monkeypatch):
    monkeypatch.setenv("KAERU_MTK_BIN", "/opt/custom/mtk --extra")
    loc = locate_mtkclient()
    assert loc.argv0 == ("/opt/custom/mtk", "--extra")
    assert "env" in loc.source
