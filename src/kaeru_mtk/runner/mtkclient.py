"""Subprocess-based integration with the upstream ``mtkclient`` tool.

kaeru-mtk does not reimplement the MediaTek BROM/DA protocol. The actual
on-the-wire work — handshake, exploits (kamakiri, kamakiri2, carbonara,
hashimoto, heapbait), DA loading, partition I/O — is delegated to
``mtkclient`` (`bkerler/mtkclient`, GPL-3.0-or-later), which is the
mature, hardware-tested reference implementation.

This module:

* locates an installed ``mtk`` executable (the script entry-point of
  mtkclient) on ``PATH``, or, failing that, locates the ``mtk.py`` script
  inside an importable ``mtkclient`` package;
* builds the argument list for an ``mtk`` invocation, transparently
  inserting ``--auth <path>`` when a kaeru-bundled auth file applies;
* streams subprocess output back to the caller.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class MtkClientNotInstalled(KaeruError):
    """``mtkclient`` is not available on the host."""


@dataclass(frozen=True)
class MtkClientLocation:
    """Where mtkclient was found.

    ``argv0`` is the command + leading args used to invoke it (either
    ``["mtk"]`` for an installed entry-point, or
    ``[sys.executable, "<path-to-mtk.py>"]`` for an in-tree script).
    """

    argv0: tuple[str, ...]
    source: str


def locate_mtkclient() -> MtkClientLocation:
    """Find a usable mtkclient invocation.

    Resolution order:

    1. ``KAERU_MTK_BIN`` environment variable, if set, is used verbatim.
    2. An ``mtk`` executable on ``PATH`` (installed via
       ``pip install mtkclient``).
    3. An importable ``mtkclient`` package: we run its ``mtk.py`` with the
       current Python interpreter.

    Raises :class:`MtkClientNotInstalled` if none apply.
    """
    env_bin = os.environ.get("KAERU_MTK_BIN")
    if env_bin:
        parts = tuple(env_bin.split())
        return MtkClientLocation(argv0=parts, source=f"env KAERU_MTK_BIN={env_bin}")

    mtk_path = shutil.which("mtk")
    if mtk_path:
        return MtkClientLocation(argv0=(mtk_path,), source=f"PATH ({mtk_path})")

    try:
        import mtkclient
    except ImportError as e:
        raise MtkClientNotInstalled(
            "mtkclient is not installed. Install it with:\n"
            "    pip install git+https://github.com/bkerler/mtkclient.git\n"
            "or set KAERU_MTK_BIN to a custom mtk command."
        ) from e

    pkg_dir = Path(mtkclient.__file__).resolve().parent.parent
    script = pkg_dir / "mtk.py"
    if not script.is_file():
        raise MtkClientNotInstalled(
            f"mtkclient package found at {pkg_dir} but mtk.py is missing"
        )
    return MtkClientLocation(
        argv0=(sys.executable, str(script)),
        source=f"package import ({script})",
    )


@dataclass
class MtkClientRunner:
    """Build and run mtkclient invocations.

    A runner is configured once with location + auth/loader/preloader
    overrides; individual operations (``read``, ``write``, ``erase``, ...)
    add their own subcommand-specific flags.
    """

    location: MtkClientLocation
    auth: Path | None = None
    loader: Path | None = None
    preloader: Path | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)

    def _global_args(self) -> list[str]:
        out: list[str] = []
        if self.auth is not None:
            out += ["--auth", str(self.auth)]
        if self.loader is not None:
            out += ["--loader", str(self.loader)]
        if self.preloader is not None:
            out += ["--preloader", str(self.preloader)]
        out += list(self.extra_args)
        return out

    def build_argv(self, subcommand: str, args: Iterable[str]) -> list[str]:
        argv: list[str] = list(self.location.argv0)
        argv.append(subcommand)
        argv += list(args)
        argv += self._global_args()
        return argv

    def run(
        self,
        subcommand: str,
        args: Sequence[str] = (),
        *,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        argv = self.build_argv(subcommand, args)
        log.info("running mtkclient: %s", " ".join(argv))
        return subprocess.run(
            argv,
            check=check,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )


__all__ = [
    "MtkClientLocation",
    "MtkClientNotInstalled",
    "MtkClientRunner",
    "locate_mtkclient",
]
