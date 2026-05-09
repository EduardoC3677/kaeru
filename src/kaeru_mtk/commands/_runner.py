from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from kaeru_mtk.auth.resolver import detect_hwcode_via_mtkclient, resolve_auth
from kaeru_mtk.data.auth_index import AuthBundle
from kaeru_mtk.runner.mtkclient import (
    MtkClientLocation,
    MtkClientNotInstalled,
    MtkClientRunner,
    locate_mtkclient,
)
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def _override_location_from_args(args: argparse.Namespace) -> MtkClientLocation | None:
    bin_arg = getattr(args, "mtk_bin", None)
    if bin_arg:
        os.environ["KAERU_MTK_BIN"] = bin_arg
    return None


def make_runner(
    args: argparse.Namespace,
    *,
    auth_bundle: AuthBundle | None = None,
) -> MtkClientRunner:
    _override_location_from_args(args)
    try:
        loc = locate_mtkclient()
    except MtkClientNotInstalled:
        if getattr(args, "dry_run", False):
            loc = MtkClientLocation(argv0=("mtk",), source="<not installed; dry-run placeholder>")
        else:
            raise

    auth_path: Path | None = None
    explicit = getattr(args, "auth_file", None)
    if explicit:
        auth_path = Path(explicit)
    elif auth_bundle is not None and not getattr(args, "no_auto_auth", False):
        auth_path = auth_bundle.path

    loader = getattr(args, "loader", None)
    preloader = getattr(args, "preloader", None)
    return MtkClientRunner(
        location=loc,
        auth=auth_path,
        loader=Path(loader) if loader else None,
        preloader=Path(preloader) if preloader else None,
    )


def auto_resolve_auth_bundle(runner: MtkClientRunner) -> AuthBundle | None:
    try:
        hw_code = detect_hwcode_via_mtkclient(runner)
    except KaeruError as e:
        log.warning("hwcode auto-detection failed: %s", e)
        return None
    res = resolve_auth(hw_code)
    if res.bundle is None:
        log.info("no bundled auth for hw_code=0x%04x", hw_code)
        return None
    log.info(
        "matched bundled auth: %s (SoC %s, SLA key #%s)",
        res.bundle.path.name,
        res.bundle.soc.name,
        res.bundle.sla_key.index if res.bundle.sla_key else "<none>",
    )
    return res.bundle


def print_command(runner: MtkClientRunner, subcommand: str, args: list[str]) -> None:
    argv = runner.build_argv(subcommand, args)
    print(" ".join(argv))


def run_or_dry_run(
    runner: MtkClientRunner,
    subcommand: str,
    args: list[str],
    *,
    dry_run: bool,
) -> int:
    if dry_run:
        print_command(runner, subcommand, args)
        return 0
    try:
        proc = runner.run(subcommand, args, check=False)
    except MtkClientNotInstalled as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    sys.stdout.write(proc.stdout or "")
    return proc.returncode


__all__ = [
    "auto_resolve_auth_bundle",
    "make_runner",
    "print_command",
    "run_or_dry_run",
]
