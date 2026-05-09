from __future__ import annotations

import argparse

from kaeru_mtk.commands._runner import auto_resolve_auth_bundle, make_runner, run_or_dry_run
from kaeru_mtk.utils.errors import KaeruError

_SENSITIVE_PARTITIONS = (
    "nvram",
    "nvdata",
    "nvcfg",
    "persist",
    "oplusreserve1",
    "oplusreserve2",
    "oplusreserve3",
    "prodnv",
    "sgpt",
    "proinfo",
    "protect1",
    "protect2",
)


def _prep(args: argparse.Namespace):
    runner = make_runner(args)
    if not args.dry_run:
        bundle = auto_resolve_auth_bundle(runner)
        if bundle is not None and not args.no_auto_auth:
            runner.auth = bundle.path
    return runner


def read(args: argparse.Namespace) -> int:
    runner = _prep(args)
    return run_or_dry_run(
        runner, "r", [args.partition, args.out], dry_run=args.dry_run
    )


def readall(args: argparse.Namespace) -> int:
    runner = _prep(args)
    forwarded = [args.out_dir]
    if args.exclude_sensitive:
        forwarded += ["--skip", ",".join(_SENSITIVE_PARTITIONS)]
    return run_or_dry_run(runner, "rl", forwarded, dry_run=args.dry_run)


def write(args: argparse.Namespace) -> int:
    if not args.confirm_brick_risk and not args.dry_run:
        raise KaeruError(
            "writing a partition can permanently brick the device. Re-run with "
            "--confirm-brick-risk (or --dry-run to preview the mtkclient command)."
        )
    runner = _prep(args)
    return run_or_dry_run(
        runner, "w", [args.partition, args.image], dry_run=args.dry_run
    )


def erase(args: argparse.Namespace) -> int:
    if not args.confirm_brick_risk and not args.dry_run:
        raise KaeruError(
            "erasing a partition can permanently brick the device. Re-run with "
            "--confirm-brick-risk (or --dry-run to preview the mtkclient command)."
        )
    runner = _prep(args)
    return run_or_dry_run(runner, "e", [args.partition], dry_run=args.dry_run)


__all__ = ["erase", "read", "readall", "write"]
