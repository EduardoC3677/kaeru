from __future__ import annotations

import argparse

from kaeru_mtk.commands._runner import auto_resolve_auth_bundle, make_runner, run_or_dry_run


def info(args: argparse.Namespace) -> int:
    runner = make_runner(args)
    if not args.dry_run:
        bundle = auto_resolve_auth_bundle(runner)
        if bundle is not None and not args.no_auto_auth:
            runner.auth = bundle.path
    return run_or_dry_run(runner, "gettargetconfig", [], dry_run=args.dry_run)


__all__ = ["info"]
