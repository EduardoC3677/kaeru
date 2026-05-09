from __future__ import annotations

import argparse

from kaeru_mtk.commands._runner import auto_resolve_auth_bundle, make_runner, run_or_dry_run
from kaeru_mtk.utils.errors import KaeruError

_UNLOCK_PARTITION = "oplusreserve1"
_UNLOCK_OFFSET_HINT = (
    "OPLUS unlock state lives inside the oplusreserve1 partition (the exact\n"
    "    `unlock_allowed_flag_offset` is set per-device in the OPlusFlashTool\n"
    "    plugin and the only public reference is the leaked OplusFlashTool DLLs.\n"
    "    kaeru-mtk does NOT bundle an offset list."
)


def unlock_bl(args: argparse.Namespace) -> int:
    if not args.dry_run and not (args.confirm_unlock and args.allow_dangerous):
        raise KaeruError(
            "BL unlock requires both --confirm-unlock and --allow-dangerous.\n"
            "    This wipes user data, voids the warranty, and on most OPPO/OnePlus\n"
            "    devices is permanent (the EFUSE state cannot be reverted).\n"
            f"\n    {_UNLOCK_OFFSET_HINT}"
        )

    runner = make_runner(args)
    if not args.dry_run:
        bundle = auto_resolve_auth_bundle(runner)
        if bundle is not None and not args.no_auto_auth:
            runner.auth = bundle.path

    if args.dry_run:
        from kaeru_mtk.commands._runner import print_command
        print(f"# would read+modify+write {_UNLOCK_PARTITION} via mtkclient r/w")
        print_command(runner, "r", [_UNLOCK_PARTITION, "oplusreserve1.bin"])
        print_command(runner, "w", [_UNLOCK_PARTITION, "oplusreserve1.bin"])
        return 0

    raise KaeruError(
        "non-dry-run BL unlock is intentionally NOT implemented in this release.\n"
        "    The unlock procedure is device-specific (per-product offsets and\n"
        "    structures) and shipping a one-size-fits-all flipper here would\n"
        "    brick devices. Use:\n"
        f"        kaeru-mtk flash read --partition {_UNLOCK_PARTITION} --out reserve1.bin\n"
        "    edit the unlock flag at the offset documented for *your* device,\n"
        "    then:\n"
        f"        kaeru-mtk flash write --partition {_UNLOCK_PARTITION} --image reserve1.bin --confirm-brick-risk"
    )


def run_ext(args: argparse.Namespace) -> int:
    runner = make_runner(args)
    return run_or_dry_run(runner, "reset", [], dry_run=args.dry_run)


__all__ = ["unlock_bl"]
