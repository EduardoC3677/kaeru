from __future__ import annotations

import argparse
import logging
import sys

from kaeru_mtk._version import __version__
from kaeru_mtk.commands import (
    cmd_auth,
    cmd_detect,
    cmd_driver,
    cmd_exploit,
    cmd_flash,
    cmd_info,
    cmd_socs,
    cmd_unlock,
)
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import install_console_logging


def _add_global_runner_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("mtkclient runner")
    g.add_argument("--mtk-bin", help="override mtkclient executable (env: KAERU_MTK_BIN)")
    g.add_argument("--loader", help="path to MediaTek DA blob (forwarded to mtkclient --loader)")
    g.add_argument("--preloader", help="path to preloader blob (forwarded to mtkclient --preloader)")
    g.add_argument(
        "--auth-file",
        help="explicit path to auth_sv5.auth (overrides hwcode-based auto-resolution)",
    )
    g.add_argument(
        "--no-auto-auth",
        action="store_true",
        help="never auto-pick a bundled auth file",
    )


def _add_dry_run(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the mtkclient invocation without executing it",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kaeru-mtk",
        description=(
            "Windows-first OnePlus / OPPO MediaTek flasher.\n"
            "Wraps mtkclient (https://github.com/bkerler/mtkclient) and adds:\n"
            "  - 15 bundled auth_sv5.auth files for MT6763 / 6765 / 6769 / 6771 /\n"
            "    6779 / 6833 / 6853 / 6873 / 6877 / 6885 / 6889 / 6893\n"
            "  - automatic auth selection based on detected hwcode\n"
            "  - the four RSA-2048 SLA public keys extracted from OPlus's\n"
            "    SLA_Challenge.dll, used to label which embedded key your\n"
            "    device's auth modulus matches against\n"
            "  - a Zadig / WinUSB driver helper for Windows hosts\n"
            "Apache-2.0. Educational and security-research use; you can brick your phone."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Workflow:\n"
            "  kaeru-mtk driver install         # Windows: bind WinUSB via Zadig\n"
            "  kaeru-mtk detect                 # list MTK USB endpoints\n"
            "  kaeru-mtk info                   # hwcode + matched bundled auth\n"
            "  kaeru-mtk auth list              # list bundled auth files\n"
            "  kaeru-mtk socs                   # list known SoCs\n"
            "  kaeru-mtk exploit list           # exploits available in mtkclient\n"
            "  kaeru-mtk flash read --partition boot --out boot.bin\n"
            "  kaeru-mtk flash readall --out-dir backup/\n"
            "  kaeru-mtk flash write --partition recovery --image recovery.img\n"
            "  kaeru-mtk flash erase --partition userdata --confirm-brick-risk\n"
            "  kaeru-mtk unlock-bl --confirm-unlock\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v=DEBUG, -vv=trace")
    p.add_argument("--no-rich", action="store_true", help="disable rich/color logging")

    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    pd = sub.add_parser("driver", help="Windows WinUSB / Zadig driver helper")
    pd_sub = pd.add_subparsers(dest="action", required=True, metavar="<action>")
    pd_sub.add_parser("status", help="show driver state for known MTK USB IDs")
    pdi = pd_sub.add_parser("install", help="download Zadig and walk through WinUSB binding")
    pdi.add_argument("--no-launch", action="store_true", help="download only, do not launch Zadig")

    sub.add_parser("detect", help="list MTK USB endpoints currently visible")

    pi = sub.add_parser("info", help="probe device, print hwcode + matched bundled auth")
    _add_global_runner_args(pi)
    _add_dry_run(pi)

    pa = sub.add_parser("auth", help="inspect bundled auth files")
    pa_sub = pa.add_subparsers(dest="action", required=True, metavar="<action>")
    pa_sub.add_parser("list", help="list every bundled auth_sv5.auth and matched SLA key")
    par = pa_sub.add_parser("resolve", help="resolve auth for a given hwcode")
    par.add_argument("hw_code", help="hwcode, decimal or 0x-prefixed hex")

    sub.add_parser("socs", help="list known SoCs (hwcode, family, arch, bundled auth?)")

    pe = sub.add_parser("exploit", help="list / run mtkclient exploits")
    pe_sub = pe.add_subparsers(dest="action", required=True, metavar="<action>")
    pe_sub.add_parser("list", help="show kamakiri/kamakiri2/carbonara/hashimoto/heapbait")
    per = pe_sub.add_parser("run", help="hand off to mtkclient with --ptype")
    per.add_argument(
        "--ptype",
        choices=("kamakiri", "kamakiri2", "carbonara"),
        help="exploit type (mtkclient picks one automatically if omitted)",
    )
    _add_global_runner_args(per)
    _add_dry_run(per)

    pf = sub.add_parser("flash", help="partition I/O via mtkclient")
    pf_sub = pf.add_subparsers(dest="action", required=True, metavar="<action>")

    pfr = pf_sub.add_parser("read", help="read one partition to a file (mtk r)")
    pfr.add_argument("--partition", required=True)
    pfr.add_argument("--out", required=True)
    _add_global_runner_args(pfr)
    _add_dry_run(pfr)

    pfra = pf_sub.add_parser("readall", help="read every partition to a directory (mtk rl)")
    pfra.add_argument("--out-dir", required=True)
    pfra.add_argument(
        "--exclude-sensitive",
        action="store_true",
        help="skip nvram, nvdata, nvcfg, persist, oplusreserve1/2/3, prodnv, sgpt",
    )
    _add_global_runner_args(pfra)
    _add_dry_run(pfra)

    pfw = pf_sub.add_parser("write", help="write a partition from a file (mtk w)")
    pfw.add_argument("--partition", required=True)
    pfw.add_argument("--image", required=True)
    pfw.add_argument(
        "--confirm-brick-risk",
        action="store_true",
        help="required: writing the wrong partition can permanently brick the device",
    )
    _add_global_runner_args(pfw)
    _add_dry_run(pfw)

    pfe = pf_sub.add_parser("erase", help="erase a partition (mtk e)")
    pfe.add_argument("--partition", required=True)
    pfe.add_argument(
        "--confirm-brick-risk",
        action="store_true",
        help="required: erasing the wrong partition can permanently brick the device",
    )
    _add_global_runner_args(pfe)
    _add_dry_run(pfe)

    pu = sub.add_parser("unlock-bl", help="OPPO/OnePlus unlock (writes oplusreserve1)")
    pu.add_argument(
        "--confirm-unlock",
        action="store_true",
        help="required: this voids the warranty and wipes user data",
    )
    pu.add_argument(
        "--allow-dangerous",
        action="store_true",
        help="required: needed in addition to --confirm-unlock",
    )
    _add_global_runner_args(pu)
    _add_dry_run(pu)

    return p


_DISPATCH = {
    ("driver", "status"): cmd_driver.status,
    ("driver", "install"): cmd_driver.install,
    ("detect", None): cmd_detect.detect,
    ("info", None): cmd_info.info,
    ("auth", "list"): cmd_auth.list_bundles,
    ("auth", "resolve"): cmd_auth.resolve,
    ("socs", None): cmd_socs.run,
    ("exploit", "list"): cmd_exploit.list_exploits,
    ("exploit", "run"): cmd_exploit.run,
    ("flash", "read"): cmd_flash.read,
    ("flash", "readall"): cmd_flash.readall,
    ("flash", "write"): cmd_flash.write,
    ("flash", "erase"): cmd_flash.erase,
    ("unlock-bl", None): cmd_unlock.unlock_bl,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose >= 1 else logging.INFO
    install_console_logging(level=level, use_rich=not args.no_rich)

    action = getattr(args, "action", None)
    handler = _DISPATCH.get((args.command, action))
    if handler is None:
        parser.error(f"unknown command/action: {args.command} {action}")

    try:
        return int(handler(args) or 0)
    except KaeruError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
