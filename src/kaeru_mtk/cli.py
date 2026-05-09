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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kaeru-mtk",
        description="MediaTek BROM/DA flashing tool for OPPO/OnePlus devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Workflow:\n"
            "  kaeru-mtk driver install         # Windows: bind WinUSB via Zadig\n"
            "  kaeru-mtk detect                 # list MTK USB endpoints\n"
            "  kaeru-mtk info                   # probe device, show config\n"
            "  kaeru-mtk auth list              # list bundled auth files\n"
            "  kaeru-mtk socs                   # list known SoCs\n"
            "  kaeru-mtk exploit run            # run BROM exploit\n"
            "  kaeru-mtk flash read --partition boot --out boot.bin\n"
            "  kaeru-mtk flash readall --out-dir backup/\n"
            "  kaeru-mtk flash write --partition recovery --image recovery.img\n"
            "  kaeru-mtk flash erase --partition userdata\n"
            "  kaeru-mtk unlock-bl              # OPPO/OnePlus BL unlock\n"
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

    pi = sub.add_parser("info", help="probe device, print BROM config + SoC match")
    pi.add_argument("--auth-file", help="path to auth_sv5.auth for SLA auth attempt")

    pa = sub.add_parser("auth", help="inspect bundled auth files")
    pa_sub = pa.add_subparsers(dest="action", required=True, metavar="<action>")
    pa_sub.add_parser("list", help="list every bundled auth_sv5.auth and matched SLA key")
    par = pa_sub.add_parser("resolve", help="resolve auth for a given hwcode")
    par.add_argument("hw_code", help="hwcode, decimal or 0x-prefixed hex")

    sub.add_parser("socs", help="list known SoCs (hwcode, family, arch, bundled auth?)")

    pe = sub.add_parser("exploit", help="BROM exploits")
    pe_sub = pe.add_subparsers(dest="action", required=True, metavar="<action>")
    pe_sub.add_parser("list", help="show available exploits")
    per = pe_sub.add_parser("run", help="run BROM exploit on connected device")
    per.add_argument(
        "--exploit",
        choices=("kamakiri", "kamakiri2", "carbonara", "hashimoto", "heapbait"),
        help="exploit to use (auto-detected from arch if omitted)",
    )
    per.add_argument("--payload", help="path to custom shellcode payload")
    per.add_argument("--wait-da", type=float, default=30.0, help="seconds to wait for DA after exploit")

    pf = sub.add_parser("flash", help="partition I/O via DA protocol")
    pf_sub = pf.add_subparsers(dest="action", required=True, metavar="<action>")

    pfr = pf_sub.add_parser("read", help="read one partition to a file")
    pfr.add_argument("--partition", required=True)
    pfr.add_argument("--out", required=True)
    pfr.add_argument("--size", type=int, default=0, help="bytes to read (0 = full partition)")

    pfra = pf_sub.add_parser("readall", help="read every partition to a directory")
    pfra.add_argument("--out-dir", required=True)
    pfra.add_argument("--exclude-sensitive", action="store_true", help="skip nvram, nvdata, etc.")

    pfw = pf_sub.add_parser("write", help="write a partition from a file")
    pfw.add_argument("--partition", required=True)
    pfw.add_argument("--image", required=True)
    pfw.add_argument("--confirm-brick-risk", action="store_true", help="required: can brick device")

    pfe = pf_sub.add_parser("erase", help="erase a partition")
    pfe.add_argument("--partition", required=True)
    pfe.add_argument("--confirm-brick-risk", action="store_true", help="required: can brick device")

    pu = sub.add_parser("unlock-bl", help="OPPO/OnePlus BL unlock")
    pu.add_argument("--confirm-unlock", action="store_true", help="required: voids warranty")
    pu.add_argument("--allow-dangerous", action="store_true", help="required: additional confirmation")
    pu.add_argument("--auth-file", help="path to auth_sv5.auth")

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
    ("exploit", "run"): cmd_exploit.run_exploit,
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
