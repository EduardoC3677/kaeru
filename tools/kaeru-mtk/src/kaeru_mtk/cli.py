from __future__ import annotations

import argparse
import logging
import sys

from kaeru_mtk._version import __version__
from kaeru_mtk.commands import (
    cmd_detect,
    cmd_diag_imei,
    cmd_driver_install,
    cmd_driver_status,
    cmd_dump_partition,
    cmd_erase_partition,
    cmd_flash_ofp,
    cmd_flash_partition,
    cmd_flash_scatter,
    cmd_info,
    cmd_readback_all,
    cmd_unlock_bl,
)
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import install_console_logging


def _add_session_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--da", help="path to MTK_AllInOne_DA.bin (or oplus DA blob)")
    p.add_argument("--auth-dir", help="directory containing per-platform auth_sv5.auth (e.g. MTKResource/)")
    p.add_argument(
        "--skip-auth",
        action="store_true",
        help="do not load auth_sv5 even if device target_config requests SLA",
    )


def _add_dry_run(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dry-run", action="store_true", help="parse/probe only, no device writes")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kaeru-mtk",
        description=(
            "Open-source MediaTek BROM/DA flasher for OnePlus / OPPO devices.\n"
            "Apache-2.0. Educational and security-research use; you can brick your phone."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Common workflows:\n"
            "  kaeru-mtk driver install        # Windows: install WinUSB via Zadig\n"
            "  kaeru-mtk detect                # see if device is in BROM mode\n"
            "  kaeru-mtk info --da DA.bin --auth-dir MTKResource\n"
            "  kaeru-mtk dump --partition oplusreserve1 --out reserve1.bin --da DA.bin --auth-dir MTKResource\n"
            "  kaeru-mtk readback-all --out-dir backup/ --da DA.bin --auth-dir MTKResource --exclude-sensitive\n"
            "  kaeru-mtk unlock-bl --confirm-unlock --da DA.bin --auth-dir MTKResource\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v=DEBUG, -vv=trace")
    p.add_argument("--no-rich", action="store_true", help="disable rich/color logging")

    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    p_det = sub.add_parser("detect", help="enumerate connected MTK BROM/Preloader devices")
    p_det.set_defaults(func=cmd_detect)

    p_inf = sub.add_parser("info", help="probe target: hwcode, sw version, target_config, ME-ID")
    _add_session_args(p_inf)
    p_inf.set_defaults(func=cmd_info)

    p_dump = sub.add_parser("dump", help="read a single partition to file")
    _add_session_args(p_dump)
    p_dump.add_argument("--partition", required=True, help="partition name (e.g. boot, vbmeta, oplusreserve1)")
    p_dump.add_argument("--out", help="output file (default: <partition>.bin)")
    p_dump.add_argument("--offset", type=lambda s: int(s, 0), default=0, help="byte offset within partition")
    p_dump.add_argument("--length", type=lambda s: int(s, 0), default=0x100000, help="bytes to read")
    p_dump.set_defaults(func=cmd_dump_partition)

    p_rb = sub.add_parser("readback-all", help="dump common partitions to a directory")
    _add_session_args(p_rb)
    p_rb.add_argument("--out-dir", default="readback", help="output directory")
    p_rb.add_argument("--max-size", type=lambda s: int(s, 0), default=0x800000, help="cap per-partition")
    p_rb.add_argument("--exclude-sensitive", action="store_true", help="skip proinfo/protect/frp")
    p_rb.set_defaults(func=cmd_readback_all)

    p_flash = sub.add_parser("flash", help="flash a partition or a full scatter / OFP")
    flash_sub = p_flash.add_subparsers(dest="flash_subcmd", required=True)

    p_fp = flash_sub.add_parser("partition", help="flash a single partition image")
    _add_session_args(p_fp)
    _add_dry_run(p_fp)
    p_fp.add_argument("--partition", required=True)
    p_fp.add_argument("--image", required=True)
    p_fp.add_argument("--i-know-what-im-doing", dest="confirm", action="store_true")
    p_fp.set_defaults(func=cmd_flash_partition)

    p_fs = flash_sub.add_parser("scatter", help="parse and (eventually) flash from a scatter file")
    _add_session_args(p_fs)
    _add_dry_run(p_fs)
    p_fs.add_argument("--scatter", required=True)
    p_fs.add_argument("--confirm-brick-risk", action="store_true")
    p_fs.set_defaults(func=cmd_flash_scatter)

    p_fo = flash_sub.add_parser("ofp", help="flash from a OnePlus OFP package")
    _add_session_args(p_fo)
    _add_dry_run(p_fo)
    p_fo.add_argument("--ofp", required=True)
    p_fo.add_argument("--extract-only", action="store_true")
    p_fo.set_defaults(func=cmd_flash_ofp)

    p_unlock = sub.add_parser("unlock-bl", help="OnePlus / OPPO bootloader unlock (BROM path)")
    _add_session_args(p_unlock)
    _add_dry_run(p_unlock)
    p_unlock.add_argument("--scatter", help="optional scatter file for partition lookup")
    p_unlock.add_argument("--confirm-unlock", action="store_true", help="REQUIRED. Wipes userdata.")
    p_unlock.set_defaults(func=cmd_unlock_bl)

    p_erase = sub.add_parser("erase", help="erase a partition (DA-side format)")
    _add_session_args(p_erase)
    _add_dry_run(p_erase)
    p_erase.add_argument("--partition", required=True)
    p_erase.add_argument("--allow-dangerous", action="store_true", help="allow erasing pl/lk/preloader")
    p_erase.set_defaults(func=cmd_erase_partition)

    p_diag = sub.add_parser("diag", help="diagnostic / read IMEI from proinfo")
    diag_sub = p_diag.add_subparsers(dest="diag_subcmd", required=True)
    p_imei = diag_sub.add_parser("imei", help="read IMEI from proinfo partition")
    _add_session_args(p_imei)
    p_imei.set_defaults(func=cmd_diag_imei)

    p_drv = sub.add_parser("driver", help="WinUSB driver helpers (Windows)")
    drv_sub = p_drv.add_subparsers(dest="driver_subcmd", required=True)
    p_drv_status = drv_sub.add_parser("status", help="show driver bound to MTK USB endpoints")
    p_drv_status.set_defaults(func=cmd_driver_status)
    p_drv_install = drv_sub.add_parser("install", help="download Zadig and guide WinUSB install")
    p_drv_install.add_argument("--no-launch", action="store_true", help="download only; don't open Zadig")
    p_drv_install.set_defaults(func=cmd_driver_install)

    return p


def _setup_logging(args: argparse.Namespace) -> None:
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose == 1:
        level = logging.INFO
    install_console_logging(level=level, use_rich=not args.no_rich)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args)
    try:
        return int(args.func(args) or 0)
    except KaeruError as e:
        logging.getLogger("kaeru_mtk").error("%s", e)
        return 2
    except KeyboardInterrupt:
        logging.getLogger("kaeru_mtk").warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
