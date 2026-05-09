from __future__ import annotations

import argparse
import platform

from kaeru_mtk.driver.windows import (
    check_driver_status,
    install_winusb_driver,
    print_driver_help,
)
from kaeru_mtk.utils.errors import DriverError


def status(_args: argparse.Namespace) -> int:
    if platform.system().lower() != "windows":
        print(
            "driver status is Windows-only.\n"
            "On Linux/macOS, libusb is used directly via pyusb; no driver step is needed."
        )
        return 0
    rows = check_driver_status()
    if not rows:
        print("No MTK USB endpoints currently visible to the Windows PnP manager.")
        return 1
    print(f"{'vid:pid':<11} {'driver':<12} {'instance'}")
    print(f"{'-'*11} {'-'*12} {'-'*40}")
    for r in rows:
        drv = r.driver or "<none>"
        ok = "WinUSB" if r.is_winusb else drv
        print(f"{r.vid:04x}:{r.pid:04x}  {ok:<12} {r.instance_id or '-'}")
    return 0


def install(args: argparse.Namespace) -> int:
    try:
        path = install_winusb_driver(launch=not args.no_launch)
    except DriverError as e:
        print(f"error: {e}")
        return 2
    print(f"Zadig at: {path}")
    print_driver_help()
    return 0


__all__ = ["install", "status"]
