from __future__ import annotations

import argparse
import platform

from kaeru_mtk.data.usb_ids import all_known_ids
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def _enumerate_libusb() -> list[tuple[int, int, str]]:
    try:
        import usb.core
    except ImportError:
        log.warning("pyusb is not installed; skipping libusb enumeration")
        return []
    found: list[tuple[int, int, str]] = []
    for entry in all_known_ids():
        for dev in usb.core.find(find_all=True, idVendor=entry.vid, idProduct=entry.pid) or []:
            try:
                manuf = usb.util.get_string(dev, dev.iManufacturer) or ""
                product = usb.util.get_string(dev, dev.iProduct) or ""
                desc = f"{manuf} {product}".strip() or entry.label
            except Exception:
                desc = entry.label
            found.append((entry.vid, entry.pid, desc))
    return found


def detect(_args: argparse.Namespace) -> int:
    print(f"host: {platform.system()} {platform.release()} ({platform.machine()})")
    print()
    print("Known MediaTek USB endpoints:")
    for entry in all_known_ids():
        print(f"  {entry.vid:04x}:{entry.pid:04x}  {entry.label}")

    enum = _enumerate_libusb()
    print()
    if not enum:
        print("No MTK device currently visible to libusb.")
        print()
        print("If you are on Windows and the device IS plugged in:")
        print("  - run `kaeru-mtk driver status` to see which driver Windows bound")
        print("  - if it is not WinUSB, run `kaeru-mtk driver install`")
        return 0

    print("Currently visible:")
    for vid, pid, desc in enum:
        print(f"  {vid:04x}:{pid:04x}  {desc}")
    return 0


__all__ = ["detect"]
