from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UsbId:
    vid: int
    pid: int
    label: str


BROM_USB_IDS: tuple[UsbId, ...] = (
    UsbId(0x0E8D, 0x0003, "MediaTek BROM"),
)

PRELOADER_USB_IDS: tuple[UsbId, ...] = (
    UsbId(0x0E8D, 0x2000, "MediaTek Preloader"),
    UsbId(0x0E8D, 0x2001, "MediaTek Preloader (alt)"),
)

DA_USB_IDS: tuple[UsbId, ...] = (
    UsbId(0x0E8D, 0x0003, "MediaTek DA (BROM-relayed)"),
)


def describe_usb_id(vid: int, pid: int) -> str:
    for table in (BROM_USB_IDS, PRELOADER_USB_IDS, DA_USB_IDS):
        for entry in table:
            if entry.vid == vid and entry.pid == pid:
                return entry.label
    return f"unknown {vid:04x}:{pid:04x}"


def all_known_ids() -> tuple[UsbId, ...]:
    seen: set[tuple[int, int]] = set()
    out: list[UsbId] = []
    for table in (BROM_USB_IDS, PRELOADER_USB_IDS, DA_USB_IDS):
        for e in table:
            key = (e.vid, e.pid)
            if key not in seen:
                seen.add(key)
                out.append(e)
    return tuple(out)
