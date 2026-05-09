from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UsbId:
    vid: int
    pid: int
    label: str


_KNOWN: tuple[UsbId, ...] = (
    UsbId(vid=0x0E8D, pid=0x0003, label="MediaTek BROM"),
    UsbId(vid=0x0E8D, pid=0x2000, label="MediaTek Preloader"),
    UsbId(vid=0x0E8D, pid=0x2001, label="MediaTek Preloader (alt)"),
    UsbId(vid=0x0E8D, pid=0x6000, label="MediaTek DA"),
)


def all_known_ids() -> tuple[UsbId, ...]:
    return _KNOWN


__all__ = ["UsbId", "all_known_ids"]
