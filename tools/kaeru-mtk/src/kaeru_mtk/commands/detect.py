from __future__ import annotations

from typing import Any

from kaeru_mtk.transport import UsbTransport
from kaeru_mtk.transport.identifiers import all_known_ids, describe_usb_id
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_detect(args: Any) -> int:
    transport = UsbTransport()
    devices = transport.list_devices()
    if not devices:
        ids = ", ".join(f"{e.vid:04x}:{e.pid:04x} ({e.label})" for e in all_known_ids())
        print("No MediaTek devices currently enumerated.")
        print(f"Looked for: {ids}")
        print()
        print("Hints:")
        print("  - Power phone OFF first.")
        print("  - Hold Vol-Down (or Vol-Up + Vol-Down) and connect USB-C.")
        print("  - On Windows: run `kaeru-mtk driver install` to set up WinUSB via Zadig.")
        return 1
    print(f"Found {len(devices)} MediaTek device(s):")
    for d in devices:
        print(
            f"  {d.vid:04x}:{d.pid:04x}  {describe_usb_id(d.vid, d.pid)}  "
            f"bus={d.bus}  addr={d.address}  serial={d.serial!r}"
        )
    return 0
