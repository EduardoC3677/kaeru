from __future__ import annotations

from typing import Any

from kaeru_mtk.driver import check_driver_status, install_winusb_driver, print_driver_help
from kaeru_mtk.utils.errors import DriverError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_driver_status(args: Any) -> int:
    statuses = check_driver_status()
    if not statuses:
        print("No MTK USB endpoints currently enumerated.")
        return 1
    print("MediaTek USB devices on this host:")
    for s in statuses:
        present = "PRESENT" if s.present else "absent"
        print(
            f"  {s.vid:04x}:{s.pid:04x}  {present}  driver={s.driver!r}  "
            f"is_winusb={s.is_winusb}  instance={s.instance_id}"
        )
    return 0


def cmd_driver_install(args: Any) -> int:
    try:
        path = install_winusb_driver(launch=not args.no_launch)
    except DriverError as e:
        log.error("%s", e)
        return 1
    print(f"Zadig at: {path}")
    print_driver_help()
    return 0
