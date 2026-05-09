from __future__ import annotations

import argparse

from kaeru_mtk.commands._session import open_brom_session, wait_for_da
from kaeru_mtk.data.soc_db import find_by_hwcode
from kaeru_mtk.utils.errors import DeviceNotFoundError, KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

_UNLOCK_PARTITION = "oplusreserve1"
_UNLOCK_OFFSETS: dict[str, int] = {
    "MT6877": 0x1A4,
    "MT6893": 0x1A4,
    "MT6885": 0x1A4,
    "MT6889": 0x1A4,
    "MT6833": 0x1A4,
    "MT6853": 0x1A4,
    "MT6873": 0x1A4,
    "MT6763": 0x1A4,
    "MT6765": 0x1A4,
    "MT6769": 0x1A4,
    "MT6771": 0x1A4,
    "MT6779": 0x1A4,
}


def unlock_bl(args: argparse.Namespace) -> int:
    if not (args.confirm_unlock and args.allow_dangerous):
        raise KaeruError(
            "BL unlock requires both --confirm-unlock and --allow-dangerous.\n"
            "    This wipes user data, voids the warranty, and on most OPPO/OnePlus\n"
            "    devices is permanent (the EFUSE state cannot be reverted)."
        )

    try:
        session = open_brom_session()
    except DeviceNotFoundError as e:
        print(f"error: {e}")
        return 1

    config = session.config
    if config is None:
        print("error: could not get target config")
        session.close()
        return 1

    socs = find_by_hwcode(config.hw_code)
    soc_name = socs[0].name if socs else f"0x{config.hw_code:04x}"
    print(f"Device: {soc_name} (hw_code=0x{config.hw_code:04x})")

    offset = _UNLOCK_OFFSETS.get(socs[0].name if socs else "")
    if offset is None:
        print(f"Warning: no known unlock offset for {soc_name}")
        print("Defaulting to offset 0x1A4 (common OPPO/OnePlus offset)")
        offset = 0x1A4

    session.close()

    print("Connecting to DA for partition I/O...")
    da = wait_for_da(timeout=30.0)
    if da is None:
        print("DA not found. Run `kaeru-mtk exploit run` first.")
        return 1

    da.init()
    print(f"Reading {_UNLOCK_PARTITION}...")
    data = da.read_partition(_UNLOCK_PARTITION)

    if len(data) < offset + 1:
        raise KaeruError(f"Partition too small: {len(data)} bytes, need offset 0x{offset:x}")

    orig = data[offset]
    data_list = bytearray(data)
    data_list[offset] = 0x00
    patched = bytes(data_list)

    print(f"Unlock flag at offset 0x{offset:x}: 0x{orig:02x} -> 0x00")

    print(f"Writing patched {_UNLOCK_PARTITION}...")
    success = da.write_partition(_UNLOCK_PARTITION, patched)
    if success:
        print("BL unlock flag written successfully!")
        print("Reboot the device for changes to take effect.")
    else:
        print("Failed to write unlock flag.")
        da.disconnect()
        return 1

    da.disconnect()
    return 0


__all__ = ["unlock_bl"]
