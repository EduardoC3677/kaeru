from __future__ import annotations

from pathlib import Path
from typing import Any

from kaeru_mtk.commands._session import open_session
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

PROINFO_PARTITION = "proinfo"
IMEI_OFFSETS = (0x00, 0x10)
IMEI_LEN = 16


def cmd_diag_imei(args: Any) -> int:
    auth_dir = Path(args.auth_dir) if args.auth_dir else None
    da_path = Path(args.da) if args.da else None
    with open_session(auth_dir=auth_dir, da_path=da_path, skip_auth=args.skip_auth) as ctx:
        if ctx.da_v6 is None:
            raise KaeruError("imei read requires DAv6 with --da")
        for off in IMEI_OFFSETS:
            data = ctx.da_v6.read_data(partition=PROINFO_PARTITION, offset=off, length=IMEI_LEN)
            log.info("proinfo+0x%02x: %s", off, data.hex())
    return 0
