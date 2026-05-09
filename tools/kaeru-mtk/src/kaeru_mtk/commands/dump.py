from __future__ import annotations

from pathlib import Path
from typing import Any

from kaeru_mtk.commands._session import open_session
from kaeru_mtk.oneplus.readback import COMMON_READBACK_TARGETS
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_dump_partition(args: Any) -> int:
    if not args.partition:
        print("usage: kaeru-mtk dump --partition NAME --out FILE")
        return 2
    out = Path(args.out) if args.out else Path(f"{args.partition}.bin")
    auth_dir = Path(args.auth_dir) if args.auth_dir else None
    da_path = Path(args.da) if args.da else None

    with open_session(auth_dir=auth_dir, da_path=da_path, skip_auth=args.skip_auth) as ctx:
        if ctx.da_v6 is None and ctx.da_v5 is None:
            raise KaeruError(
                "DA not loaded. Pass --da MTK_AllInOne_DA.bin and (if locked) --auth-dir."
            )
        if ctx.da_v6 is not None:
            data = ctx.da_v6.read_data(
                partition=args.partition, offset=args.offset, length=args.length
            )
        else:
            raise KaeruError(
                "DAv5 readback requires partition-id mapping; pass a scatter via --scatter."
            )

    out.write_bytes(data)
    log.info("Wrote %d bytes to %s", len(data), out)
    return 0


def cmd_readback_all(args: Any) -> int:
    out_dir = Path(args.out_dir) if args.out_dir else Path("readback")
    out_dir.mkdir(parents=True, exist_ok=True)
    auth_dir = Path(args.auth_dir) if args.auth_dir else None
    da_path = Path(args.da) if args.da else None
    targets = list(COMMON_READBACK_TARGETS)
    if args.exclude_sensitive:
        targets = [t for t in targets if not t.sensitive]

    with open_session(auth_dir=auth_dir, da_path=da_path, skip_auth=args.skip_auth) as ctx:
        if ctx.da_v6 is None:
            raise KaeruError("readback requires DAv6; load with --da and --auth-dir")
        for t in targets:
            try:
                data = ctx.da_v6.read_data(partition=t.partition, offset=0, length=args.max_size)
                dest = out_dir / f"{t.partition}.bin"
                dest.write_bytes(data)
                log.info("[OK] %s -> %s (%d B)", t.partition, dest, len(data))
            except Exception as e:
                log.warning("[skip] %s: %s", t.partition, e)
    return 0
