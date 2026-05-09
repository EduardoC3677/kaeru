from __future__ import annotations

from pathlib import Path
from typing import Any

from kaeru_mtk.commands._session import open_session_from_args
from kaeru_mtk.formats.scatter import parse_scatter
from kaeru_mtk.oneplus.unlock import perform_oneplus_unlock
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_unlock_bl(args: Any) -> int:
    scatter = parse_scatter(Path(args.scatter)) if args.scatter else None

    if not args.confirm_unlock and not args.dry_run:
        raise KaeruError(
            "Bootloader unlock will WIPE userdata and tamper-flag the device. "
            "Pass --confirm-unlock to proceed, or --dry-run to inspect."
        )

    with open_session_from_args(args) as ctx:
        if ctx.da_v6 is None and ctx.da_v5 is None and not args.dry_run:
            raise KaeruError(
                "Unlock requires a loaded DA. Pass --da MTK_AllInOne_DA.bin and --auth-dir."
            )
        result = perform_oneplus_unlock(
            da=ctx.da_v6 or ctx.da_v5,
            scatter=scatter,
            dry_run=args.dry_run,
        )
    log.info("Unlock result: ok=%s method=%s detail=%s", result.ok, result.method, result.detail)
    return 0 if result.ok else 1
