from __future__ import annotations

from typing import Any

from kaeru_mtk.commands._session import open_session_from_args
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

DANGEROUS_PARTITIONS = frozenset(
    {"preloader", "pl", "pl_a", "pl_b", "tee1", "tee2", "lk", "lk_a", "lk_b", "para", "boot_para"}
)


def cmd_erase_partition(args: Any) -> int:
    if not args.partition:
        print("usage: kaeru-mtk erase --partition NAME")
        return 2

    if args.partition in DANGEROUS_PARTITIONS and not args.allow_dangerous:
        raise KaeruError(
            f"refusing to erase '{args.partition}' (high brick risk). "
            "Pass --allow-dangerous to override."
        )

    if args.dry_run:
        log.info("[dry-run] would erase %s", args.partition)
        return 0

    with open_session_from_args(args) as ctx:
        if ctx.da_v6 is None:
            raise KaeruError("erase requires DAv6 with --da and (if locked) --auth-dir.")
        raise KaeruError("DAv6 erase is intentionally gated until protocol confirmation lands.")
