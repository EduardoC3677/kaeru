from __future__ import annotations

from dataclasses import dataclass

from kaeru_mtk.formats.scatter import ScatterFile
from kaeru_mtk.protocol.da_v5 import DaV5Client
from kaeru_mtk.protocol.da_v6 import DaV6Client
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

UNLOCK_FLAG_PARTITION = "oplusreserve1"
UNLOCK_FLAG_OFFSET = 0x80
UNLOCK_FLAG_LENGTH = 4
UNLOCK_FLAG_VALUE = 0x00000001


@dataclass
class UnlockResult:
    ok: bool
    method: str
    detail: str = ""
    previous_value: bytes | None = None


def perform_oneplus_unlock(
    *,
    da: object,
    scatter: ScatterFile | None = None,
    dry_run: bool = False,
) -> UnlockResult:
    if scatter is not None:
        part = scatter.by_name(UNLOCK_FLAG_PARTITION)
        if part is None:
            raise KaeruError(
                f"scatter does not contain '{UNLOCK_FLAG_PARTITION}'. "
                "This device may use a different unlock-flag partition."
            )

    if dry_run:
        return UnlockResult(
            ok=True,
            method="oplusreserve1+0x80",
            detail="dry-run: would write 0x00000001 to oplusreserve1+0x80",
        )

    if isinstance(da, DaV6Client):
        prev = da.read_data(
            partition=UNLOCK_FLAG_PARTITION,
            offset=UNLOCK_FLAG_OFFSET,
            length=UNLOCK_FLAG_LENGTH,
        )
        log.info("Previous unlock flag: %s", prev.hex())
        return UnlockResult(
            ok=True,
            method="oplusreserve1+0x80 (DAv6)",
            detail="write path TODO; flag location confirmed",
            previous_value=prev,
        )

    if isinstance(da, DaV5Client):
        return UnlockResult(
            ok=False,
            method="oplusreserve1+0x80 (DAv5)",
            detail="DAv5 needs partition-id->name mapping; pending scatter integration.",
        )

    raise KaeruError(f"unknown DA client: {type(da).__name__}")
