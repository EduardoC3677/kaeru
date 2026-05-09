from __future__ import annotations

from pathlib import Path
from typing import Any

from kaeru_mtk.commands._session import open_session
from kaeru_mtk.formats.ofp import parse_ofp
from kaeru_mtk.formats.scatter import filter_flashable, parse_scatter
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


def cmd_flash_partition(args: Any) -> int:
    if not args.partition or not args.image:
        print("usage: kaeru-mtk flash partition --partition NAME --image FILE")
        return 2
    image = Path(args.image)
    if not image.is_file():
        raise KaeruError(f"image not found: {image}")
    auth_dir = Path(args.auth_dir) if args.auth_dir else None
    da_path = Path(args.da) if args.da else None
    payload = image.read_bytes()
    log.info("Will flash %s (%d B) -> %s", image, len(payload), args.partition)

    if args.dry_run:
        log.info("[dry-run] no write performed")
        return 0

    with open_session(auth_dir=auth_dir, da_path=da_path, skip_auth=args.skip_auth) as ctx:
        if ctx.da_v6 is None:
            raise KaeruError("flash requires DAv6 (DAv5 path needs scatter id mapping).")
        raise KaeruError("DAv6 WRITE_DATA path is intentionally gated. Pass --i-know-what-im-doing")
    return 0


def cmd_flash_scatter(args: Any) -> int:
    scatter_file = Path(args.scatter)
    if not scatter_file.is_file():
        raise KaeruError(f"scatter not found: {scatter_file}")
    sf = parse_scatter(scatter_file)
    flashable = filter_flashable(sf.partitions)
    log.info("scatter: project=%s storage=%s partitions=%d (flashable=%d)",
             sf.project, sf.storage, len(sf.partitions), len(flashable))
    for p in flashable:
        log.info(
            "  -> %-20s file=%-30s size=%s",
            p.name,
            p.file_name,
            f"0x{p.partition_size:x}" if p.partition_size else "?",
        )
    if args.dry_run:
        log.info("[dry-run] no flash performed")
        return 0
    raise KaeruError(
        "Full scatter flash is gated behind --confirm-brick-risk. Use partition-level flash for now."
    )


def cmd_flash_ofp(args: Any) -> int:
    ofp_file = Path(args.ofp)
    if not ofp_file.is_file():
        raise KaeruError(f"OFP not found: {ofp_file}")
    pkg = parse_ofp(ofp_file)
    log.info("OFP family=%s magic=%r entries=%d", pkg.header.family, pkg.header.magic, len(pkg.entries))
    if pkg.header.family in ("unknown", "qualcomm"):
        raise KaeruError(
            f"OFP family={pkg.header.family} is not supported by the MTK path. "
            "Run `kaeru-mtk ofp inspect` to see structure."
        )
    if not pkg.entries:
        log.warning("OFP parsed but no entries discovered. Decryption may be required.")
    if args.dry_run:
        return 0
    raise KaeruError("OFP flashing path requires decryption keys. Use --extract-only for now.")
