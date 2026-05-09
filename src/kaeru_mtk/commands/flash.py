from __future__ import annotations

import argparse
from pathlib import Path

from kaeru_mtk.commands._session import wait_for_da
from kaeru_mtk.protocol.da import DaProtocol
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

_SENSITIVE_PARTITIONS = (
    "nvram", "nvdata", "nvcfg", "persist",
    "oplusreserve1", "oplusreserve2", "oplusreserve3",
    "prodnv", "sgpt", "proinfo", "protect1", "protect2",
)


def _connect_da() -> DaProtocol:
    print("Connecting to DA...")
    da = wait_for_da(timeout=30.0)
    if da is None:
        print("DA device not found. Run `kaeru-mtk exploit run` first.")
        raise KaeruError("DA not available")
    da.init()
    return da


def read(args: argparse.Namespace) -> int:
    da = _connect_da()
    data = da.read_partition(args.partition, size=args.size)
    out_path = Path(args.out)
    out_path.write_bytes(data)
    print(f"Read {len(data)} bytes from {args.partition} -> {args.out}")
    da.disconnect()
    return 0


def readall(args: argparse.Namespace) -> int:
    da = _connect_da()
    parts = da.get_partitions()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sensitive_lower = {p.lower() for p in _SENSITIVE_PARTITIONS}

    count = 0
    for part in parts:
        if args.exclude_sensitive and part.name.lower() in sensitive_lower:
            print(f"  Skipping (sensitive): {part.name}")
            continue
        print(f"  Reading {part.name} ({part.size / 1024 / 1024:.1f} MB)...")
        data = da.read_partition(part.name)
        out_path = out_dir / f"{part.name}.bin"
        out_path.write_bytes(data)
        count += 1

    print(f"Read {count} partitions to {args.out_dir}")
    da.disconnect()
    return 0


def write(args: argparse.Namespace) -> int:
    if not args.confirm_brick_risk:
        raise KaeruError(
            "Writing a partition can permanently brick the device. "
            "Re-run with --confirm-brick-risk"
        )
    da = _connect_da()
    image_path = Path(args.image)
    if not image_path.exists():
        raise KaeruError(f"Image not found: {args.image}")
    data = image_path.read_bytes()
    success = da.write_partition(args.partition, data)
    if success:
        print(f"Wrote {len(data)} bytes to {args.partition}")
    else:
        print(f"Write failed for {args.partition}")
    da.disconnect()
    return 0 if success else 1


def erase(args: argparse.Namespace) -> int:
    if not args.confirm_brick_risk:
        raise KaeruError(
            "Erasing a partition can permanently brick the device. "
            "Re-run with --confirm-brick-risk"
        )
    da = _connect_da()
    success = da.erase_partition(args.partition)
    if success:
        print(f"Erased {args.partition}")
    else:
        print(f"Erase failed for {args.partition}")
    da.disconnect()
    return 0 if success else 1


__all__ = ["erase", "read", "readall", "write"]
