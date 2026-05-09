from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError


class ScatterParseError(KaeruError):
    pass


@dataclass
class PartitionEntry:
    name: str
    file_name: str | None = None
    is_download: bool = True
    type: str | None = None
    linear_start_addr: int | None = None
    physical_start_addr: int | None = None
    partition_size: int | None = None
    region: str | None = None
    storage: str | None = None
    boundary_check: bool | None = None
    is_reserved: bool = False
    operation_type: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class ScatterFile:
    project: str | None = None
    storage: str | None = None
    platform: str | None = None
    raw_yaml: str = ""
    partitions: list[PartitionEntry] = field(default_factory=list)

    def by_name(self, name: str) -> PartitionEntry | None:
        nl = name.lower()
        for p in self.partitions:
            if p.name.lower() == nl:
                return p
        return None

    def names(self) -> list[str]:
        return [p.name for p in self.partitions]


_NUM_PREFIXES = ("0x", "0X")


def _parse_int(text: str) -> int | None:
    s = text.strip()
    if not s:
        return None
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    if any(s.startswith(p) for p in _NUM_PREFIXES):
        try:
            v = int(s, 16)
        except ValueError:
            return None
    else:
        try:
            v = int(s, 10)
        except ValueError:
            return None
    return -v if neg else v


def _parse_bool(text: str) -> bool | None:
    s = text.strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def parse_scatter(source: str | bytes | Path) -> ScatterFile:
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8", errors="replace")
    elif isinstance(source, bytes):
        text = source.decode("utf-8", errors="replace")
    else:
        text = source

    sf = ScatterFile(raw_yaml=text)
    current: dict | None = None
    pending_partitions: list[dict] = []

    in_partition_index = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- partition_index:"):
            if current is not None:
                pending_partitions.append(current)
            current = {"partition_index": stripped.split(":", 1)[1].strip()}
            in_partition_index = True
            continue
        if stripped.startswith("############################################################################################################"):
            continue
        if stripped == "general:":
            in_partition_index = False
            current = None
            continue

        if ":" not in stripped:
            continue

        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if in_partition_index and current is not None:
            current[key] = value
            continue

        if key == "project":
            sf.project = value
        elif key == "platform":
            sf.platform = value
        elif key == "storage":
            sf.storage = value

    if current is not None:
        pending_partitions.append(current)

    for raw in pending_partitions:
        sf.partitions.append(_to_partition(raw))

    return sf


def _to_partition(raw: dict) -> PartitionEntry:
    name = raw.get("partition_name") or raw.get("partition_index") or ""
    name = name.strip()
    pe = PartitionEntry(name=name, raw=raw)
    pe.file_name = raw.get("file_name") or None
    pe.type = raw.get("type") or None
    pe.region = raw.get("region") or None
    pe.storage = raw.get("storage") or None
    pe.operation_type = raw.get("operation_type") or None
    pe.linear_start_addr = _parse_int(raw.get("linear_start_addr", "")) if raw.get("linear_start_addr") else None
    pe.physical_start_addr = _parse_int(raw.get("physical_start_addr", "")) if raw.get("physical_start_addr") else None
    pe.partition_size = _parse_int(raw.get("partition_size", "")) if raw.get("partition_size") else None
    pe.boundary_check = _parse_bool(raw.get("boundary_check", "")) if raw.get("boundary_check") else None
    is_dl = raw.get("is_download")
    if is_dl is not None:
        b = _parse_bool(is_dl)
        if b is not None:
            pe.is_download = b
    is_res = raw.get("is_reserved")
    if is_res is not None:
        b = _parse_bool(is_res)
        if b is not None:
            pe.is_reserved = b
    return pe


def filter_flashable(parts: Iterable[PartitionEntry]) -> list[PartitionEntry]:
    return [p for p in parts if p.is_download and not p.is_reserved and p.file_name and p.file_name.upper() != "NONE"]
