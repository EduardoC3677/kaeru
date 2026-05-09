from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError


class DaBlobParseError(KaeruError):
    pass


DA_MAGIC_V5 = b"MTK_DA_v5"
DA_MAGIC_V6 = b"MTK_DA_v6"
DA_GENERIC_PREFIX = b"MTK_DA"


@dataclass
class DaRegion:
    soc_name: str
    da_offset: int
    da_size: int
    sig_offset: int
    sig_size: int

    @property
    def end(self) -> int:
        return self.da_offset + self.da_size


@dataclass
class DaBlob:
    raw: bytes
    version: int
    regions: list[DaRegion] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return len(self.raw)

    def select_for_soc(self, soc_hwcode: int) -> list[DaRegion]:
        wanted = f"{soc_hwcode:04x}"
        return [r for r in self.regions if wanted in r.soc_name.lower()]


def parse_da_blob(source: str | bytes | Path) -> DaBlob:
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)

    if len(data) < 0x80:
        raise DaBlobParseError(f"DA blob too small: {len(data)} bytes")

    head = data[:0x10]
    if not head.startswith(DA_GENERIC_PREFIX):
        raise DaBlobParseError(f"DA blob magic mismatch: {head!r}")

    if head.startswith(DA_MAGIC_V6):
        version = 6
    elif head.startswith(DA_MAGIC_V5):
        version = 5
    else:
        version = 5

    blob = DaBlob(raw=data, version=version)
    cursor = 0x80
    region_count = struct.unpack_from("<I", data, 0x6C)[0] if len(data) >= 0x70 else 0
    if region_count <= 0 or region_count > 256:
        return blob

    entry_size = 0xDC if version == 5 else 0xE8
    for _ in range(region_count):
        if cursor + entry_size > len(data):
            break
        chunk = data[cursor : cursor + entry_size]
        try:
            soc_name = chunk[:64].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            da_offset, da_size, sig_offset, sig_size = struct.unpack_from("<IIII", chunk, 64)
        except struct.error:
            break
        blob.regions.append(
            DaRegion(
                soc_name=soc_name,
                da_offset=da_offset,
                da_size=da_size,
                sig_offset=sig_offset,
                sig_size=sig_size,
            )
        )
        cursor += entry_size

    return blob
