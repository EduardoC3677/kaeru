from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError


class OfpParseError(KaeruError):
    pass


OFP_MAGIC_QC = b"OPPOENCRYPT!"
OFP_MAGIC_MTK = b"MTK_PUMP_BIN"
OFP_FOOTER_LEN = 0x6C


@dataclass
class OfpEntry:
    name: str
    file_path: str
    offset: int
    size: int
    sha256: str | None = None
    encrypted: bool = False
    extra: dict = field(default_factory=dict)


@dataclass
class OfpHeader:
    magic: bytes
    family: str
    version: str = ""
    project: str = ""
    chip: str = ""


@dataclass
class OfpPackage:
    path: Path
    header: OfpHeader
    entries: list[OfpEntry] = field(default_factory=list)

    def find(self, name: str) -> OfpEntry | None:
        nl = name.lower()
        for e in self.entries:
            if e.name.lower() == nl:
                return e
        return None


def parse_ofp(source: str | Path) -> OfpPackage:
    p = Path(source)
    if not p.exists():
        raise OfpParseError(f"OFP not found: {p}")
    with open(p, "rb") as fh:
        head = fh.read(0x100)
        if not head:
            raise OfpParseError("empty OFP file")

        if zipfile.is_zipfile(p):
            return _parse_ofp_zip(p)

        magic = head[:12]
        if magic == OFP_MAGIC_QC:
            family = "qualcomm"
        elif magic == OFP_MAGIC_MTK:
            family = "mediatek"
        else:
            family = "unknown"

        return OfpPackage(
            path=p,
            header=OfpHeader(magic=magic, family=family),
        )


def _parse_ofp_zip(p: Path) -> OfpPackage:
    pkg = OfpPackage(path=p, header=OfpHeader(magic=b"PK", family="zip"))
    with zipfile.ZipFile(p) as zf:
        for info in zf.infolist():
            pkg.entries.append(
                OfpEntry(
                    name=Path(info.filename).name,
                    file_path=info.filename,
                    offset=info.header_offset,
                    size=info.file_size,
                    encrypted=bool(info.flag_bits & 0x1),
                )
            )
    return pkg
