from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError


class OpsParseError(KaeruError):
    pass


OPS_FOOTER_LEN = 0x200
OPS_FOOTER_MAGIC = 0x7CEF
OPS_FOOTER_MAGIC_OFFSET = 0x10
OPS_FOOTER_VERSION_OFFSET = 0x14
OPS_FOOTER_XML_OFFSET = 0x18
OPS_FOOTER_XML_LEN_OFFSET = 0x20


@dataclass
class OpsFooter:
    raw: bytes
    magic: int
    xml_offset: int
    xml_length: int
    version: int

    @classmethod
    def from_bytes(cls, data: bytes) -> OpsFooter:
        if len(data) < OPS_FOOTER_LEN:
            raise OpsParseError(f"OPS footer too small: {len(data)}")
        magic = struct.unpack_from("<H", data, OPS_FOOTER_MAGIC_OFFSET)[0]
        xml_off = struct.unpack_from("<Q", data, OPS_FOOTER_XML_OFFSET)[0]
        xml_len = struct.unpack_from("<Q", data, OPS_FOOTER_XML_LEN_OFFSET)[0]
        version = struct.unpack_from("<I", data, OPS_FOOTER_VERSION_OFFSET)[0]
        return cls(raw=data, magic=magic, xml_offset=xml_off, xml_length=xml_len, version=version)

    @property
    def magic_ok(self) -> bool:
        return self.magic == OPS_FOOTER_MAGIC


@dataclass
class OpsFile:
    path: Path
    footer: OpsFooter
    encrypted_xml: bytes
    decrypted_xml: bytes | None = None
    partitions: list[dict] = field(default_factory=list)


def parse_ops(source: str | Path) -> OpsFile:
    p = Path(source)
    if not p.is_file():
        raise OpsParseError(f"OPS not found: {p}")
    size = p.stat().st_size
    if size < OPS_FOOTER_LEN:
        raise OpsParseError(f"OPS too small: {size}")

    with open(p, "rb") as fh:
        fh.seek(size - OPS_FOOTER_LEN)
        footer_raw = fh.read(OPS_FOOTER_LEN)
        footer = OpsFooter.from_bytes(footer_raw)
        if not footer.magic_ok:
            raise OpsParseError(
                f"OPS magic mismatch: 0x{footer.magic:04x} (expected 0x{OPS_FOOTER_MAGIC:04x})"
            )

        if footer.xml_offset + footer.xml_length > size - OPS_FOOTER_LEN:
            raise OpsParseError(
                f"OPS XML region out of range: off=0x{footer.xml_offset:x} len=0x{footer.xml_length:x}"
            )

        fh.seek(footer.xml_offset)
        encrypted_xml = fh.read(footer.xml_length)

    return OpsFile(path=p, footer=footer, encrypted_xml=encrypted_xml)
