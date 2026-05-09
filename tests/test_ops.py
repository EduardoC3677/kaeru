from __future__ import annotations

import struct
from pathlib import Path

import pytest

from kaeru_mtk.formats.ops import (
    OPS_FOOTER_LEN,
    OPS_FOOTER_MAGIC,
    OPS_FOOTER_MAGIC_OFFSET,
    OPS_FOOTER_VERSION_OFFSET,
    OPS_FOOTER_XML_LEN_OFFSET,
    OPS_FOOTER_XML_OFFSET,
    OpsParseError,
    parse_ops,
)


def _build_ops(tmp_path: Path, *, xml: bytes, version: int = 1, magic: int = OPS_FOOTER_MAGIC) -> Path:
    body = b"\xaa" * 0x100
    xml_offset = len(body)
    body += xml

    footer = bytearray(OPS_FOOTER_LEN)
    struct.pack_into("<H", footer, OPS_FOOTER_MAGIC_OFFSET, magic)
    struct.pack_into("<Q", footer, OPS_FOOTER_XML_OFFSET, xml_offset)
    struct.pack_into("<Q", footer, OPS_FOOTER_XML_LEN_OFFSET, len(xml))
    struct.pack_into("<I", footer, OPS_FOOTER_VERSION_OFFSET, version)

    out = tmp_path / "fake.ops"
    out.write_bytes(body + bytes(footer))
    return out


def test_parse_valid_footer(tmp_path):
    xml = b"<?xml version='1.0'?><manifest></manifest>"
    p = _build_ops(tmp_path, xml=xml)
    ops = parse_ops(p)
    assert ops.footer.magic_ok
    assert ops.footer.xml_length == len(xml)
    assert ops.encrypted_xml == xml


def test_bad_magic(tmp_path):
    xml = b"<x/>"
    p = _build_ops(tmp_path, xml=xml, magic=0xDEAD)
    with pytest.raises(OpsParseError):
        parse_ops(p)


def test_too_small(tmp_path):
    p = tmp_path / "tiny.ops"
    p.write_bytes(b"\x00" * 16)
    with pytest.raises(OpsParseError):
        parse_ops(p)
