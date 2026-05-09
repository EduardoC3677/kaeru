from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from kaeru_mtk.protocol.frame import Framing
from kaeru_mtk.transport.base import Transport
from kaeru_mtk.utils.errors import ProtocolError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class DaV6Cmd(IntEnum):
    HELLO = 0x6800
    SECURE_INIT = 0x6801
    SETUP_HW_INIT = 0x6802
    SETUP_ENV = 0x6803
    DEVICE_CTRL = 0x6810
    GET_HW_INFO = 0x6811
    GET_SYS_PROPERTY = 0x6812
    READ_DATA = 0x6830
    WRITE_DATA = 0x6831
    FORMAT_DATA = 0x6832
    SHUTDOWN = 0x6840


@dataclass
class DaV6Hello:
    da_version: int
    flash_id: bytes
    flash_size: int
    raw: bytes


class DaV6Client:
    def __init__(self, t: Transport) -> None:
        self._t = t
        self._f = Framing(t)

    def hello(self) -> DaV6Hello:
        self._f.write_be16(int(DaV6Cmd.HELLO))
        ack = self._f.read_be16()
        if ack != int(DaV6Cmd.HELLO):
            raise ProtocolError(f"DAv6 HELLO ack mismatch 0x{ack:04x}")
        ver = self._f.read_be32()
        flash_id = self._f.read_bytes(16)
        flash_size = self._f.read_be32() | (self._f.read_be32() << 32)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv6 hello status=0x{status:04x}")
        return DaV6Hello(da_version=ver, flash_id=flash_id, flash_size=flash_size, raw=b"")

    def read_data(self, *, partition: str, offset: int, length: int) -> bytes:
        name_b = partition.encode("utf-8") + b"\x00"
        self._f.write_be16(int(DaV6Cmd.READ_DATA))
        self._f.write_be32(len(name_b))
        self._f.write_bytes(name_b)
        self._f.write_be32(offset & 0xFFFFFFFF)
        self._f.write_be32((offset >> 32) & 0xFFFFFFFF)
        self._f.write_be32(length & 0xFFFFFFFF)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv6 READ_DATA init status=0x{status:04x}")
        out = bytearray()
        remaining = length
        while remaining:
            chunk = self._t.read(min(remaining, 0x10000))
            if not chunk:
                break
            out.extend(chunk)
            remaining -= len(chunk)
        end = self._f.read_be16()
        if end != 0:
            raise ProtocolError(f"DAv6 READ_DATA end status=0x{end:04x}")
        return bytes(out)
