from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from kaeru_mtk.protocol.frame import Framing
from kaeru_mtk.transport.base import Transport
from kaeru_mtk.utils.errors import ProtocolError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class DaV5Cmd(IntEnum):
    GET_DA_VERSION = 0xFE
    GET_BMT_INFO = 0x51
    GET_PROJECT_ID = 0x55
    GET_FW_VERSION = 0x56
    DOWNLOAD = 0x58
    READBACK = 0x59
    FORMAT = 0x5A
    BOOT_TO = 0x57
    PROGRESS_QUERY = 0x52
    DA_HW_INIT = 0x60
    SET_BOOT_REGION = 0x61
    SET_RUNTIME_PARAMETER = 0x62


@dataclass
class DaV5Info:
    version: int
    raw: bytes


class DaV5Client:
    def __init__(self, t: Transport) -> None:
        self._t = t
        self._f = Framing(t)

    def hello(self) -> DaV5Info:
        self._f.expect_echo(int(DaV5Cmd.GET_DA_VERSION))
        ver = self._f.read_be32()
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv5 hello status=0x{status:04x}")
        return DaV5Info(version=ver, raw=struct.pack(">I", ver))

    def readback(self, *, ut_partition_id: int, offset: int, length: int) -> bytes:
        self._f.expect_echo(int(DaV5Cmd.READBACK))
        self._f.write_be32(ut_partition_id)
        self._f.write_be32(offset & 0xFFFFFFFF)
        self._f.write_be32((offset >> 32) & 0xFFFFFFFF)
        self._f.write_be32(length & 0xFFFFFFFF)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv5 READBACK init status=0x{status:04x}")
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
            raise ProtocolError(f"DAv5 READBACK end status=0x{end:04x}")
        return bytes(out)

    def format_partition(self, *, ut_partition_id: int, offset: int, length: int) -> None:
        self._f.expect_echo(int(DaV5Cmd.FORMAT))
        self._f.write_be32(ut_partition_id)
        self._f.write_be32(offset & 0xFFFFFFFF)
        self._f.write_be32(length & 0xFFFFFFFF)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv5 FORMAT init status=0x{status:04x}")
        end = self._f.read_be16()
        if end != 0:
            raise ProtocolError(f"DAv5 FORMAT end status=0x{end:04x}")

    def download(self, *, ut_partition_id: int, offset: int, payload: bytes) -> None:
        self._f.expect_echo(int(DaV5Cmd.DOWNLOAD))
        self._f.write_be32(ut_partition_id)
        self._f.write_be32(offset & 0xFFFFFFFF)
        self._f.write_be32(len(payload))
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"DAv5 DOWNLOAD init status=0x{status:04x}")
        chunk = 0x10000
        for i in range(0, len(payload), chunk):
            self._f.write_bytes(payload[i : i + chunk])
        end = self._f.read_be16()
        if end != 0:
            raise ProtocolError(f"DAv5 DOWNLOAD end status=0x{end:04x}")
