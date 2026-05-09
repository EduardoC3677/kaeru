from __future__ import annotations

import struct

from kaeru_mtk.transport.base import Transport
from kaeru_mtk.utils.errors import ProtocolError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class Framing:
    def __init__(self, t: Transport) -> None:
        self._t = t

    def echo_byte(self, b: int) -> int:
        self._t.write(bytes([b & 0xFF]))
        out = self._t.read(1)
        if not out:
            raise ProtocolError(f"echo: no response to 0x{b:02x}")
        return out[0]

    def expect_echo(self, b: int) -> None:
        got = self.echo_byte(b)
        if got != (b & 0xFF):
            raise ProtocolError(f"echo mismatch: sent 0x{b:02x}, got 0x{got:02x}")

    def write_be16(self, value: int) -> None:
        self._t.write(struct.pack(">H", value & 0xFFFF))

    def write_be32(self, value: int) -> None:
        self._t.write(struct.pack(">I", value & 0xFFFFFFFF))

    def read_be16(self, *, timeout_ms: int | None = None) -> int:
        data = self._read_exact(2, timeout_ms=timeout_ms)
        return struct.unpack(">H", data)[0]

    def read_be32(self, *, timeout_ms: int | None = None) -> int:
        data = self._read_exact(4, timeout_ms=timeout_ms)
        return struct.unpack(">I", data)[0]

    def _read_exact(self, n: int, *, timeout_ms: int | None = None) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self._t.read(n - len(out), timeout_ms=timeout_ms)
            if not chunk:
                raise ProtocolError(f"short read: wanted {n}, got {len(out)}")
            out += chunk
        return out

    def write_bytes(self, data: bytes) -> None:
        self._t.write(data)

    def read_bytes(self, n: int, *, timeout_ms: int | None = None) -> bytes:
        return self._read_exact(n, timeout_ms=timeout_ms)
