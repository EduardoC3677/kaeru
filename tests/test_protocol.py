from __future__ import annotations

import struct

import pytest

from kaeru_mtk.data import AUTH_DIR
from kaeru_mtk.protocol.brom import (
    BROM_HANDSHAKE,
    BromProtocol,
)
from kaeru_mtk.protocol.exploits import EXPLOIT_REGISTRY
from kaeru_mtk.protocol.sla import parse_auth_file


class _MockTransport:
    def __init__(self):
        self.written = b""
        self.to_read = b""
        self.ctrl_data = b""
        self.connected = True
        self._info = {}

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def write(self, data: bytes) -> int:
        self.written = data
        return len(data)

    def read(self, size: int, timeout: int = 5000) -> bytes:
        return self.to_read[:size]

    def write_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, data: bytes = b"") -> bytes:
        self.written = data
        return b""

    def read_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, size: int) -> bytes:
        return self.ctrl_data[:size]

    @property
    def device_info(self) -> dict:
        return self._info


def test_brom_handshake():
    transport = _MockTransport()
    transport.to_read = b"\x5f\x00\x00\x00\x00"
    brom = BromProtocol(transport)
    result = brom.handshake()
    assert result is True
    assert transport.written == BROM_HANDSHAKE


def test_brom_get_hw_code():
    transport = _MockTransport()
    transport.ctrl_data = struct.pack("<H", 0x959)
    brom = BromProtocol(transport)
    hw = brom.get_hw_code()
    assert hw == 0x959


def test_brom_get_target_config():
    transport = _MockTransport()
    transport.ctrl_data = (
        struct.pack("<HHHH", 0x959, 0x00, 0x00, 0x00) +
        struct.pack("<I", 0x03) +
        b"\x00" * 16
    )
    brom = BromProtocol(transport)
    cfg = brom.get_target_config()
    assert cfg.hw_code == 0x959
    assert cfg.secure_boot is True
    assert cfg.sla_enabled is True
    assert cfg.daa_enabled is False


def test_brom_write32():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    brom.write32(0x10000000, 0xDEADBEEF)
    assert len(transport.written) >= 8


def test_brom_read32():
    transport = _MockTransport()
    transport.ctrl_data = struct.pack("<I", 0xCAFEBABE)
    brom = BromProtocol(transport)
    val = brom.read32(0x10000000)
    assert val == 0xCAFEBABE


def test_exploit_registry_has_all():
    assert "kamakiri" in EXPLOIT_REGISTRY
    assert "kamakiri2" in EXPLOIT_REGISTRY
    assert "carbonara" in EXPLOIT_REGISTRY
    assert "hashimoto" in EXPLOIT_REGISTRY
    assert "heapbait" in EXPLOIT_REGISTRY


def test_kamakiri_exploit():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    exploit = EXPLOIT_REGISTRY["kamakiri"](brom)
    assert exploit.name() == "kamakiri"
    assert exploit.arch() == "armv7"
    result = exploit.execute()
    assert result.success is True


def test_kamakiri2_exploit():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    exploit = EXPLOIT_REGISTRY["kamakiri2"](brom)
    assert exploit.name() == "kamakiri2"
    assert exploit.arch() == "aarch64"
    result = exploit.execute()
    assert result.success is True


def test_carbonara_exploit():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    exploit = EXPLOIT_REGISTRY["carbonara"](brom)
    assert exploit.arch() == "aarch64"
    result = exploit.execute()
    assert result.success is True


def test_hashimoto_exploit():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    exploit = EXPLOIT_REGISTRY["hashimoto"](brom)
    assert exploit.arch() == "armv7"
    result = exploit.execute()
    assert result.success is True


def test_heapbait_exploit():
    transport = _MockTransport()
    brom = BromProtocol(transport)
    exploit = EXPLOIT_REGISTRY["heapbait"](brom)
    assert exploit.arch() == "aarch64"
    result = exploit.execute()
    assert result.success is True


def test_parse_auth_file():
    auth_files = sorted(AUTH_DIR.glob("*.auth"))
    assert len(auth_files) > 0
    for f in auth_files:
        data = f.read_bytes()
        auth = parse_auth_file(str(f), data)
        assert len(auth.modulus) == 256
        assert len(auth.signature) == 256
        assert auth.path == str(f)


def test_parse_auth_file_invalid_magic():
    from kaeru_mtk.utils.errors import AuthError
    with pytest.raises(AuthError):
        parse_auth_file("test.auth", b"\x00\x00\x00\x00")


def test_parse_auth_file_truncated():
    from kaeru_mtk.utils.errors import AuthError
    with pytest.raises(AuthError):
        parse_auth_file("test.auth", b"MMM\x01" + b"\x00" * 100)
