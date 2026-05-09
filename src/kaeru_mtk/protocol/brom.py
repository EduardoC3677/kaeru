from __future__ import annotations

import struct
from dataclasses import dataclass

from kaeru_mtk.transport.interface import TransportInterface
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

BROM_VID = 0x0E8D
BROM_PID = 0x0003
PRELOADER_PID = 0x2000

BROM_HANDSHAKE = b"\xA0\x0A\x50\x05"
BROM_ACK = b"\x5F"

CMD_GET_HW_CODE = 0xD1
CMD_GET_HW_SW_VER = 0xD2
CMD_GET_TARGET_CONFIG = 0xD3
CMD_WRITE16 = 0xD4
CMD_WRITE32 = 0xD5
CMD_READ16 = 0xD6
CMD_READ32 = 0xD7
CMD_JUMP_DA = 0xD8
CMD_SEND_DA = 0xDA
CMD_GET_DA_LOAD_INFO = 0xDB
CMD_SEND_CERT = 0xDC
CMD_SEND_AUTH_DATA = 0xDD
CMD_GET_CHALLENGE = 0xDE
CMD_WRITE_REG = 0xE0
CMD_READ_REG = 0xE1
CMD_JUMP_ADDR = 0xE2

CTRL_OUT = 0x40
CTRL_IN = 0xC0
BROM_REQUEST = 0x01


@dataclass
class BromTargetConfig:
    hw_code: int = 0
    hw_subcode: int = 0
    hw_version: int = 0
    sw_version: int = 0
    brom_ver: str = ""
    da_ver: str = ""
    me_id: bytes = b""
    secure_boot: bool = False
    sla_enabled: bool = False
    daa_enabled: bool = False

    def __str__(self) -> str:
        return (
            f"hw_code: 0x{self.hw_code:04x}\n"
            f"hw_subcode: 0x{self.hw_subcode:04x}\n"
            f"hw_version: 0x{self.hw_version:04x}\n"
            f"sw_version: 0x{self.sw_version:04x}\n"
            f"brom_ver: {self.brom_ver}\n"
            f"da_ver: {self.da_ver}\n"
            f"me_id: {self.me_id.hex()}\n"
            f"secure_boot: {self.secure_boot}\n"
            f"sla_enabled: {self.sla_enabled}\n"
            f"daa_enabled: {self.daa_enabled}"
        )


class BromProtocol:
    def __init__(self, transport: TransportInterface):
        self._transport = transport
        self._connected = False
        self._config: BromTargetConfig | None = None

    @property
    def transport(self) -> TransportInterface:
        return self._transport

    @property
    def config(self) -> BromTargetConfig | None:
        return self._config

    def connect(self) -> None:
        self._transport.connect()
        self._connected = True

    def disconnect(self) -> None:
        self._transport.disconnect()
        self._connected = False

    def handshake(self) -> bool:
        log.info("BROM handshake...")
        self._transport.write(BROM_HANDSHAKE)
        resp = self._transport.read(5)
        if len(resp) < 1:
            raise KaeruError("No response to BROM handshake")
        if resp[0:1] == BROM_ACK:
            log.info("BROM handshake OK")
            return True
        log.warning("BROM handshake unexpected response: %s", resp.hex())
        return False

    def _send_cmd(self, cmd: int, data: bytes = b"") -> bytes:
        payload = struct.pack("<BH", cmd, len(data)) + data
        self._transport.write(payload)
        resp = self._transport.read(64)
        return resp

    def _send_cmd_ctrl(self, cmd: int, data: bytes = b"") -> bytes:
        return self._transport.write_ctrl(CTRL_OUT, BROM_REQUEST, cmd, 0, data)

    def _read_ctrl(self, cmd: int, size: int = 64) -> bytes:
        return self._transport.read_ctrl(CTRL_IN, BROM_REQUEST, cmd, 0, size)

    def _send_then_read_ctrl(self, cmd: int, data: bytes = b"", read_size: int = 64) -> bytes:
        self._send_cmd_ctrl(cmd, data)
        return self._read_ctrl(cmd, read_size)

    def get_hw_code(self) -> int:
        resp = self._send_then_read_ctrl(CMD_GET_HW_CODE)
        if len(resp) >= 2:
            return struct.unpack("<H", resp[:2])[0]
        raise KaeruError(f"GET_HW_CODE failed: {resp.hex()}")

    def get_hw_sw_ver(self) -> tuple[int, int, int, int]:
        resp = self._send_then_read_ctrl(CMD_GET_HW_SW_VER)
        if len(resp) >= 8:
            vals = struct.unpack("<HHHH", resp[:8])
            return vals
        raise KaeruError(f"GET_HW_SW_VER failed: {resp.hex()}")

    def get_target_config(self) -> BromTargetConfig:
        resp = self._send_then_read_ctrl(CMD_GET_TARGET_CONFIG)
        cfg = BromTargetConfig()
        if len(resp) < 12:
            raise KaeruError(f"GET_TARGET_CONFIG too short: {len(resp)} bytes")
        cfg.hw_code = struct.unpack("<H", resp[0:2])[0]
        if len(resp) >= 4:
            cfg.hw_subcode = struct.unpack("<H", resp[2:4])[0]
        if len(resp) >= 6:
            cfg.hw_version = struct.unpack("<H", resp[4:6])[0]
        if len(resp) >= 8:
            cfg.sw_version = struct.unpack("<H", resp[6:8])[0]
        if len(resp) >= 12:
            flags = struct.unpack("<I", resp[8:12])[0]
            cfg.secure_boot = bool(flags & 0x1)
            cfg.sla_enabled = bool(flags & 0x2)
            cfg.daa_enabled = bool(flags & 0x4)
        if len(resp) > 12:
            cfg.me_id = resp[12:]
        self._config = cfg
        log.info("Target config: hw_code=0x%04x secure=%s sla=%s daa=%s",
                 cfg.hw_code, cfg.secure_boot, cfg.sla_enabled, cfg.daa_enabled)
        return cfg

    def write16(self, addr: int, value: int) -> bytes:
        data = struct.pack("<IH", addr, value)
        return self._send_cmd_ctrl(CMD_WRITE16, data)

    def write32(self, addr: int, value: int) -> bytes:
        data = struct.pack("<II", addr, value)
        return self._send_cmd_ctrl(CMD_WRITE32, data)

    def read16(self, addr: int) -> int:
        data = struct.pack("<I", addr)
        resp = self._send_then_read_ctrl(CMD_READ16, data)
        if len(resp) >= 2:
            return struct.unpack("<H", resp[:2])[0]
        raise KaeruError(f"READ16 failed at 0x{addr:08x}: {resp.hex()}")

    def read32(self, addr: int) -> int:
        data = struct.pack("<I", addr)
        resp = self._send_then_read_ctrl(CMD_READ32, data)
        if len(resp) >= 4:
            return struct.unpack("<I", resp[:4])[0]
        raise KaeruError(f"READ32 failed at 0x{addr:08x}: {resp.hex()}")

    def write_register(self, addr: int, mask: int, value: int) -> bytes:
        data = struct.pack("<III", addr, mask, value)
        return self._send_cmd_ctrl(CMD_WRITE_REG, data)

    def read_register(self, addr: int) -> int:
        data = struct.pack("<I", addr)
        resp = self._send_then_read_ctrl(CMD_READ_REG, data)
        if len(resp) >= 4:
            return struct.unpack("<I", resp[:4])[0]
        raise KaeruError(f"READ_REG failed at 0x{addr:08x}: {resp.hex()}")

    def jump_addr(self, addr: int) -> bytes:
        data = struct.pack("<I", addr)
        return self._send_cmd_ctrl(CMD_JUMP_ADDR, data)

    def get_challenge(self) -> bytes:
        resp = self._send_then_read_ctrl(CMD_GET_CHALLENGE)
        return resp

    def send_auth_data(self, data: bytes) -> bytes:
        return self._send_cmd_ctrl(CMD_SEND_AUTH_DATA, data)

    def get_da_load_info(self) -> tuple[int, int]:
        resp = self._send_then_read_ctrl(CMD_GET_DA_LOAD_INFO)
        if len(resp) >= 8:
            addr, max_size = struct.unpack("<II", resp[:8])
            return addr, max_size
        raise KaeruError(f"GET_DA_LOAD_INFO failed: {resp.hex()}")

    def send_da(self, data: bytes, addr: int = 0) -> bytes:
        header = struct.pack("<II", addr, len(data)) if addr else struct.pack("<I", len(data))
        payload = header + data
        return self._send_cmd_ctrl(CMD_SEND_DA, payload)

    def jump_da(self, addr: int = 0) -> bytes:
        data = struct.pack("<I", addr) if addr else b""
        return self._send_cmd_ctrl(CMD_JUMP_DA, data)

    def is_connected(self) -> bool:
        return self._connected

    def detect_device(self) -> BromTargetConfig:
        self.connect()
        self.handshake()
        return self.get_target_config()
