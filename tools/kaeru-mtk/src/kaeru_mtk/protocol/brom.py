from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from kaeru_mtk.protocol.frame import Framing
from kaeru_mtk.transport.base import Transport
from kaeru_mtk.utils.errors import ProtocolError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class BromCmd(IntEnum):
    GET_HW_SW_VER = 0xFC
    GET_HW_CODE = 0xFD
    GET_BL_VER = 0xFE
    GET_VERSION = 0xFF
    GET_TARGET_CONFIG = 0xD8
    GET_ME_ID = 0xE1
    GET_SOC_ID = 0xE7

    READ16 = 0xA2
    WRITE16 = 0xA1
    READ32 = 0xD1
    WRITE32 = 0xD4

    JUMP_DA = 0xD5
    SEND_DA = 0xD7
    JUMP_BL = 0xD6

    SEND_CERT = 0xE0
    SEND_AUTH = 0xE2
    SLA_CHALLENGE = 0xE3
    SLA_RESPONSE = 0xE4

    UART1_LOG_EN = 0xDB
    POWER_INIT = 0xC4
    POWER_DEINIT = 0xC5
    POWER_READ16 = 0xC6
    POWER_WRITE16 = 0xC7

    CMD_C8 = 0xC8


HANDSHAKE_BYTES: Sequence[int] = (0xA0, 0x0A, 0x50, 0x05)


@dataclass
class BromTarget:
    hw_code: int
    hw_subcode: int
    hw_version: int
    sw_version: int
    secure_boot: bool
    serial_link_authorization: bool
    download_agent_authorization: bool
    target_config_raw: int
    me_id: bytes | None = None
    soc_id: bytes | None = None


class BromClient:
    def __init__(self, t: Transport) -> None:
        self._t = t
        self._f = Framing(t)

    def handshake(self, *, attempts: int = 200, timeout_ms: int = 100) -> None:
        for attempt in range(attempts):
            try:
                for b in HANDSHAKE_BYTES:
                    self._t.write(bytes([b]))
                    rx = self._t.read(1, timeout_ms=timeout_ms)
                    if not rx:
                        raise ProtocolError("handshake: empty rx")
                    if rx[0] != ((~b) & 0xFF):
                        raise ProtocolError(
                            f"handshake mismatch: sent 0x{b:02x}, got 0x{rx[0]:02x}"
                        )
                log.info("BROM handshake completed in %d attempts", attempt + 1)
                return
            except ProtocolError:
                continue
        raise ProtocolError(f"BROM handshake failed after {attempts} attempts")

    def _cmd(self, cmd: BromCmd) -> None:
        self._f.expect_echo(int(cmd))

    def get_hw_code(self) -> int:
        self._cmd(BromCmd.GET_HW_CODE)
        hw_code = self._f.read_be16()
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"GET_HW_CODE status=0x{status:04x}")
        return hw_code

    def get_hw_sw_ver(self) -> tuple[int, int, int, int]:
        self._cmd(BromCmd.GET_HW_SW_VER)
        hw_subcode = self._f.read_be16()
        hw_ver = self._f.read_be16()
        sw_ver = self._f.read_be16()
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"GET_HW_SW_VER status=0x{status:04x}")
        return hw_subcode, hw_ver, sw_ver, status

    def get_target_config(self) -> int:
        self._cmd(BromCmd.GET_TARGET_CONFIG)
        cfg = self._f.read_be32()
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"GET_TARGET_CONFIG status=0x{status:04x}")
        return cfg

    def get_me_id(self) -> bytes:
        self._cmd(BromCmd.GET_ME_ID)
        length = self._f.read_be32()
        if length == 0 or length > 64:
            raise ProtocolError(f"GET_ME_ID bad length {length}")
        meid = self._f.read_bytes(length)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"GET_ME_ID status=0x{status:04x}")
        return meid

    def read32(self, addr: int, count: int = 1) -> list[int]:
        if count <= 0:
            return []
        self._cmd(BromCmd.READ32)
        self._f.write_be32(addr)
        self._f.write_be32(count)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"READ32 init status=0x{status:04x}")
        words = [self._f.read_be32() for _ in range(count)]
        end = self._f.read_be16()
        if end != 0:
            raise ProtocolError(f"READ32 end status=0x{end:04x}")
        return words

    def write32(self, addr: int, words: Sequence[int]) -> None:
        if not words:
            return
        self._cmd(BromCmd.WRITE32)
        self._f.write_be32(addr)
        self._f.write_be32(len(words))
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"WRITE32 init status=0x{status:04x}")
        for w in words:
            self._f.write_be32(w)
        end = self._f.read_be16()
        if end != 0:
            raise ProtocolError(f"WRITE32 end status=0x{end:04x}")

    def send_da(self, da_payload: bytes, *, addr: int, sig_len: int = 0) -> None:
        self._cmd(BromCmd.SEND_DA)
        self._f.write_be32(addr)
        self._f.write_be32(len(da_payload))
        self._f.write_be32(sig_len)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"SEND_DA init status=0x{status:04x}")
        chunk = 0x1000
        for i in range(0, len(da_payload), chunk):
            self._f.write_bytes(da_payload[i : i + chunk])
        chk = self._f.read_be16()
        end = self._f.read_be16()
        log.debug("SEND_DA checksum=0x%04x end=0x%04x", chk, end)
        if end != 0:
            raise ProtocolError(f"SEND_DA end status=0x{end:04x}")

    def jump_da(self, addr: int) -> None:
        self._cmd(BromCmd.JUMP_DA)
        self._f.write_be32(addr)
        status = self._f.read_be16()
        if status != 0:
            raise ProtocolError(f"JUMP_DA status=0x{status:04x}")
        log.info("Jumped DA at 0x%08x", addr)

    def probe_target(self) -> BromTarget:
        hw_code = self.get_hw_code()
        hw_subcode, hw_ver, sw_ver, _ = self.get_hw_sw_ver()
        cfg = self.get_target_config()
        secure_boot = bool(cfg & 0x1)
        sla = bool(cfg & 0x2)
        daa = bool(cfg & 0x4)
        meid = None
        try:
            meid = self.get_me_id()
        except ProtocolError as e:
            log.debug("ME_ID read failed: %s", e)
        return BromTarget(
            hw_code=hw_code,
            hw_subcode=hw_subcode,
            hw_version=hw_ver,
            sw_version=sw_ver,
            secure_boot=secure_boot,
            serial_link_authorization=sla,
            download_agent_authorization=daa,
            target_config_raw=cfg,
            me_id=meid,
        )
