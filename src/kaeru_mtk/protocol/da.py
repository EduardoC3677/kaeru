from __future__ import annotations

import contextlib
import struct
from dataclasses import dataclass
from typing import Any

from kaeru_mtk.transport.interface import TransportInterface
from kaeru_mtk.utils.errors import KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

DA_VID = 0x0E8D
DA_PID = 0x6000

DA_CMD_OPEN = 0x01
DA_CMD_CLOSE = 0x02
DA_CMD_READ = 0x03
DA_CMD_WRITE = 0x04
DA_CMD_ERASE = 0x05
DA_CMD_GET_INFO = 0x06
DA_CMD_INIT = 0x07
DA_CMD_GET_PARTITIONS = 0x08
DA_CMD_READ_EXT = 0x09
DA_CMD_WRITE_EXT = 0x0A
DA_CMD_ERASE_EXT = 0x0B

DA_STATUS_OK = 0x00
DA_STATUS_ERROR = 0xFF


@dataclass
class PartitionInfo:
    name: str
    start_addr: int
    size: int
    is_linear: bool = True

    def __str__(self) -> str:
        size_mb = self.size / (1024 * 1024)
        return f"{self.name:<20} 0x{self.start_addr:010x}  {size_mb:>8.1f} MB"


class DaProtocol:
    def __init__(self, transport: TransportInterface):
        self._transport = transport
        self._connected = False
        self._partitions: list[PartitionInfo] = []

    def connect(self) -> None:
        from kaeru_mtk.transport.usb import find_mtk_device
        dev = find_mtk_device(DA_PID)
        try:
            import usb.util
        except ImportError as e:
            raise KaeruError("pyusb is required") from e

        with contextlib.suppress(Exception):
            dev.set_configuration()

        cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]
        ep_out = None
        ep_in = None
        for ep in intf.endpoints():
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                ep_out = ep
            else:
                ep_in = ep

        if ep_out is None or ep_in is None:
            raise KaeruError("DA endpoints not found")

        self._transport = _DaTransportWrapper(dev, ep_out, ep_in)
        self._connected = True
        log.info("DA connected")

    def disconnect(self) -> None:
        if self._connected:
            try:
                import usb.util
                usb.util.dispose_resources(self._transport._dev)
            except Exception:
                pass
            self._connected = False

    def _send_da_cmd(self, cmd: int, data: bytes = b"") -> bytes:
        payload = struct.pack("<BH", cmd, len(data)) + data
        self._transport.write(payload)
        resp = self._transport.read(64)
        return resp

    def init(self) -> bool:
        resp = self._send_da_cmd(DA_CMD_INIT)
        if len(resp) >= 1 and resp[0] == DA_STATUS_OK:
            log.info("DA init OK")
            return True
        log.warning("DA init failed: %s", resp.hex() if resp else "no response")
        return False

    def get_partitions(self) -> list[PartitionInfo]:
        resp = self._send_da_cmd(DA_CMD_GET_PARTITIONS)
        parts: list[PartitionInfo] = []
        offset = 0
        while offset + 512 <= len(resp):
            name_bytes = resp[offset:offset + 32]
            name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace").strip()
            start = struct.unpack("<Q", resp[offset + 32:offset + 40])[0]
            size = struct.unpack("<Q", resp[offset + 40:offset + 48])[0]
            if name:
                parts.append(PartitionInfo(name=name, start_addr=start, size=size))
            offset += 512
        self._partitions = parts
        log.info("Found %d partitions", len(parts))
        return parts

    def read_partition(self, name: str, size: int = 0, offset: int = 0) -> bytes:
        part = self._find_partition(name)
        if part is None:
            raise KaeruError(f"Partition {name} not found")
        read_size = size if size > 0 else part.size
        log.info("Reading %s: offset=0x%x size=%d", name, offset, read_size)

        data = bytearray()
        chunk_size = 1024 * 1024
        remaining = read_size
        while remaining > 0:
            chunk = min(chunk_size, remaining)
            cmd_data = struct.pack("<II", part.start_addr + offset + len(data), chunk)
            resp = self._send_da_cmd(DA_CMD_READ_EXT, cmd_data)
            data.extend(resp)
            remaining -= chunk
            if len(resp) < chunk:
                break

        return bytes(data)

    def write_partition(self, name: str, data: bytes, offset: int = 0) -> bool:
        part = self._find_partition(name)
        if part is None:
            raise KaeruError(f"Partition {name} not found")
        log.info("Writing %s: offset=0x%x size=%d", name, offset, len(data))

        chunk_size = 1024 * 1024
        written = 0
        while written < len(data):
            chunk = data[written:written + chunk_size]
            cmd_data = struct.pack("<II", part.start_addr + offset + written, len(chunk)) + chunk
            resp = self._send_da_cmd(DA_CMD_WRITE_EXT, cmd_data)
            if len(resp) >= 1 and resp[0] != DA_STATUS_OK:
                log.error("Write failed at offset 0x%x", written)
                return False
            written += len(chunk)

        log.info("Write complete: %d bytes", written)
        return True

    def erase_partition(self, name: str) -> bool:
        part = self._find_partition(name)
        if part is None:
            raise KaeruError(f"Partition {name} not found")
        log.info("Erasing %s: 0x%x bytes at 0x%x", name, part.size, part.start_addr)

        cmd_data = struct.pack("<II", part.start_addr, part.size)
        resp = self._send_da_cmd(DA_CMD_ERASE_EXT, cmd_data)
        if len(resp) >= 1 and resp[0] == DA_STATUS_OK:
            log.info("Erase OK")
            return True
        log.warning("Erase failed: %s", resp.hex() if resp else "no response")
        return False

    def _find_partition(self, name: str) -> PartitionInfo | None:
        if not self._partitions:
            self.get_partitions()
        for p in self._partitions:
            if p.name.lower() == name.lower():
                return p
        return None


class _DaTransportWrapper:
    def __init__(self, dev: Any, ep_out: Any, ep_in: Any):
        self._dev = dev
        self._ep_out = ep_out
        self._ep_in = ep_in

    def write(self, data: bytes) -> int:
        return self._ep_out.write(data, timeout=10000)

    def read(self, size: int, timeout: int = 10000) -> bytes:
        return bytes(self._ep_in.read(size, timeout=timeout))
