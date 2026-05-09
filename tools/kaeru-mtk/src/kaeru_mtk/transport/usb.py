from __future__ import annotations

import contextlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from kaeru_mtk.transport.base import Transport
from kaeru_mtk.transport.identifiers import (
    BROM_USB_IDS,
    PRELOADER_USB_IDS,
    UsbId,
    describe_usb_id,
)
from kaeru_mtk.utils.errors import DeviceNotFoundError, DriverError, TransportError
from kaeru_mtk.utils.errors import TimeoutError as KaeruTimeoutError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

DEFAULT_TIMEOUT_MS = 5_000


@dataclass
class UsbDeviceInfo:
    vid: int
    pid: int
    bus: int | None
    address: int | None
    serial: str | None

    @property
    def label(self) -> str:
        return describe_usb_id(self.vid, self.pid)


class UsbTransport(Transport):
    def __init__(
        self,
        *,
        candidates: Sequence[UsbId] = BROM_USB_IDS + PRELOADER_USB_IDS,
        interface: int = 0,
        ep_in: int | None = None,
        ep_out: int | None = None,
    ) -> None:
        self._candidates = tuple(candidates)
        self._interface = interface
        self._ep_in_addr = ep_in
        self._ep_out_addr = ep_out
        self._dev = None
        self._ep_in = None
        self._ep_out = None
        self._opened = False

    @staticmethod
    def _import_usb():
        try:
            import usb.core
            import usb.util
        except ImportError as e:
            raise DriverError(
                "pyusb is required. Install with: pip install pyusb libusb-package"
            ) from e
        try:
            import libusb_package

            backend = libusb_package.get_libusb1_backend()
        except Exception:
            backend = None
        return usb.core, usb.util, backend

    def list_devices(self) -> list[UsbDeviceInfo]:
        usb_core, _usb_util, backend = self._import_usb()
        out: list[UsbDeviceInfo] = []
        for cand in self._candidates:
            try:
                found = usb_core.find(
                    find_all=True, idVendor=cand.vid, idProduct=cand.pid, backend=backend
                )
            except Exception as e:
                raise DriverError(
                    f"libusb backend not available: {e}. "
                    "On Windows install with: pip install libusb-package, then run "
                    "`kaeru-mtk driver install` to bind WinUSB. "
                    "On Linux: `sudo apt install libusb-1.0-0` and add a udev rule for VID 0e8d."
                ) from e
            for d in found or ():
                serial = None
                try:
                    serial = usb_core.util.get_string(d, d.iSerialNumber) if d.iSerialNumber else None
                except Exception:
                    serial = None
                out.append(
                    UsbDeviceInfo(
                        vid=d.idVendor,
                        pid=d.idProduct,
                        bus=getattr(d, "bus", None),
                        address=getattr(d, "address", None),
                        serial=serial,
                    )
                )
        return out

    def open(self) -> None:
        if self._opened:
            return
        usb_core, usb_util, backend = self._import_usb()
        dev = None
        for cand in self._candidates:
            dev = usb_core.find(idVendor=cand.vid, idProduct=cand.pid, backend=backend)
            if dev is not None:
                log.info("Found %s (vid=0x%04x pid=0x%04x)", cand.label, cand.vid, cand.pid)
                break
        if dev is None:
            wanted = ", ".join(f"{c.vid:04x}:{c.pid:04x}" for c in self._candidates)
            raise DeviceNotFoundError(
                f"No MTK USB device found. Candidates tried: {wanted}. "
                "Confirm device is in BROM/Preloader mode and the WinUSB driver is installed "
                "(see `kaeru-mtk driver install`)."
            )

        try:
            try:
                if dev.is_kernel_driver_active(self._interface):
                    dev.detach_kernel_driver(self._interface)
            except (NotImplementedError, AttributeError):
                pass
            except Exception as e:
                log.warning("detach_kernel_driver failed (ignored): %s", e)

            try:
                dev.set_configuration()
            except Exception as e:
                raise DriverError(
                    f"set_configuration failed: {e}. On Windows, replace the device driver "
                    "with WinUSB via Zadig or run `kaeru-mtk driver install`."
                ) from e

            cfg = dev.get_active_configuration()
            intf = cfg[(self._interface, 0)]
            usb_util.claim_interface(dev, self._interface)

            ep_in = None
            ep_out = None
            for ep in intf:
                addr = ep.bEndpointAddress
                is_in = (addr & 0x80) != 0
                if self._ep_in_addr is not None and addr == self._ep_in_addr:
                    ep_in = ep
                elif self._ep_out_addr is not None and addr == self._ep_out_addr:
                    ep_out = ep
                elif self._ep_in_addr is None and is_in and ep_in is None:
                    ep_in = ep
                elif self._ep_out_addr is None and not is_in and ep_out is None:
                    ep_out = ep

            if ep_in is None or ep_out is None:
                raise DriverError(
                    "Unable to locate IN/OUT bulk endpoints on interface "
                    f"{self._interface}. Device may already be claimed by another process."
                )

            self._dev = dev
            self._ep_in = ep_in
            self._ep_out = ep_out
            self._opened = True
            log.info(
                "Opened %s ep_in=0x%02x ep_out=0x%02x",
                describe_usb_id(dev.idVendor, dev.idProduct),
                ep_in.bEndpointAddress,
                ep_out.bEndpointAddress,
            )
        except Exception:
            with contextlib.suppress(Exception):
                usb_util.dispose_resources(dev)
            raise

    def close(self) -> None:
        if not self._opened:
            return
        try:
            import usb.util as usb_util

            with contextlib.suppress(Exception):
                usb_util.release_interface(self._dev, self._interface)
            with contextlib.suppress(Exception):
                usb_util.dispose_resources(self._dev)
        finally:
            self._dev = None
            self._ep_in = None
            self._ep_out = None
            self._opened = False

    def is_open(self) -> bool:
        return self._opened

    def write(self, data: bytes, *, timeout_ms: int | None = None) -> int:
        if not self._opened:
            raise TransportError("transport is not open")
        try:
            return int(self._ep_out.write(bytes(data), timeout=timeout_ms or DEFAULT_TIMEOUT_MS))
        except Exception as e:
            if "timeout" in str(e).lower():
                raise KaeruTimeoutError(f"USB write timeout after {len(data)} bytes") from e
            raise TransportError(f"USB write failed: {e}") from e

    def read(self, n: int, *, timeout_ms: int | None = None) -> bytes:
        if not self._opened:
            raise TransportError("transport is not open")
        try:
            arr = self._ep_in.read(n, timeout=timeout_ms or DEFAULT_TIMEOUT_MS)
            return bytes(arr)
        except Exception as e:
            if "timeout" in str(e).lower():
                raise KaeruTimeoutError(f"USB read timeout (wanted {n} bytes)") from e
            raise TransportError(f"USB read failed: {e}") from e


def find_first(candidates: Iterable[UsbId] = BROM_USB_IDS + PRELOADER_USB_IDS) -> UsbDeviceInfo | None:
    t = UsbTransport(candidates=tuple(candidates))
    found = t.list_devices()
    return found[0] if found else None
