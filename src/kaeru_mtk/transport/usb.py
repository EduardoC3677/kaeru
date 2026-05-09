from __future__ import annotations

import platform
from dataclasses import dataclass
from typing import Any

from kaeru_mtk.data.usb_ids import all_known_ids
from kaeru_mtk.transport.interface import TransportInterface
from kaeru_mtk.utils.errors import DeviceNotFoundError, KaeruError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

_MTK_VID = 0x0E8D


@dataclass
class MtkDeviceInfo:
    vid: int
    pid: int
    bus: int
    address: int
    manufacturer: str = ""
    product: str = ""
    serial: str = ""


def find_mtk_device(pid: int | None = None):
    try:
        import usb.core
        import usb.util
    except ImportError as e:
        raise KaeruError("pyusb is required. Install: pip install pyusb") from e

    if pid is not None:
        dev = usb.core.find(idVendor=_MTK_VID, idProduct=pid)
        if dev is not None:
            return dev
        raise DeviceNotFoundError(f"No MTK device found with PID 0x{pid:04X}")

    for entry in all_known_ids():
        dev = usb.core.find(idVendor=entry.vid, idProduct=entry.pid)
        if dev is not None:
            return dev

    dev = usb.core.find(idVendor=_MTK_VID)
    if dev is not None:
        return dev

    raise DeviceNotFoundError(
        "No MediaTek device found. "
        "Ensure the device is in BROM/Preloader mode and WinUSB/libusb is bound."
    )


class UsbTransport(TransportInterface):
    def __init__(self, pid: int | None = None, timeout: int = 5000):
        self._pid = pid
        self._timeout = timeout
        self._dev: Any = None
        self._ep_out: Any = None
        self._ep_in: Any = None
        self._info: MtkDeviceInfo | None = None

    def connect(self) -> None:
        dev = find_mtk_device(self._pid)
        try:
            import usb.core
            import usb.util
        except ImportError as e:
            raise KaeruError("pyusb is required") from e

        if dev._manufacturer is not None:
            pass
        if platform.system().lower() != "windows":
            try:
                if dev.is_kernel_driver_active(0):
                    dev.detach_kernel_driver(0)
            except (usb.core.USBError, NotImplementedError):
                pass

        try:
            dev.set_configuration()
        except usb.core.USBError as e:
            if "Resource busy" not in str(e):
                log.debug("set_configuration: %s", e)

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
            raise KaeruError("Could not find bulk endpoints")

        self._dev = dev
        self._ep_out = ep_out
        self._ep_in = ep_in

        try:
            manuf = usb.util.get_string(dev, dev.iManufacturer) if dev.iManufacturer else ""
        except Exception:
            manuf = ""
        try:
            product = usb.util.get_string(dev, dev.iProduct) if dev.iProduct else ""
        except Exception:
            product = ""
        try:
            serial = usb.util.get_string(dev, dev.iSerialNumber) if dev.iSerialNumber else ""
        except Exception:
            serial = ""

        self._info = MtkDeviceInfo(
            vid=dev.idVendor,
            pid=dev.idProduct,
            bus=dev.bus,
            address=dev.address,
            manufacturer=manuf,
            product=product,
            serial=serial,
        )
        log.info(
            "Connected: %04x:%04x bus=%d addr=%d %s %s",
            dev.idVendor, dev.idProduct, dev.bus, dev.address,
            manuf, product,
        )

    def disconnect(self) -> None:
        if self._dev is not None:
            try:
                import usb.util
                usb.util.dispose_resources(self._dev)
            except Exception:
                pass
            self._dev = None
            self._ep_out = None
            self._ep_in = None
            self._info = None

    def write(self, data: bytes) -> int:
        if self._ep_out is None:
            raise KaeruError("Not connected")
        return self._ep_out.write(data, timeout=self._timeout)

    def read(self, size: int, timeout: int = 5000) -> bytes:
        if self._ep_in is None:
            raise KaeruError("Not connected")
        return bytes(self._ep_in.read(size, timeout=timeout))

    def write_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, data: bytes = b"") -> bytes:
        if self._dev is None:
            raise KaeruError("Not connected")
        return bytes(self._dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data, timeout=self._timeout))

    def read_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, size: int) -> bytes:
        if self._dev is None:
            raise KaeruError("Not connected")
        return bytes(self._dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, size, timeout=self._timeout))

    @property
    def connected(self) -> bool:
        return self._dev is not None

    @property
    def device_info(self) -> dict:
        if self._info is None:
            return {}
        return {
            "vid": f"{self._info.vid:04x}",
            "pid": f"{self._info.pid:04x}",
            "bus": self._info.bus,
            "address": self._info.address,
            "manufacturer": self._info.manufacturer,
            "product": self._info.product,
            "serial": self._info.serial,
        }
