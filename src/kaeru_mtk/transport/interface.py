from __future__ import annotations

from abc import ABC, abstractmethod


class TransportInterface(ABC):
    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def disconnect(self) -> None:
        ...

    @abstractmethod
    def write(self, data: bytes) -> int:
        ...

    @abstractmethod
    def read(self, size: int, timeout: int = 5000) -> bytes:
        ...

    @abstractmethod
    def write_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, data: bytes = b"") -> bytes:
        ...

    @abstractmethod
    def read_ctrl(self, bmRequestType: int, bRequest: int, wValue: int, wIndex: int, size: int) -> bytes:
        ...

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @property
    @abstractmethod
    def device_info(self) -> dict:
        ...
