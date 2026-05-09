from __future__ import annotations

from abc import ABC, abstractmethod


class Transport(ABC):
    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def write(self, data: bytes, *, timeout_ms: int | None = None) -> int: ...

    @abstractmethod
    def read(self, n: int, *, timeout_ms: int | None = None) -> bytes: ...

    @abstractmethod
    def is_open(self) -> bool: ...

    def __enter__(self) -> Transport:
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
