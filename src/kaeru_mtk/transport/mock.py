from __future__ import annotations

from collections import deque
from typing import Callable

from kaeru_mtk.transport.base import Transport
from kaeru_mtk.utils.errors import TimeoutError as KaeruTimeoutError
from kaeru_mtk.utils.errors import TransportError


class MockTransport(Transport):
    def __init__(self, *, responder: Callable[[bytes], bytes] | None = None) -> None:
        self._open = False
        self._tx_log: list[bytes] = []
        self._rx_queue: deque[bytes] = deque()
        self._responder = responder

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def is_open(self) -> bool:
        return self._open

    def queue_response(self, data: bytes) -> None:
        self._rx_queue.append(bytes(data))

    @property
    def tx_log(self) -> list[bytes]:
        return list(self._tx_log)

    def write(self, data: bytes, *, timeout_ms: int | None = None) -> int:
        if not self._open:
            raise TransportError("not open")
        self._tx_log.append(bytes(data))
        if self._responder is not None:
            resp = self._responder(bytes(data))
            if resp:
                self._rx_queue.append(resp)
        return len(data)

    def read(self, n: int, *, timeout_ms: int | None = None) -> bytes:
        if not self._open:
            raise TransportError("not open")
        if not self._rx_queue:
            raise KaeruTimeoutError("mock transport: no queued response")
        data = self._rx_queue.popleft()
        return data[:n] if len(data) > n else data
