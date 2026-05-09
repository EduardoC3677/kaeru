from __future__ import annotations

import struct

from kaeru_mtk.protocol.brom import HANDSHAKE_BYTES, BromClient, BromCmd
from kaeru_mtk.transport.mock import MockTransport


def test_handshake_succeeds_with_inverted_echo():
    t = MockTransport()
    t.open()
    for b in HANDSHAKE_BYTES:
        t.queue_response(bytes([(~b) & 0xFF]))
    BromClient(t).handshake(attempts=1)
    sent = b"".join(t.tx_log)
    assert sent == bytes(HANDSHAKE_BYTES)


def test_get_hw_code_format():
    t = MockTransport()
    t.open()
    t.queue_response(bytes([int(BromCmd.GET_HW_CODE)]))
    t.queue_response(struct.pack(">H", 0x0996))
    t.queue_response(struct.pack(">H", 0x0000))
    code = BromClient(t).get_hw_code()
    assert code == 0x0996


def test_read32_payload_layout():
    t = MockTransport()
    t.open()
    t.queue_response(bytes([int(BromCmd.READ32)]))
    t.queue_response(struct.pack(">H", 0x0000))
    t.queue_response(struct.pack(">I", 0xCAFEBABE))
    t.queue_response(struct.pack(">I", 0xDEADBEEF))
    t.queue_response(struct.pack(">H", 0x0000))
    words = BromClient(t).read32(addr=0x10000, count=2)
    assert words == [0xCAFEBABE, 0xDEADBEEF]
    sent = b"".join(t.tx_log)
    assert sent[:1] == bytes([int(BromCmd.READ32)])
    assert struct.unpack(">I", sent[1:5])[0] == 0x10000
    assert struct.unpack(">I", sent[5:9])[0] == 2
