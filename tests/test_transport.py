from __future__ import annotations

import pytest

from kaeru_mtk.data.usb_ids import all_known_ids
from kaeru_mtk.transport.interface import TransportInterface


def test_transport_interface_is_abstract():
    with pytest.raises(TypeError):
        TransportInterface()  # type: ignore


def test_known_usb_ids():
    ids = all_known_ids()
    assert len(ids) >= 4
    brom_ids = [e for e in ids if "BROM" in e.label]
    assert len(brom_ids) >= 1
    assert brom_ids[0].vid == 0x0E8D
    assert brom_ids[0].pid == 0x0003


def test_usb_id_dataclass():
    from kaeru_mtk.data.usb_ids import UsbId
    uid = UsbId(vid=0x0E8D, pid=0x0003, label="test")
    assert uid.vid == 0x0E8D
    assert uid.pid == 0x0003
    assert uid.label == "test"
