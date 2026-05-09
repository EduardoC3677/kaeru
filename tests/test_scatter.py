from __future__ import annotations

from kaeru_mtk.formats.scatter import filter_flashable, parse_scatter

SAMPLE_SCATTER = """\
project: ONEPLUS_NORD
platform: MT6877
storage: HW_STORAGE_UFS

partitions:
- partition_index: SYS0
  partition_name: preloader
  file_name: preloader_oneplus.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x80000
  region: BOOT_1
  storage: HW_STORAGE_UFS
  boundary_check: true
  is_reserved: false
  operation_type: BOOTLOADERS

- partition_index: SYS1
  partition_name: oplusreserve1
  file_name: oplusreserve1.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x800000
  physical_start_addr: 0x800000
  partition_size: 0x800000
  region: USER
  storage: HW_STORAGE_UFS
  boundary_check: true
  is_reserved: false
  operation_type: UPDATE

- partition_index: SYS2
  partition_name: userdata
  file_name: NONE
  is_download: false
  type: SV5_BL_BIN
  partition_size: 0xc0000000
  is_reserved: false
"""


def test_parse_basic():
    sf = parse_scatter(SAMPLE_SCATTER)
    assert sf.project == "ONEPLUS_NORD"
    assert sf.platform == "MT6877"
    assert sf.storage == "HW_STORAGE_UFS"
    assert len(sf.partitions) == 3


def test_by_name():
    sf = parse_scatter(SAMPLE_SCATTER)
    p = sf.by_name("oplusreserve1")
    assert p is not None
    assert p.file_name == "oplusreserve1.img"
    assert p.partition_size == 0x800000
    assert p.is_download is True
    assert p.is_reserved is False


def test_filter_flashable():
    sf = parse_scatter(SAMPLE_SCATTER)
    flashable = filter_flashable(sf.partitions)
    names = [p.name for p in flashable]
    assert "preloader" in names
    assert "oplusreserve1" in names
    assert "userdata" not in names


def test_int_parsing_hex_and_dec():
    sf = parse_scatter(SAMPLE_SCATTER)
    pre = sf.by_name("preloader")
    assert pre.partition_size == 0x80000
    rsv = sf.by_name("oplusreserve1")
    assert rsv.linear_start_addr == 0x800000
