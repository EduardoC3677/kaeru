from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReadbackTarget:
    partition: str
    description: str
    sensitive: bool = False


COMMON_READBACK_TARGETS: tuple[ReadbackTarget, ...] = (
    ReadbackTarget("preloader", "MTK preloader (slot A)"),
    ReadbackTarget("pl", "alias for preloader_a"),
    ReadbackTarget("lk", "Little Kernel bootloader"),
    ReadbackTarget("lk_a", "LK slot A"),
    ReadbackTarget("lk_b", "LK slot B"),
    ReadbackTarget("boot_para", "boot mode parameter block"),
    ReadbackTarget("para", "para partition"),
    ReadbackTarget("seccfg", "secure configuration"),
    ReadbackTarget("oplusreserve1", "OPlus reserve (unlock flag, UFS info)", sensitive=True),
    ReadbackTarget("oplusreserve2", "OPlus reserve 2"),
    ReadbackTarget("nvram", "MediaTek NVRAM"),
    ReadbackTarget("nvdata", "MediaTek NVDATA"),
    ReadbackTarget("nvcfg", "MediaTek NVCFG"),
    ReadbackTarget("proinfo", "Production info (IMEI, calibration)", sensitive=True),
    ReadbackTarget("protect1", "encrypted protect 1", sensitive=True),
    ReadbackTarget("protect2", "encrypted protect 2", sensitive=True),
    ReadbackTarget("metadata", "Android metadata"),
    ReadbackTarget("frp", "Factory Reset Protection", sensitive=True),
    ReadbackTarget("persist", "persistent settings"),
    ReadbackTarget("vbmeta", "Android Verified Boot meta"),
    ReadbackTarget("vbmeta_a", "AVB slot A"),
    ReadbackTarget("vbmeta_b", "AVB slot B"),
    ReadbackTarget("boot", "Android boot image"),
    ReadbackTarget("boot_a", "boot slot A"),
    ReadbackTarget("boot_b", "boot slot B"),
    ReadbackTarget("vendor_boot", "vendor_boot image"),
    ReadbackTarget("dtbo", "Device Tree Blob Overlay"),
    ReadbackTarget("md1img", "modem image 1"),
    ReadbackTarget("md1dsp", "modem DSP"),
    ReadbackTarget("scp1", "Sensor Co-Processor"),
    ReadbackTarget("sspm_1", "Secure System Power Manager"),
)
