"""Bundled data resources for kaeru-mtk.

This module ships with the package:

* ``data/auth/<SOC>.auth`` — 15 ``auth_sv5.auth`` files extracted from the
  publicly available ``EduardoC3677/opencode`` repository under
  ``O+/Plugins/resource/MTKResource/MTK/<SOC>/``. Each is a 2256/2272-byte
  GFH-wrapped (``MMM\\x01``) blob with a 256-byte RSA-2048 modulus at offset
  ``0x4C4`` and a 256-byte signature at the end.

* ``sla_keys`` — the four RSA-2048 public keys hardcoded in the
  ``SLA_Challenge.dll`` (OPlus build, 2021-11-23) plus the SoC → key-index
  mapping derived by cross-referencing each modulus against the auth files.

* ``soc_db`` — per-SoC BROM/DA configuration (hwcode → SoC name, payload
  bases, watchdog addrs, AArch64 flag, exploit recipe).
"""

from __future__ import annotations

from pathlib import Path

DATA_DIR: Path = Path(__file__).resolve().parent
AUTH_DIR: Path = DATA_DIR / "auth"

__all__ = ["AUTH_DIR", "DATA_DIR"]
