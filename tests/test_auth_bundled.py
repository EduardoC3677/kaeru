from __future__ import annotations

from kaeru_mtk.data import AUTH_DIR
from kaeru_mtk.data.auth_index import (
    all_bundles,
    best_bundle_for_hwcode,
    bundles_for_hwcode,
)
from kaeru_mtk.data.sla_keys import ALL_SLA_KEYS


def test_bundled_auth_dir_exists_and_has_15_files():
    assert AUTH_DIR.is_dir()
    files = sorted(AUTH_DIR.glob("*.auth"))
    assert len(files) == 15


def test_every_bundled_auth_starts_with_gfh_magic():
    for f in AUTH_DIR.glob("*.auth"):
        assert f.read_bytes()[:4] == b"MMM\x01"


def test_all_bundles_load_and_have_256_byte_modulus():
    bundles = all_bundles()
    assert len(bundles) == 15
    for b in bundles:
        assert len(b.rsa_modulus) == 256


def test_best_bundle_for_known_hwcodes():
    cases = [
        (0x690, "MT6763"),
        (0x766, "MT6765"),
        (0x788, "MT6771"),
        (0x725, "MT6779"),
        (0x989, "MT6833"),
        (0x996, "MT6853"),
        (0x886, "MT6873"),
        (0x959, "MT6877"),
        (0x950, "MT6893"),
    ]
    for hw, expected_soc in cases:
        b = best_bundle_for_hwcode(hw)
        assert b is not None, f"hwcode 0x{hw:04x} should resolve"
        assert b.soc.name == expected_soc


def test_unknown_hwcode_resolves_to_none():
    assert best_bundle_for_hwcode(0xCAFE) is None
    assert bundles_for_hwcode(0xCAFE) == []


def test_seven_auth_files_share_sla_key_1():
    expected = {"MT6763", "MT6833", "MT6853", "MT6873", "MT6877", "MT6885", "MT6889"}
    matched: set[str] = set()
    for b in all_bundles():
        if any(b.rsa_modulus == k.modulus and k.index == 1 for k in ALL_SLA_KEYS):
            matched.add(b.path.stem)
    assert matched == expected


def test_hwcode_0x816_returns_two_socs_one_bundle_per_soc():
    bundles = bundles_for_hwcode(0x816)
    soc_names = {b.soc.name for b in bundles}
    assert "MT6885" in soc_names
    assert "MT6889" in soc_names
