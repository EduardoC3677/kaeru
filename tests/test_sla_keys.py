from __future__ import annotations

import hashlib

from kaeru_mtk.data.sla_keys import (
    ALL_SLA_KEYS,
    SOC_TO_SLA_KEY_INDEX,
    find_sla_key_by_modulus,
    get_sla_key_for_soc,
)


def test_four_keys_are_2048_bit():
    assert len(ALL_SLA_KEYS) == 4
    for k in ALL_SLA_KEYS:
        assert len(k.modulus) == 256, f"key #{k.index} modulus must be RSA-2048 (256 B)"
        assert k.public_exponent == 0x10001


def test_keys_are_distinct():
    fingerprints = {hashlib.sha256(k.modulus).hexdigest() for k in ALL_SLA_KEYS}
    assert len(fingerprints) == 4


def test_key1_first_byte_matches_static_analysis():
    assert ALL_SLA_KEYS[0].modulus[:4].hex() == "c43469a9"
    assert ALL_SLA_KEYS[1].modulus[:4].hex() == "8e02cdb3"
    assert ALL_SLA_KEYS[2].modulus[:4].hex() == "707c8892"
    assert ALL_SLA_KEYS[3].modulus[:4].hex() == "a243f669"


def test_seven_socs_share_key_one():
    expected = {
        "MT6763", "MT6833", "MT6853", "MT6873",
        "MT6877", "MT6885", "MT6889",
    }
    assert set(SOC_TO_SLA_KEY_INDEX.keys()) == expected
    for soc in expected:
        assert SOC_TO_SLA_KEY_INDEX[soc] == 1


def test_get_sla_key_for_soc_case_insensitive():
    k = get_sla_key_for_soc("mt6877")
    assert k is not None
    assert k.index == 1
    assert get_sla_key_for_soc("UNKNOWN") is None


def test_find_sla_key_by_modulus_roundtrip():
    for k in ALL_SLA_KEYS:
        found = find_sla_key_by_modulus(k.modulus)
        assert found is k

    bogus = b"\x00" * 256
    assert find_sla_key_by_modulus(bogus) is None
