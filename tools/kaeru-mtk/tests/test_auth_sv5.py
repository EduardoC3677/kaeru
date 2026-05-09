from __future__ import annotations

import pytest

from kaeru_mtk.formats.auth_sv5 import (
    GFH_MAGIC,
    RSA_KEY_LEN,
    RSA_MODULUS_OFFSET,
    SIGNATURE_LEN,
    AuthSv5ParseError,
    parse_auth_sv5,
)


def _build_fake_auth() -> bytes:
    file_info = GFH_MAGIC + b"\x00" * (RSA_MODULUS_OFFSET // 2 - 4)
    anti_clone = b"\xab" * (RSA_MODULUS_OFFSET // 2)
    modulus = b"\xcd" * RSA_KEY_LEN
    sig = b"\xef" * SIGNATURE_LEN
    blob = file_info + anti_clone + modulus + sig
    assert len(blob) == RSA_MODULUS_OFFSET + RSA_KEY_LEN + SIGNATURE_LEN
    return blob


def test_parse_layout():
    blob = _build_fake_auth()
    auth = parse_auth_sv5(blob)
    assert auth.rsa_modulus == b"\xcd" * RSA_KEY_LEN
    assert auth.signature == b"\xef" * SIGNATURE_LEN
    assert auth.total_size == len(blob)


def test_bad_magic():
    blob = b"XXXX" + b"\x00" * (RSA_MODULUS_OFFSET + RSA_KEY_LEN + SIGNATURE_LEN - 4)
    with pytest.raises(AuthSv5ParseError):
        parse_auth_sv5(blob)


def test_too_small():
    with pytest.raises(AuthSv5ParseError):
        parse_auth_sv5(b"MMM\x01")
