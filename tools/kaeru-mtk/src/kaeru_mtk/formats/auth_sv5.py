from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kaeru_mtk.utils.errors import KaeruError


class AuthSv5ParseError(KaeruError):
    pass


GFH_MAGIC = b"MMM\x01"
RSA_MODULUS_OFFSET = 0x4C4
RSA_KEY_LEN = 256
SIGNATURE_LEN = 256


@dataclass
class AuthSv5File:
    raw: bytes
    rsa_modulus: bytes
    signature: bytes
    file_info: bytes
    anti_clone: bytes

    @property
    def total_size(self) -> int:
        return len(self.raw)


def parse_auth_sv5(source: str | bytes | Path) -> AuthSv5File:
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else bytes(source)

    if len(data) < RSA_MODULUS_OFFSET + RSA_KEY_LEN + SIGNATURE_LEN:
        raise AuthSv5ParseError(f"auth_sv5 too small: {len(data)} bytes")

    if not data.startswith(GFH_MAGIC):
        raise AuthSv5ParseError(
            f"auth_sv5 GFH magic mismatch: {data[:4].hex()} (expected {GFH_MAGIC.hex()})"
        )

    file_info = data[: RSA_MODULUS_OFFSET // 2]
    anti_clone = data[RSA_MODULUS_OFFSET // 2 : RSA_MODULUS_OFFSET]
    modulus = data[RSA_MODULUS_OFFSET : RSA_MODULUS_OFFSET + RSA_KEY_LEN]
    signature = data[-SIGNATURE_LEN:]

    return AuthSv5File(
        raw=data,
        rsa_modulus=modulus,
        signature=signature,
        file_info=file_info,
        anti_clone=anti_clone,
    )


def modulus_hex(auth: AuthSv5File) -> str:
    return auth.rsa_modulus.hex()
