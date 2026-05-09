from __future__ import annotations

from dataclasses import dataclass

from kaeru_mtk.data.sla_keys import SlaKey, find_sla_key_by_modulus
from kaeru_mtk.protocol.brom import BromProtocol
from kaeru_mtk.utils.errors import AuthError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)

GFH_MAGIC = b"MMM\x01"
GFH_TYPE_ANTI_CLONE = 0x0203
GFH_TYPE_FILE_INFO = 0x0201

AUTH_SV5_GFH_HEADER_LEN = 0x30
AUTH_SV5_MODULUS_OFFSET = 0x4C4
AUTH_SV5_MODULUS_LEN = 256
AUTH_SV5_SIGNATURE_OFFSET = 0x7C4
AUTH_SV5_SIGNATURE_LEN = 256


@dataclass
class AuthFile:
    path: str
    data: bytes
    modulus: bytes
    signature: bytes
    sla_key: SlaKey | None = None


def parse_auth_file(path: str, data: bytes) -> AuthFile:
    if not data.startswith(GFH_MAGIC):
        raise AuthError(f"Invalid auth file {path}: missing MMM\\x01 magic")

    end_mod = AUTH_SV5_MODULUS_OFFSET + AUTH_SV5_MODULUS_LEN
    if len(data) < end_mod:
        raise AuthError(f"Truncated auth file {path}: {len(data)} bytes")

    modulus = data[AUTH_SV5_MODULUS_OFFSET:end_mod]
    sig_start = len(data) - AUTH_SV5_SIGNATURE_LEN
    if sig_start < 0:
        sig_start = AUTH_SV5_SIGNATURE_OFFSET
    signature = data[sig_start:sig_start + AUTH_SV5_SIGNATURE_LEN]

    sla_key = find_sla_key_by_modulus(modulus)

    return AuthFile(
        path=path,
        data=data,
        modulus=modulus,
        signature=signature,
        sla_key=sla_key,
    )


class SlaAuthenticator:
    def __init__(self, brom: BromProtocol):
        self._brom = brom
        self._authenticated = False

    @property
    def authenticated(self) -> bool:
        return self._authenticated

    def authenticate(self, auth_data: bytes) -> bool:
        auth = parse_auth_file("auth_sv5.auth", auth_data)

        log.info("SLA auth file: modulus starts with %s, key match: %s",
                 auth.modulus[:8].hex(),
                 f"#{auth.sla_key.index}" if auth.sla_key else "none")

        log.info("Getting BROM challenge...")
        challenge = self._brom.get_challenge()
        log.info("Challenge: %s bytes", len(challenge))

        log.info("Sending auth data...")
        resp = self._brom.send_auth_data(auth_data)
        log.info("Auth response: %s", resp.hex() if resp else "empty")

        if len(resp) >= 1 and resp[0] == 0x00:
            self._authenticated = True
            log.info("SLA authentication successful")
            return True

        log.warning("SLA authentication failed (expected without private key)")
        self._authenticated = False
        return False

    def authenticate_with_cert_chain(self, auth_data: bytes, cert_data: bytes) -> bool:
        combined = auth_data + cert_data
        return self.authenticate(combined)
