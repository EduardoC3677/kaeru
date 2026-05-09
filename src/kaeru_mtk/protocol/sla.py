from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from kaeru_mtk.data.sla_keys import SlaKey, find_sla_key_by_modulus
from kaeru_mtk.formats.auth_sv5 import AuthSv5File
from kaeru_mtk.protocol.brom import BromClient, BromCmd
from kaeru_mtk.utils.errors import AuthError, ProtocolError
from kaeru_mtk.utils.logging import get_logger

log = get_logger(__name__)


class SlaState(Enum):
    INACTIVE = "inactive"
    CHALLENGE_SENT = "challenge_sent"
    RESPONSE_OK = "response_ok"
    FAILED = "failed"


@dataclass
class SlaChallenge:
    state: SlaState = SlaState.INACTIVE
    challenge: bytes | None = None
    response: bytes | None = None
    key: SlaKey | None = None


SlaSigner = Callable[[bytes, AuthSv5File, "SlaKey | None"], bytes]


def sha256_signer(challenge: bytes, auth: AuthSv5File, key: SlaKey | None) -> bytes:
    digest = hashlib.sha256(challenge + auth.rsa_modulus).digest()
    body = digest + auth.signature[: 256 - len(digest)]
    return body[:256]


def rsa_pss_signer(_challenge: bytes, _auth: AuthSv5File, _key: SlaKey | None) -> bytes:
    raise AuthError(
        "RSA-PSS signing requires an OEM private key. The four public keys "
        "extracted from SLA_Challenge.dll are RSA-2048 PUBLIC moduli only; "
        "the matching private keys never leave OPPO infra. Use --skip-auth or "
        "an exploit (kamakiri / kamakiri2 / iguana) to bypass SLA instead."
    )


def perform_sla(
    brom: BromClient,
    *,
    auth: AuthSv5File,
    signer: SlaSigner = sha256_signer,
) -> SlaChallenge:
    framing = brom._f
    framing.expect_echo(int(BromCmd.SLA_CHALLENGE))
    challenge_len = framing.read_be32()
    if challenge_len == 0 or challenge_len > 1024:
        raise ProtocolError(f"SLA_CHALLENGE bad len {challenge_len}")
    challenge = framing.read_bytes(challenge_len)
    status = framing.read_be16()
    if status != 0:
        raise ProtocolError(f"SLA_CHALLENGE status=0x{status:04x}")

    key = find_sla_key_by_modulus(auth.rsa_modulus)
    if key:
        log.info(
            "SLA challenge: %d bytes; matched embedded RSA key #%d",
            challenge_len, key.index,
        )
    else:
        log.info(
            "SLA challenge: %d bytes; auth modulus not in known SLA key set",
            challenge_len,
        )

    try:
        response = signer(challenge, auth, key)
    except AuthError:
        raise
    except Exception as e:
        raise AuthError(f"SLA signer failed: {e}") from e

    framing.expect_echo(int(BromCmd.SLA_RESPONSE))
    framing.write_be32(len(response))
    framing.write_bytes(response)
    status = framing.read_be16()
    if status != 0:
        return SlaChallenge(
            state=SlaState.FAILED,
            challenge=challenge,
            response=response,
            key=key,
        )

    log.info("SLA handshake OK (challenge=%dB, response=%dB)", challenge_len, len(response))
    return SlaChallenge(
        state=SlaState.RESPONSE_OK,
        challenge=challenge,
        response=response,
        key=key,
    )


__all__ = ["SlaChallenge", "SlaState", "perform_sla", "rsa_pss_signer", "sha256_signer"]
