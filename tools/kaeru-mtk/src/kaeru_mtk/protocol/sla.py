from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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


def perform_sla(brom: BromClient, *, auth: AuthSv5File, signer) -> SlaChallenge:
    framing = brom._f
    framing.expect_echo(int(BromCmd.SLA_CHALLENGE))
    challenge_len = framing.read_be32()
    if challenge_len == 0 or challenge_len > 1024:
        raise ProtocolError(f"SLA_CHALLENGE bad len {challenge_len}")
    challenge = framing.read_bytes(challenge_len)
    status = framing.read_be16()
    if status != 0:
        raise ProtocolError(f"SLA_CHALLENGE status=0x{status:04x}")

    try:
        response = signer(challenge, auth)
    except Exception as e:
        raise AuthError(f"SLA signer failed: {e}") from e

    framing.expect_echo(int(BromCmd.SLA_RESPONSE))
    framing.write_be32(len(response))
    framing.write_bytes(response)
    status = framing.read_be16()
    if status != 0:
        return SlaChallenge(
            state=SlaState.FAILED, challenge=challenge, response=response
        )

    log.info("SLA handshake OK (challenge=%d B, response=%d B)", challenge_len, len(response))
    return SlaChallenge(state=SlaState.RESPONSE_OK, challenge=challenge, response=response)
