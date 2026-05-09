from __future__ import annotations


class KaeruError(Exception):
    pass


class TransportError(KaeruError):
    pass


class DriverError(TransportError):
    pass


class DeviceNotFoundError(TransportError):
    pass


class TimeoutError(TransportError):
    pass


class ProtocolError(KaeruError):
    pass


class AuthError(KaeruError):
    pass


class UnsupportedSocError(KaeruError):
    pass
