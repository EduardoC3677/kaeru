from __future__ import annotations


class KaeruError(Exception):
    pass


class DriverError(KaeruError):
    pass


class DeviceNotFoundError(KaeruError):
    pass


class AuthError(KaeruError):
    pass


class UnsupportedSocError(KaeruError):
    pass
