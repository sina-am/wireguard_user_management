class UserDoesNotExist(Exception):
    pass


class PeerAlreadyExist(Exception):
    pass


class PeerNotFound(Exception):
    pass


class WireGuardConfigFileError(Exception):
    pass


class InvalidPublicKey(Exception):
    pass


class IPAddressAlreadyExist(Exception):
    pass
