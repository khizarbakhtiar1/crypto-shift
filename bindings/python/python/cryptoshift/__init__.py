"""CryptoShift — crypto-agility SDK for post-quantum migration."""

from cryptoshift._native import (
    ALGORITHMS,
    decrypt,
    encrypt,
    keygen,
    scan,
    sign,
    verify,
    version,
)

__all__ = [
    "ALGORITHMS",
    "decrypt",
    "encrypt",
    "keygen",
    "scan",
    "sign",
    "verify",
    "version",
]

__version__ = version()
