"""Hierarchical-deterministic key derivation (BIP32-style).

Wraps :class:`bitcoinx.BIP32PrivateKey` so the wallet can derive an
arbitrary tree of keys from a single seed. Encrypted seed storage uses a
passphrase-derived key (PBKDF2-HMAC-SHA256) and AES-GCM via the standard
``hashlib`` / ``hmac`` / built-in ``cryptography`` is avoided to keep the
dependency surface tight; we use a simple authenticated XOR-based stream
cipher derived from the passphrase. This is sufficient for local at-rest
protection on a single machine (the design point — the wallet is never
exposed over a remote API), and is documented as such.

For consumer deployment a hardened encryption layer would replace this
module's :func:`encrypt_seed` / :func:`decrypt_seed` pair; the rest of
the wallet does not depend on the encryption mechanism.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from bitcoinx import BIP32PrivateKey, BitcoinRegtest, PrivateKey, PublicKey

from ..errors import ChannelError


class WalletError(ChannelError):
    pass


# ---------------------------------------------------------------------------
# Seed encryption (PBKDF2-derived key + HMAC-authenticated stream XOR)
# ---------------------------------------------------------------------------


_KDF_ITERS = 200_000
_NONCE_LEN = 16


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, _KDF_ITERS, dklen=32)


def _stream(nonce: bytes, key: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def encrypt_seed(seed: bytes, passphrase: str) -> bytes:
    """Encrypt ``seed`` with ``passphrase`` and return a self-contained blob.

    Blob layout: ``salt(16) || nonce(16) || ciphertext || hmac_tag(32)``.
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(_NONCE_LEN)
    key = _derive_key(passphrase.encode("utf-8"), salt)
    keystream = _stream(nonce, key, len(seed))
    ct = bytes(a ^ b for a, b in zip(seed, keystream))
    tag = hmac.new(key, salt + nonce + ct, hashlib.sha256).digest()
    return salt + nonce + ct + tag


def decrypt_seed(blob: bytes, passphrase: str) -> bytes:
    if len(blob) < 16 + _NONCE_LEN + 32:
        raise WalletError("decrypt_seed: blob too short")
    salt = blob[:16]
    nonce = blob[16:16 + _NONCE_LEN]
    ct_tag = blob[16 + _NONCE_LEN:]
    ct = ct_tag[:-32]
    tag = ct_tag[-32:]
    key = _derive_key(passphrase.encode("utf-8"), salt)
    expected_tag = hmac.new(key, salt + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise WalletError("decrypt_seed: passphrase incorrect or blob corrupt")
    keystream = _stream(nonce, key, len(ct))
    return bytes(a ^ b for a, b in zip(ct, keystream))


# ---------------------------------------------------------------------------
# HD key tree
# ---------------------------------------------------------------------------


@dataclass
class HDWallet:
    """A simple HD wallet rooted at one BIP32 master key.

    Derivation path: ``m / account / index``. Each leaf private key is
    derived via ``child_safe`` to skip indices whose derivation would
    accidentally produce an invalid key.
    """

    master: BIP32PrivateKey

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDWallet":
        if len(seed) < 16:
            raise WalletError("seed must be at least 16 bytes")
        return cls(master=BIP32PrivateKey.from_seed(seed, BitcoinRegtest))

    @classmethod
    def new(cls, seed: Optional[bytes] = None) -> "HDWallet":
        if seed is None:
            seed = secrets.token_bytes(32)
        return cls.from_seed(seed)

    def account(self, index: int) -> BIP32PrivateKey:
        return self.master.child_safe(index)

    def derive(self, account: int, index: int) -> PrivateKey:
        acct = self.account(account)
        return acct.child_safe(index)

    def public_at(self, account: int, index: int) -> PublicKey:
        return self.derive(account, index).public_key


__all__ = [
    "WalletError",
    "HDWallet",
    "encrypt_seed",
    "decrypt_seed",
]
