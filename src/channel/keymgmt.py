"""Key management and key-replacement transfer.

Each participant holds one :class:`bitcoinx.PrivateKey`. A
*key-replacement transfer* models the sale or hand-off of a participant's
position in the channel: after the transfer, the buyer's key controls the
position and the seller's key cannot produce a valid spend. This is
modelled by simply replacing the seller's key with the buyer's key in the
:class:`KeyBook` and rotating the channel so the new key appears in every
future locking script. Old scripts (already-built UTXOs) remain locked to
the old key set; new scripts are locked to the new key set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from bitcoinx import PrivateKey, PublicKey

from .errors import KeyReplacementError


@dataclass
class KeyBook:
    """Mutable map ``party_index -> PrivateKey``.

    Operations are explicit (no implicit replacement) so any change to the
    key set is auditable in the call sites that drive the lifecycle.
    """

    keys: list[PrivateKey] = field(default_factory=list)

    @classmethod
    def random(cls, n: int) -> "KeyBook":
        return cls([PrivateKey.from_random() for _ in range(n)])

    @classmethod
    def from_ints(cls, ints: Sequence[int]) -> "KeyBook":
        """Deterministic constructor for tests."""
        return cls([PrivateKey(i.to_bytes(32, "big")) for i in ints])

    @property
    def n(self) -> int:
        return len(self.keys)

    def public_keys(self) -> list[PublicKey]:
        return [k.public_key for k in self.keys]

    def private(self, index: int) -> PrivateKey:
        if not 0 <= index < self.n:
            raise KeyReplacementError(f"index {index} out of [0, {self.n})")
        return self.keys[index]

    def public(self, index: int) -> PublicKey:
        return self.private(index).public_key

    def replace(self, index: int, new_priv: PrivateKey) -> None:
        """Replace party ``index``'s private key with ``new_priv``.

        This models the key-replacement step of a position transfer: after
        the call, the previous holder cannot sign for ``index`` (since
        their key is no longer in the book and the new locking scripts
        built from this book commit to the new public key).
        """
        if not 0 <= index < self.n:
            raise KeyReplacementError(f"index {index} out of [0, {self.n})")
        self.keys[index] = new_priv

    def copy(self) -> "KeyBook":
        return KeyBook(list(self.keys))


__all__ = ["KeyBook"]
