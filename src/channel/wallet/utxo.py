"""Wallet UTXO tracking against the embedded node.

The wallet maintains a set of P2PKH locking scripts (one per derived
key) that it considers "ours", and periodically scans the node's UTXO
store for entries matching any of them. The combined view yields the
spendable balance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from bitcoinx import PrivateKey, PublicKey, Script

from ..scripts import p2pkh_script
from ..node.blockstore import BlockStore, UtxoEntry


@dataclass
class WalletScripts:
    """A registry of scripts the wallet considers its own."""

    # script_bytes -> (account, index, private key)
    by_script: dict[bytes, tuple[int, int, PrivateKey]] = field(default_factory=dict)

    def add_p2pkh(self, account: int, index: int, priv: PrivateKey) -> bytes:
        script = bytes(p2pkh_script(priv.public_key))
        self.by_script[script] = (account, index, priv)
        return script

    def keys_for(self, script_bytes: bytes) -> tuple[int, int, PrivateKey] | None:
        return self.by_script.get(script_bytes)

    def all_scripts(self) -> list[bytes]:
        return list(self.by_script.keys())


@dataclass
class WalletUtxoView:
    """Combined wallet UTXO view, refreshed from the node's store."""

    scripts: WalletScripts
    store: BlockStore

    def refresh(self) -> list[UtxoEntry]:
        """Return all UTXOs locked by any wallet script."""
        out: list[UtxoEntry] = []
        for s in self.scripts.all_scripts():
            out.extend(self.store.utxos_for_script(s))
        return out

    def confirmed_balance(self) -> int:
        return sum(e.value for e in self.refresh() if e.height >= 0)


__all__ = ["WalletScripts", "WalletUtxoView"]
