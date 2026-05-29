"""Higher-level wallet utilities: balance, history, address generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from bitcoinx import PrivateKey, PublicKey

from .hd import HDWallet
from .utxo import WalletScripts, WalletUtxoView


@dataclass
class WalletManager:
    """Glues HD derivation, the wallet-scripts registry, and the UTXO view."""

    hd: HDWallet
    scripts: WalletScripts
    view: WalletUtxoView

    @classmethod
    def fresh(cls, hd: HDWallet, store_view: WalletUtxoView) -> "WalletManager":
        return cls(hd=hd, scripts=store_view.scripts, view=store_view)

    def new_receive_address(self, account: int, index: int) -> PublicKey:
        priv = self.hd.derive(account, index)
        self.scripts.add_p2pkh(account, index, priv)
        return priv.public_key

    def balance(self) -> int:
        return self.view.confirmed_balance()

    def list_utxos(self) -> list[tuple[bytes, int, int]]:
        out: list[tuple[bytes, int, int]] = []
        for u in self.view.refresh():
            out.append((u.txid, u.vout, u.value))
        return out


__all__ = ["WalletManager"]
