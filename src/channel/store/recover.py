"""Channel recovery from durable store.

On restart, the system reloads every channel's latest state from the
:class:`SystemStore` and reconstructs a :class:`Channel` object.
"""

from __future__ import annotations

import json
from typing import Optional

from bitcoinx import PrivateKey, Tx

from ..accounting import State
from ..bond import BondOutput, make_bond_script_for
from ..config import ChannelConfig
from ..errors import StateError
from ..keymgmt import KeyBook
from ..lifecycle import Channel
from .store import SystemStore


def persist_channel(store: SystemStore, ch: Channel) -> None:
    cfg_json = json.dumps({
        "n": ch.cfg.n,
        "k": ch.cfg.k,
        "S": ch.cfg.S,
        "bonds": list(ch.cfg.bonds),
        "L0": ch.cfg.L0,
        "delta": ch.cfg.delta,
    })
    keys_hex = ",".join(k.to_bytes().hex() for k in ch.keybook.keys)
    parent_value = ch.funding_utxos[0].value
    store.put_channel_meta(
        channel_id=ch.funding_txid(),
        cfg_json=cfg_json,
        keys_hex=keys_hex,
        funding_tx_hex=ch.funding_tx.to_hex(),
        funding_confirmed=ch.funding_confirmed,
        parent_value=parent_value,
    )
    state_json = json.dumps({
        "balances": list(ch.state.balances),
        "version": ch.state.version,
    })
    store.put_channel_state(ch.funding_txid(), ch.state.version, state_json)


def recover_channel(store: SystemStore, channel_id: bytes) -> Optional[Channel]:
    meta = store.get_channel_meta(channel_id)
    if meta is None:
        return None
    cfg_d = json.loads(meta["cfg_json"])  # type: ignore[arg-type]
    cfg = ChannelConfig(
        n=cfg_d["n"], k=cfg_d["k"], S=cfg_d["S"],
        bonds=tuple(cfg_d["bonds"]),
        L0=cfg_d["L0"], delta=cfg_d["delta"],
    )
    keys = [PrivateKey(bytes.fromhex(h)) for h in str(meta["keys_hex"]).split(",")]
    book = KeyBook(keys)
    funding_tx = Tx.from_hex(str(meta["funding_tx_hex"]))
    from bitcoinx import Ops, Script, TxOutput
    parent_value = int(str(meta["parent_value"]))
    funding_utxos = [TxOutput(parent_value, Script() << Ops.OP_TRUE)]

    ch = Channel(
        cfg=cfg, keybook=book,
        funding_tx=funding_tx, funding_utxos=funding_utxos,
        funding_confirmed=bool(meta["funding_confirmed"]),
    )
    pubs = book.public_keys()
    bonds: list[BondOutput] = []
    for i in range(cfg.n):
        cp = [pubs[j] for j in range(cfg.n) if j != i]
        bond_locking = make_bond_script_for(pubs[i], cp)
        bonds.append(BondOutput(
            owner_index=i, value=cfg.bonds[i],
            funding_txid=funding_tx.hash(),
            vout=1 + i,
            locking_script=bond_locking,
        ))
    ch.bonds = bonds

    latest = store.get_latest_channel_state(channel_id)
    if latest is None:
        # Fresh channel with no transfers applied yet.
        from ..accounting import initial_state
        ch.state = initial_state(cfg)
    else:
        _v, sj = latest
        d = json.loads(sj)
        s = State(tuple(d["balances"]), version=d["version"])
        s.conservation_check(cfg)
        ch.state = s
    return ch


__all__ = ["persist_channel", "recover_channel"]
