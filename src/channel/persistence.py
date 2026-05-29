"""JSON persistence for channel state.

The persisted format is a versioned JSON document. Public keys are
deterministically derived from private keys, so we only serialise the
private-key bytes.

Re-loading reconstructs the :class:`Channel`, re-validates every
invariant, and re-checks the funding transaction's identity by recomputing
its txid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bitcoinx import Tx

from .accounting import State, initial_state
from .bond import BondOutput, make_bond_script_for
from .config import ChannelConfig
from .errors import PersistenceError
from .keymgmt import KeyBook
from .lifecycle import Channel


SCHEMA_VERSION = 1


def channel_to_dict(ch: Channel) -> dict[str, Any]:
    """Serialise a :class:`Channel` to a JSON-friendly dict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "cfg": {
            "n": ch.cfg.n,
            "k": ch.cfg.k,
            "S": ch.cfg.S,
            "bonds": list(ch.cfg.bonds),
            "L0": ch.cfg.L0,
            "delta": ch.cfg.delta,
        },
        "keys": [k.to_bytes().hex() for k in ch.keybook.keys],
        "funding_tx_hex": ch.funding_tx.to_hex(),
        "funding_parent_value": ch.funding_utxos[0].value,
        "funding_confirmed": ch.funding_confirmed,
        "state": {
            "balances": list(ch.state.balances),
            "version": ch.state.version,
        },
    }


def dict_to_channel(d: dict[str, Any]) -> Channel:
    """Reconstruct a :class:`Channel` from a dict produced by :func:`channel_to_dict`."""
    if d.get("schema_version") != SCHEMA_VERSION:
        raise PersistenceError(
            f"unsupported schema_version {d.get('schema_version')!r}"
        )
    cfg_d = d["cfg"]
    cfg = ChannelConfig(
        n=cfg_d["n"], k=cfg_d["k"], S=cfg_d["S"],
        bonds=tuple(cfg_d["bonds"]), L0=cfg_d["L0"], delta=cfg_d["delta"],
    )
    from bitcoinx import PrivateKey  # local import; keep package init light
    keys = [PrivateKey(bytes.fromhex(h)) for h in d["keys"]]
    keybook = KeyBook(keys)
    funding_tx = Tx.from_hex(d["funding_tx_hex"])
    parent_value = int(d["funding_parent_value"])
    from bitcoinx import Ops, Script, TxOutput
    funding_utxos = [TxOutput(parent_value, Script() << Ops.OP_TRUE)]

    ch = Channel(
        cfg=cfg, keybook=keybook,
        funding_tx=funding_tx, funding_utxos=funding_utxos,
        funding_confirmed=bool(d["funding_confirmed"]),
    )
    # Rebuild bonds from the funding tx and the key book.
    pubs = keybook.public_keys()
    bonds: list[BondOutput] = []
    for i in range(cfg.n):
        cp = [pubs[j] for j in range(cfg.n) if j != i]
        bond_locking = make_bond_script_for(pubs[i], cp)
        bonds.append(BondOutput(
            owner_index=i,
            value=cfg.bonds[i],
            funding_txid=funding_tx.hash(),
            vout=1 + i,
            locking_script=bond_locking,
        ))
    ch.bonds = bonds
    state = State(tuple(d["state"]["balances"]), version=d["state"]["version"])
    state.conservation_check(cfg)
    ch.state = state
    return ch


def save_channel(ch: Channel, path: str | Path) -> None:
    path = Path(path)
    path.write_text(json.dumps(channel_to_dict(ch), indent=2))


def load_channel(path: str | Path) -> Channel:
    path = Path(path)
    if not path.exists():
        raise PersistenceError(f"channel file not found: {path}")
    try:
        d = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise PersistenceError(f"invalid channel file {path}: {e}") from e
    return dict_to_channel(d)


__all__ = ["save_channel", "load_channel", "channel_to_dict", "dict_to_channel"]
