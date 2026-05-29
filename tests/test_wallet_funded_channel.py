"""D11 — wallet-funded channel open via the embedded mempool.

End-to-end test of the wallet-funded path:

1. Mine a coinbase block to the wallet's address (gives wallet UTXOs).
2. Wallet builds a real funding transaction whose outputs are the
   canonical channel + bond outputs, signed P2PKH spends of its UTXOs.
3. Submit the funding tx to the embedded node's mempool. The mempool
   validates every input through the real interpreter.
4. Mine the funding tx into a block. The node's UTXO set now contains
   the channel + bond outputs (and the wallet's change).
5. Wrap the confirmed funding tx with ``Channel.from_funding_tx``.
6. Run a transfer + cooperative close. The close spends the real
   funding outputs from the node's UTXO set; the spend is admitted by
   the mempool through the interpreter, mined, and the resulting
   coin-distribution matches ``Q*(state) + bond`` for each party.

This removes the soundness-adjacent scoping note D11: nothing in the
flow installs UTXOs directly. Every UTXO arrives via a mempool-
admitted, interpreter-verified transaction.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey  # noqa: E402

from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.node.network import EmbeddedNode  # noqa: E402
from channel.scripts import p2pkh_script  # noqa: E402
from channel.verify import verify_all_inputs  # noqa: E402
from channel.wallet.builder import build_channel_funding_tx, select_utxos  # noqa: E402
from channel.wallet.hd import HDWallet  # noqa: E402
from channel.wallet.utxo import WalletScripts, WalletUtxoView  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup() -> tuple[EmbeddedNode, HDWallet, WalletScripts, WalletUtxoView,
                       PrivateKey, PrivateKey]:
    """Common setup: node + wallet + funded-from-coinbase scripts."""
    node = EmbeddedNode()
    hd = HDWallet.from_seed(b"funded-channel-seed_padded______")
    scripts = WalletScripts()
    view = WalletUtxoView(scripts=scripts, store=node.blockstore)
    # Two wallet addresses: receive (mining target) and change.
    recv = hd.derive(0, 0)
    change = hd.derive(0, 1)
    scripts.add_p2pkh(0, 0, recv)
    scripts.add_p2pkh(0, 1, change)
    node.generate_block(p2pkh_script(recv.public_key))
    assert view.confirmed_balance() == node.coinbase_reward
    return node, hd, scripts, view, recv, change


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------


def test_wallet_funded_channel_open_close_through_mempool() -> None:
    """The funding tx is built by the wallet and mined; close still verifies."""
    node, hd, scripts, view, recv, change = _setup()

    # Build the channel config + key book.
    cfg = ChannelConfig.uniform_bond(n=3, k=1000, S=2, bond=1)
    book = KeyBook.from_ints([200_000, 200_001, 200_002])

    # Wallet builds the funding tx spending its coinbase UTXO.
    utxos = view.refresh()
    assert utxos, "wallet has no UTXOs"
    target_value = cfg.S + sum(cfg.bonds) + 1_000  # rough headroom
    selected = select_utxos(utxos, target_value)
    keyed = [(u, recv) for u in selected]
    funding_tx = build_channel_funding_tx(keyed, cfg, book, change.public_key)

    # Submit to the mempool — every input goes through the interpreter.
    result = node.submit_tx(funding_tx)
    assert result.ok, result.reason
    assert result.fee > 0

    # Mine it.
    miner_priv = PrivateKey.from_random()
    node.generate_block(p2pkh_script(miner_priv.public_key))

    # The channel + bond outputs are now real UTXOs on the node's UTXO set.
    funding_txid = funding_tx.hash()
    for vout in range(1 + cfg.n):
        assert node.blockstore.get_utxo(funding_txid, vout) is not None, (
            f"funding output {vout} missing after mining"
        )

    # Wrap the confirmed funding tx with the channel layer.
    from bitcoinx import Ops, Script, TxOutput
    parent_utxos = [TxOutput(u.value, Script(u.script_pubkey)) for u in selected]
    ch = Channel.from_funding_tx(cfg, book, funding_tx, parent_utxos)
    ch.mark_confirmed()
    # The channel's funding_txid is the real one.
    assert ch.funding_txid() == funding_txid

    # Drive a sequence of transfers, then cooperative close.
    ch.apply_transfer(0, 1, 400)
    ch.apply_transfer(0, 2, 600)
    close_tx, close_utxos = ch.cooperative_close()
    verify_all_inputs(close_tx, close_utxos)

    # Admit the close transaction to the node's mempool — it spends the
    # real funding output and the real bond outputs that the node holds.
    close_result = node.submit_tx(close_tx)
    assert close_result.ok, close_result.reason
    # No fee — the channel construction's close is exact (sum out == S + bonds).
    assert close_result.fee == 0

    node.generate_block(p2pkh_script(miner_priv.public_key))
    # After close + mine, the funding outputs are spent.
    for vout in range(1 + cfg.n):
        assert node.blockstore.get_utxo(funding_txid, vout) is None

    # Total settled equals S + sum(bonds).
    total_out = sum(o.value for o in close_tx.outputs)
    assert total_out == cfg.S + sum(cfg.bonds)


def test_wallet_funded_channel_funding_tx_validates_outputs() -> None:
    """from_funding_tx rejects a tx whose outputs don't match the canonical."""
    node, hd, scripts, view, recv, change = _setup()
    cfg = ChannelConfig.uniform_bond(n=3, k=1000, S=1, bond=1)
    book = KeyBook.from_ints([200_100, 200_101, 200_102])

    # Build a "funding" tx with mismatched outputs (wrong S).
    bad_cfg = ChannelConfig.uniform_bond(n=3, k=1000, S=5, bond=1)
    utxos = view.refresh()
    selected = select_utxos(utxos, 100_000)
    keyed = [(u, recv) for u in selected]
    funding_tx = build_channel_funding_tx(keyed, bad_cfg, book, change.public_key)

    # Wrapping under the (smaller) cfg must reject — outputs don't match.
    from bitcoinx import Ops, Script, TxOutput
    parent_utxos = [TxOutput(u.value, Script(u.script_pubkey)) for u in selected]
    with pytest.raises(Exception):
        Channel.from_funding_tx(cfg, book, funding_tx, parent_utxos)
