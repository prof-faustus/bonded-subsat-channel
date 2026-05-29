"""Phase 8 GATE: HD wallet end-to-end on the embedded regtest node.

Verifies:
- HD derivation is deterministic from seed.
- Seed encryption roundtrip with correct passphrase succeeds; wrong fails.
- Wallet sees a coinbase as its own UTXO after a block is mined to a
  derived script.
- A wallet-built payment is admitted to the mempool (interpreter-verified)
  and mined.
"""

from __future__ import annotations

import os
import secrets
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey  # noqa: E402

from channel.node.network import EmbeddedNode  # noqa: E402
from channel.scripts import p2pkh_script  # noqa: E402
from channel.wallet.builder import FundingOutput, build_and_sign_payment, select_utxos  # noqa: E402
from channel.wallet.hd import HDWallet, WalletError, decrypt_seed, encrypt_seed  # noqa: E402
from channel.wallet.manage import WalletManager  # noqa: E402
from channel.wallet.send import pay_p2pkh  # noqa: E402
from channel.wallet.utxo import WalletScripts, WalletUtxoView  # noqa: E402


# ---------------------------------------------------------------------------
# Seed encryption
# ---------------------------------------------------------------------------


def test_seed_encryption_roundtrip() -> None:
    seed = b"S" * 32
    blob = encrypt_seed(seed, "correct-passphrase")
    assert decrypt_seed(blob, "correct-passphrase") == seed


def test_seed_decryption_with_wrong_passphrase_fails() -> None:
    blob = encrypt_seed(b"S" * 32, "right")
    with pytest.raises(WalletError):
        decrypt_seed(blob, "wrong")


# ---------------------------------------------------------------------------
# HD derivation
# ---------------------------------------------------------------------------


def test_hd_derivation_deterministic() -> None:
    seed = b"deterministic_seed_for_testing_!" * 1
    w1 = HDWallet.from_seed(seed)
    w2 = HDWallet.from_seed(seed)
    p1 = w1.derive(0, 5)
    p2 = w2.derive(0, 5)
    assert p1.to_bytes() == p2.to_bytes()


# ---------------------------------------------------------------------------
# Wallet sees coinbase
# ---------------------------------------------------------------------------


def test_wallet_sees_coinbase_after_block_mined_to_it() -> None:
    node = EmbeddedNode()
    hd = HDWallet.from_seed(b"X" * 32)
    scripts = WalletScripts()
    view = WalletUtxoView(scripts=scripts, store=node.blockstore)
    mgr = WalletManager.fresh(hd, view)
    pk = mgr.new_receive_address(0, 0)

    node.generate_block(p2pkh_script(pk))
    assert mgr.balance() == node.coinbase_reward


def test_wallet_send_payment_mined() -> None:
    node = EmbeddedNode()
    sender_hd = HDWallet.from_seed(b"S" * 32)
    recip_hd = HDWallet.from_seed(b"R" * 32)
    sender_scripts = WalletScripts()
    recip_scripts = WalletScripts()
    sender_view = WalletUtxoView(sender_scripts, node.blockstore)
    recip_view = WalletUtxoView(recip_scripts, node.blockstore)
    sender_mgr = WalletManager.fresh(sender_hd, sender_view)
    recip_mgr = WalletManager.fresh(recip_hd, recip_view)

    sender_pk = sender_mgr.new_receive_address(0, 0)
    recip_pk = recip_mgr.new_receive_address(0, 0)
    change_pk = sender_mgr.new_receive_address(0, 1)

    # Fund the sender.
    node.generate_block(p2pkh_script(sender_pk))
    assert sender_mgr.balance() == node.coinbase_reward

    # Pay 1_000_000 sat to the recipient.
    result = pay_p2pkh(sender_view, recip_pk, 1_000_000, change_pk, node)
    assert result.accepted, result.reason
    assert result.fee > 0

    # Mine the payment.
    miner_priv = PrivateKey.from_random()
    node.generate_block(p2pkh_script(miner_priv.public_key))
    assert recip_mgr.balance() == 1_000_000
    # Sender balance = original coinbase - 1_000_000 - fee.
    assert sender_mgr.balance() == node.coinbase_reward - 1_000_000 - result.fee


# ---------------------------------------------------------------------------
# Coin selection
# ---------------------------------------------------------------------------


def test_select_utxos_largest_first() -> None:
    from channel.node.blockstore import UtxoEntry
    utxos = [UtxoEntry(b"\x00" * 32, i, v, b"x", 0) for i, v in enumerate([10, 50, 30, 1])]
    sel = select_utxos(utxos, 60)
    assert sum(u.value for u in sel) >= 60
    # Largest-first means [50, 30] is selected before [10, 1].
    assert sel[0].value == 50


def test_select_utxos_insufficient_funds() -> None:
    from channel.node.blockstore import UtxoEntry
    from channel.wallet.builder import WalletBuildError
    utxos = [UtxoEntry(b"\x00" * 32, 0, 10, b"x", 0)]
    with pytest.raises(WalletBuildError):
        select_utxos(utxos, 100)
