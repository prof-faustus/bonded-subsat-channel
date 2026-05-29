"""Phase 4 GATE: routing with staggered horizons.

Covers:
- secret-revealed path settles every hop on the claim branch;
- secret-never-revealed path returns every hop;
- intermediary cannot claim incoming hop without publishing the secret;
- path-length feasibility bound is enforced.
"""

from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey, hash160  # noqa: E402

from channel.errors import RoutingError  # noqa: E402
from channel.routing import (  # noqa: E402
    Hop, Path,
    assert_staggering_invariant,
    build_claim_tx,
    build_path,
    build_return_tx,
    settle_secret_not_revealed,
    settle_secret_revealed,
)
from channel.verify import spend_verifies, verify_spend  # noqa: E402


def _keys(n: int) -> list[PrivateKey]:
    return [PrivateKey((10000 + i).to_bytes(32, "big")) for i in range(n)]


# ---------------------------------------------------------------------------
# Staggering & path-length bound
# ---------------------------------------------------------------------------


def test_staggering_invariant_holds_for_built_path() -> None:
    keys = _keys(5)
    preimage = b"\x07" * 32
    path = build_path(keys, value=1000, L0=1000, delta=100, preimage=preimage)
    assert path.length() == 4
    assert_staggering_invariant(path)


def test_path_length_bound_rejects_overlong_path() -> None:
    keys = _keys(11)  # 10 hops
    preimage = b"\x09" * 32
    # 10 hops * delta=100 = 1000 >= L0 -> infeasible
    with pytest.raises(RoutingError):
        build_path(keys, value=1000, L0=1000, delta=100, preimage=preimage)


# ---------------------------------------------------------------------------
# Settlement outcomes
# ---------------------------------------------------------------------------


def test_secret_revealed_every_hop_settles() -> None:
    keys = _keys(4)
    preimage = b"\x21" * 32
    path = build_path(keys, value=1000, L0=2000, delta=100, preimage=preimage)
    txs = settle_secret_revealed(path)
    assert len(txs) == path.length()


def test_secret_not_revealed_every_hop_returns() -> None:
    keys = _keys(4)
    preimage = b"\x33" * 32
    path = build_path(keys, value=1000, L0=2000, delta=100, preimage=preimage)
    txs = settle_secret_not_revealed(path)
    assert len(txs) == path.length()


# ---------------------------------------------------------------------------
# Intermediary safety
# ---------------------------------------------------------------------------


def test_intermediary_cannot_claim_without_preimage() -> None:
    """An intermediary handed only an image cannot satisfy the IF branch."""
    keys = _keys(3)
    real_preimage = b"\x55" * 32
    path = build_path(keys, value=500, L0=1500, delta=100, preimage=real_preimage)
    hop = path.hops[1]  # middle hop, claim branch belongs to keys[2]

    # The interpreter only accepts the IF branch with a preimage hashing to
    # the embedded image. With a guessed-wrong preimage, the spend fails.
    wrong = b"\xCC" * 32
    assert hash160(wrong) != hop.image_h160
    with pytest.raises(RoutingError):
        build_claim_tx(hop, wrong)


def test_claim_with_correct_preimage_verifies() -> None:
    keys = _keys(3)
    preimage = b"\x66" * 32
    path = build_path(keys, value=400, L0=1500, delta=100, preimage=preimage)
    for j, hop in enumerate(path.hops):
        tx, utxo = build_claim_tx(hop, preimage)
        assert verify_spend(tx, 0, utxo), f"hop {j} did not verify"


def test_return_with_payee_key_fails_through_vm() -> None:
    """Returning a hop requires the payer's signature; payee cannot return."""
    keys = _keys(3)
    preimage = b"\x77" * 32
    path = build_path(keys, value=400, L0=1500, delta=100, preimage=preimage)
    hop = path.hops[0]

    # Construct a return tx but sign with the payee's key instead of payer.
    from bitcoinx import Script, Tx, TxInput, TxOutput
    from channel.config import SIGHASH_ALL_FORKID
    from channel.scripts import hop_return_unlock, p2pkh_script
    from channel.signing import sign_input

    prev_hash, prev_idx = hop.funding_outpoint
    tx_in = TxInput(prev_hash, prev_idx, Script(b""), 0)
    out = TxOutput(hop.value, p2pkh_script(hop.payer_priv.public_key))
    tx = Tx(1, [tx_in], [out], hop.locktime)
    bad_sig = sign_input(tx, 0, hop.value, hop.locking_script(),
                         hop.payee_priv, SIGHASH_ALL_FORKID)
    tx.inputs[0] = TxInput(prev_hash, prev_idx,
                            hop_return_unlock(bad_sig), 0)
    assert not spend_verifies(tx, 0, hop.utxo())
