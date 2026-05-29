"""Atomic multi-hop routing with staggered horizons.

A path ``i_0 -> i_1 -> ... -> i_l`` is realised by ``l`` hashlocked hops,
all conditioned on a single shared secret ``x`` with image
``h = HASH160(x)``. Hop ``j`` (``i_j -> i_{j+1}``) carries a return-branch
locktime ``L_j = L_0 - j*Delta``, where ``Delta`` is the worst-case
confirmation bound and ``L_j`` strictly decreases along the path. Thus
when the secret is revealed, each intermediary has at least ``Delta`` time
to claim its incoming hop after its outgoing hop is claimed; and when the
secret is never revealed, each intermediary's outgoing return precedes its
incoming return.

The script for every hop is :func:`channel.scripts.hop_script` — there is
**no** in-script timelock opcode. Timing is enforced on the return
transaction's ``nLockTime``.

Feasibility bound. The final hop must retain at least one confirmation
window: ``L_{l-1} = L_0 - (l-1)*Delta >= Delta``, i.e. ``l <= L_0/Delta``.
We require strict ``l < L_0/Delta`` (one full window margin) and reject
overlong paths in :func:`build_path`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from bitcoinx import (
    Ops, PrivateKey, PublicKey, Script, Tx, TxInput, TxOutput, hash160,
)

from .config import FINAL_SEQUENCE, SIGHASH_ALL_FORKID
from .errors import RoutingError, VerificationError
from .scripts import (
    hop_claim_unlock, hop_return_unlock, hop_script, p2pkh_script,
)
from .signing import sign_input
from .verify import spend_verifies, verify_spend


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hop and path data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hop:
    """A single routing hop ``payer -> payee``.

    Attributes
    ----------
    payer_priv, payee_priv
        Private keys controlling the return and claim branches.
    value
        Satoshi value funded into this hop.
    image_h160
        ``HASH160(x)``; the same image is used across all hops on the path.
    locktime
        ``nLockTime`` for the return transaction. This is the *only*
        timing primitive used; the script does not contain a timelock
        opcode (CLTV/CSV are inert no-ops post-Genesis).
    funding_outpoint
        ``(prev_hash, prev_idx)`` of the UTXO funding this hop.
    """

    payer_priv: PrivateKey
    payee_priv: PrivateKey
    value: int
    image_h160: bytes
    locktime: int
    funding_outpoint: tuple[bytes, int]

    def locking_script(self) -> Script:
        return hop_script(self.image_h160,
                          self.payee_priv.public_key,
                          self.payer_priv.public_key)

    def utxo(self) -> TxOutput:
        return TxOutput(self.value, self.locking_script())


@dataclass(frozen=True)
class Path:
    """A complete path of ``l`` hops, indexed 0..l-1 from source to sink."""

    hops: tuple[Hop, ...]
    L0: int
    delta: int
    image_h160: bytes
    preimage: bytes | None  # known to the sink only; ``None`` for intermediaries

    def length(self) -> int:
        return len(self.hops)


# ---------------------------------------------------------------------------
# Path construction
# ---------------------------------------------------------------------------


def build_path(
    keys_on_path: Sequence[PrivateKey],
    value: int,
    L0: int,
    delta: int,
    preimage: bytes,
    funding_outpoints: Sequence[tuple[bytes, int]] | None = None,
) -> Path:
    """Build an ``(l = len(keys_on_path) - 1)``-hop path with staggered horizons.

    Parameters
    ----------
    keys_on_path
        ``l+1`` keys: ``keys_on_path[j]`` is the payer of hop ``j`` and the
        payee of hop ``j-1`` (so intermediary nodes appear twice in the
        chain implicitly via their key).
    value
        Common satoshi value on every hop (we don't model per-hop fees;
        the paper's routing-fee analysis is reported in the security
        section rather than carried in the implementation).
    L0
        Initial channel horizon.
    delta
        Worst-case confirmation bound for staggering.
    preimage
        The secret ``x``; its ``HASH160`` is embedded as the image.
    funding_outpoints
        Optional per-hop ``(prev_hash, prev_idx)``. Defaults to deterministic
        synthetic outpoints (one per hop).
    """
    if len(keys_on_path) < 2:
        raise RoutingError("path must have at least one hop")
    l = len(keys_on_path) - 1
    if not isinstance(L0, int) or L0 <= 0:
        raise RoutingError(f"L0 must be a positive int (got {L0!r})")
    if not isinstance(delta, int) or delta <= 0:
        raise RoutingError(f"delta must be a positive int (got {delta!r})")
    # Strict feasibility: each hop's locktime L_j = L_0 - j*delta must be
    # >= delta (the final hop must retain one full confirmation window).
    # Equivalently l < L_0 / delta.
    if l * delta >= L0:
        raise RoutingError(
            f"path length {l} infeasible: l*delta={l*delta} >= L0={L0}"
        )
    image = hash160(preimage)

    if funding_outpoints is None:
        funding_outpoints = [(bytes([j + 1] * 32), 0) for j in range(l)]
    if len(funding_outpoints) != l:
        raise RoutingError(
            f"funding_outpoints has length {len(funding_outpoints)} != l={l}"
        )

    hops: list[Hop] = []
    for j in range(l):
        L_j = L0 - j * delta
        hops.append(Hop(
            payer_priv=keys_on_path[j],
            payee_priv=keys_on_path[j + 1],
            value=value,
            image_h160=image,
            locktime=L_j,
            funding_outpoint=funding_outpoints[j],
        ))
    return Path(tuple(hops), L0=L0, delta=delta,
                image_h160=image, preimage=preimage)


# ---------------------------------------------------------------------------
# Claim and return transactions for a single hop
# ---------------------------------------------------------------------------


def build_claim_tx(hop: Hop, preimage: bytes,
                   sink_payout_pk: PublicKey | None = None) -> tuple[Tx, TxOutput]:
    """Build and sign the claim (IF) spend of ``hop`` revealing ``preimage``.

    The output is a P2PKH to the payee (the natural recipient of the
    claimed value); ``sink_payout_pk`` overrides the payout key when given
    (used at the sink of a path that pays out to an external key).
    """
    if hash160(preimage) != hop.image_h160:
        raise RoutingError("preimage does not match hop image")
    prev_hash, prev_idx = hop.funding_outpoint
    tx_in = TxInput(prev_hash, prev_idx, Script(b""), FINAL_SEQUENCE)
    pk = sink_payout_pk if sink_payout_pk is not None else hop.payee_priv.public_key
    out = TxOutput(hop.value, p2pkh_script(pk))
    tx = Tx(1, [tx_in], [out], 0)
    sig = sign_input(tx, 0, hop.value, hop.locking_script(),
                     hop.payee_priv, SIGHASH_ALL_FORKID)
    tx.inputs[0] = TxInput(prev_hash, prev_idx,
                            hop_claim_unlock(sig, preimage), FINAL_SEQUENCE)
    return tx, hop.utxo()


def build_return_tx(hop: Hop) -> tuple[Tx, TxOutput]:
    """Build and sign the return (ELSE) spend of ``hop``.

    The transaction's ``nLockTime`` is the hop's locktime ``L_j``. Note:
    the input's ``nSequence`` is **not** final — locktime activation
    requires at least one non-final input. We use sequence 0 for clarity.
    """
    prev_hash, prev_idx = hop.funding_outpoint
    tx_in = TxInput(prev_hash, prev_idx, Script(b""), 0)
    out = TxOutput(hop.value, p2pkh_script(hop.payer_priv.public_key))
    tx = Tx(1, [tx_in], [out], hop.locktime)
    sig = sign_input(tx, 0, hop.value, hop.locking_script(),
                     hop.payer_priv, SIGHASH_ALL_FORKID)
    tx.inputs[0] = TxInput(prev_hash, prev_idx,
                            hop_return_unlock(sig), 0)
    return tx, hop.utxo()


# ---------------------------------------------------------------------------
# Whole-path settlement: secret-revealed and secret-not-revealed
# ---------------------------------------------------------------------------


def settle_secret_revealed(path: Path) -> list[Tx]:
    """Claim every hop with the revealed secret, asserting each verifies.

    Returns the list of claim transactions, one per hop.
    """
    if path.preimage is None:
        raise RoutingError("settle_secret_revealed requires path.preimage")
    txs: list[Tx] = []
    for hop in path.hops:
        tx, utxo = build_claim_tx(hop, path.preimage)
        verify_spend(tx, 0, utxo)
        txs.append(tx)
    return txs


def settle_secret_not_revealed(path: Path) -> list[Tx]:
    """Return every hop to its payer (the secret is never revealed)."""
    txs: list[Tx] = []
    for hop in path.hops:
        tx, utxo = build_return_tx(hop)
        verify_spend(tx, 0, utxo)
        txs.append(tx)
    return txs


# ---------------------------------------------------------------------------
# Staggering invariant
# ---------------------------------------------------------------------------


def assert_staggering_invariant(path: Path) -> None:
    """Each successive hop has a locktime exactly ``delta`` smaller.

    Also asserts the final hop retains at least ``delta`` confirmations of
    margin (``l*delta < L_0``, see :func:`build_path`).
    """
    prev = path.L0 + path.delta  # so first comparison succeeds
    for j, hop in enumerate(path.hops):
        expected = path.L0 - j * path.delta
        if hop.locktime != expected:
            raise RoutingError(
                f"hop {j} locktime {hop.locktime} != expected {expected}"
            )
        if prev - hop.locktime != path.delta:
            raise RoutingError(
                f"hops {j-1} and {j} differ by {prev - hop.locktime}, "
                f"expected delta {path.delta}"
            )
        prev = hop.locktime
    if path.hops[-1].locktime < path.delta:
        raise RoutingError(
            f"final hop locktime {path.hops[-1].locktime} < delta {path.delta}"
        )


__all__ = [
    "Hop",
    "Path",
    "build_path",
    "build_claim_tx",
    "build_return_tx",
    "settle_secret_revealed",
    "settle_secret_not_revealed",
    "assert_staggering_invariant",
]
