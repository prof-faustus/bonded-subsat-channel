"""Channel lifecycle: open, transfer, refresh, close, contested, coalition.

The lifecycle drives the orchestration of a channel through its phases. It
ties together :mod:`scripts`, :mod:`signing`, :mod:`accounting`,
:mod:`bond`, and :mod:`keymgmt`.

Conventions used throughout:

- The funding transaction has output index 0 for the channel output and
  output indices 1..n for the bond outputs (one per party).
- A *state transaction* spends the channel output and pays
  ``Q*(a)_i`` satoshis to party ``i`` via P2PKH. It is held off-chain until
  one of: (a) cooperative close, which co-signs the close transaction
  spending the channel output *and* every bond output (returning each
  bond); or (b) contested close, which broadcasts the current state
  transaction and then permits the honest counterparties to forfeit the
  offender's bond.
- ``nSequence`` values encode the state version (see DECISIONS.md D4);
  ``0xFFFFFFFF`` marks a final transaction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from bitcoinx import Ops, PrivateKey, PublicKey, Script, Tx, TxInput, TxOutput

from .accounting import (
    State,
    assert_conservation_over_sequence,
    ensure_whole_satoshi,
    initial_state,
    quantise,
    transfer,
)
from .bond import (
    BondOutput,
    make_bond_script_for,
    sign_bond_forfeit,
    sign_bond_return,
)
# Note: make_bond_script_for is also imported by build_channel_outputs
# below; keep this import block tidy.
from .config import (
    ChannelConfig,
    COOP_LOCKTIME,
    FINAL_SEQUENCE,
    MAX_NON_FINAL_SEQUENCE,
    SIGHASH_ALL_FORKID,
    START_SEQUENCE,
)
from .errors import (
    StateError,
    UnconfirmedFundingError,
    VerificationError,
)
from .keymgmt import KeyBook
from .scripts import (
    channel_funding_script,
    channel_funding_unlock,
    p2pkh_script,
    p2pkh_unlock,
)
from .signing import sign_input
from .verify import verify_all_inputs, verify_spend


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sequence encoding
# ---------------------------------------------------------------------------


def sequence_for_version(version: int) -> int:
    """Map an integer state version to an ``nSequence`` value.

    Version 0 uses ``START_SEQUENCE`` (= 0). Each transfer bumps the version
    by 1 and so the sequence by 1. The final replaceable value is
    ``MAX_NON_FINAL_SEQUENCE`` (0xFFFFFFFE); reaching it forces a refresh.
    """
    if version < 0:
        raise StateError(f"version must be >= 0 (got {version})")
    seq = START_SEQUENCE + version
    if seq >= FINAL_SEQUENCE:
        raise StateError(
            f"state version {version} exhausts non-final sequence space; "
            "refresh the channel"
        )
    return seq


# ---------------------------------------------------------------------------
# Funding transaction outputs (shared between standalone and wallet-funded)
# ---------------------------------------------------------------------------


def build_channel_outputs(cfg: "ChannelConfig", keybook: "KeyBook",
                           ) -> list[TxOutput]:
    """Return the canonical output vector for a channel funding tx.

    Output 0 is the n-of-n channel CMS output of value ``S``; outputs
    1..n are the per-participant bond outputs of value ``b_i``. Used by
    both :meth:`Channel.open` (standalone placeholder parent) and the
    wallet's funding-tx builder (real wallet-UTXO parent).
    """
    if keybook.n != cfg.n:
        raise StateError(f"keybook size {keybook.n} != cfg.n {cfg.n}")
    pubs = keybook.public_keys()
    outs: list[TxOutput] = [TxOutput(cfg.S, channel_funding_script(pubs))]
    for i in range(cfg.n):
        cp = [pubs[j] for j in range(cfg.n) if j != i]
        outs.append(TxOutput(cfg.bonds[i], make_bond_script_for(pubs[i], cp)))
    return outs


# ---------------------------------------------------------------------------
# Funding transaction
# ---------------------------------------------------------------------------


@dataclass
class Channel:
    """A bonded sub-satoshi channel.

    The object accumulates the funding transaction, bond descriptors, the
    current key book, the current state, and a confirmation flag. All
    operations route through methods on this object so the
    confirm-before-sign discipline can be enforced centrally.
    """

    cfg: ChannelConfig
    keybook: KeyBook
    funding_tx: Tx
    funding_utxos: list[TxOutput]  # parent UTXOs feeding the funding tx
    funding_confirmed: bool = False
    state: State = field(init=False)
    bonds: list[BondOutput] = field(init=False)

    # ----- construction -----------------------------------------------------

    @classmethod
    def open(cls, cfg: ChannelConfig, keybook: KeyBook,
             parent_outpoint: tuple[bytes, int] = (b"\x00" * 32, 0),
             parent_value: int | None = None) -> "Channel":
        """Construct a fresh channel via a funding transaction.

        Standalone path: the funding transaction's input is a single
        placeholder OP_TRUE input. This is sufficient for unit tests and
        for the channel-layer's own correctness; production funding goes
        through :meth:`from_funding_tx` after the wallet has built a real
        UTXO-spending funding transaction (see
        :func:`channel.wallet.builder.build_channel_funding_tx`).
        """
        total = cfg.S + sum(cfg.bonds)
        ensure_whole_satoshi(total)
        if parent_value is None:
            parent_value = total

        outputs = build_channel_outputs(cfg, keybook)
        prev_hash, prev_idx = parent_outpoint
        tx_in = TxInput(prev_hash, prev_idx, Script(b""), FINAL_SEQUENCE)
        funding_tx = Tx(1, [tx_in], outputs, 0)
        funding_utxos = [TxOutput(parent_value, Script() << Ops.OP_TRUE)]
        return cls._wrap_funding(cfg, keybook, funding_tx, funding_utxos)

    @classmethod
    def from_funding_tx(cls, cfg: ChannelConfig, keybook: KeyBook,
                         funding_tx: Tx,
                         parent_utxos: list[TxOutput]) -> "Channel":
        """Wrap an externally-built (e.g. wallet-funded) funding transaction.

        The funding transaction must carry the canonical channel-output
        vector at outputs 0..n: output 0 is the n-of-n channel CMS
        output of value ``S``, outputs 1..n are the per-participant bond
        outputs. This invariant is checked.

        ``parent_utxos`` are the UTXOs the wallet spent into the funding
        tx; they are stored for downstream auditing but are no longer the
        OP_TRUE placeholder of :meth:`open`.
        """
        expected = build_channel_outputs(cfg, keybook)
        if len(funding_tx.outputs) < 1 + cfg.n:
            raise StateError(
                f"funding_tx has {len(funding_tx.outputs)} outputs; "
                f"need >= {1 + cfg.n}"
            )
        for i in range(1 + cfg.n):
            actual = funding_tx.outputs[i]
            want = expected[i]
            if actual.value != want.value:
                raise StateError(
                    f"funding_tx.outputs[{i}].value = {actual.value} "
                    f"!= expected {want.value}"
                )
            if bytes(actual.script_pubkey) != bytes(want.script_pubkey):
                raise StateError(
                    f"funding_tx.outputs[{i}].script_pubkey mismatch"
                )
        return cls._wrap_funding(cfg, keybook, funding_tx, parent_utxos)

    @classmethod
    def _wrap_funding(cls, cfg: ChannelConfig, keybook: KeyBook,
                       funding_tx: Tx,
                       funding_utxos: list[TxOutput]) -> "Channel":
        """Common tail used by :meth:`open` and :meth:`from_funding_tx`."""
        if keybook.n != cfg.n:
            raise StateError(f"keybook size {keybook.n} != cfg.n {cfg.n}")
        pubs = keybook.public_keys()
        funding_txid = funding_tx.hash()
        bonds: list[BondOutput] = []
        for i in range(cfg.n):
            cp = [pubs[j] for j in range(cfg.n) if j != i]
            bond_locking = make_bond_script_for(pubs[i], cp)
            bonds.append(BondOutput(
                owner_index=i,
                value=cfg.bonds[i],
                funding_txid=funding_txid,
                vout=1 + i,
                locking_script=bond_locking,
            ))
        ch = cls(
            cfg=cfg,
            keybook=keybook,
            funding_tx=funding_tx,
            funding_utxos=funding_utxos,
            funding_confirmed=False,
        )
        ch.state = initial_state(cfg, funder_index=0)
        ch.bonds = bonds
        return ch

    # ----- confirmation discipline -----------------------------------------

    def mark_confirmed(self) -> None:
        """Flip the funding-tx confirmation flag.

        Until this is called, any operation that would sign a child of the
        funding transaction raises :class:`UnconfirmedFundingError`. This is
        the *entire* handling required for the unconfirmed-funding identifier
        window — the protocol does not invoke any other feature here.
        """
        self.funding_confirmed = True

    def _require_confirmed(self) -> None:
        if not self.funding_confirmed:
            raise UnconfirmedFundingError(
                "funding tx not yet confirmed; refuse to sign children"
            )

    # ----- accessors -------------------------------------------------------

    def channel_output_value(self) -> int:
        return self.funding_tx.outputs[0].value

    def channel_locking_script(self) -> Script:
        return self.funding_tx.outputs[0].script_pubkey

    def funding_txid(self) -> bytes:
        return self.funding_tx.hash()

    # ----- transfer --------------------------------------------------------

    def apply_transfer(self, sender: int, recipient: int, delta: int) -> State:
        """Apply a single micro-unit transfer, returning the new state."""
        self.state = transfer(self.state, sender, recipient, delta, self.cfg)
        return self.state

    def apply_sequence(self, ops: Sequence[tuple[int, int, int]]) -> State:
        """Apply many transfers; conservation re-checked after each."""
        self.state = assert_conservation_over_sequence(self.state, ops, self.cfg)
        return self.state

    # ----- state transaction (off-chain) -----------------------------------

    def build_state_tx(self, state: State) -> tuple[Tx, list[TxOutput]]:
        """Build the state transaction for ``state`` (unsigned).

        Spends the channel output and pays each party their ``Q*(state)``
        satoshis via P2PKH. ``nSequence`` encodes the state version so that
        a higher-version state supersedes a lower-version state under the
        original replacement rule.

        Returns the tx and the list of UTXOs being spent (one entry, the
        channel output).
        """
        q = quantise(state, self.cfg)
        seq = sequence_for_version(state.version)
        # Spend only the channel output for a state tx (bonds are not
        # touched until close).
        tx_in = TxInput(self.funding_txid(), 0, Script(b""), seq)
        outputs: list[TxOutput] = []
        for i, qi in enumerate(q):
            if qi > 0:
                outputs.append(TxOutput(
                    ensure_whole_satoshi(qi),
                    p2pkh_script(self.keybook.public(i)),
                ))
        if not outputs:
            # All payouts rounded to zero; add a placeholder so the tx is
            # well-formed. (Not expected in practice; defensively included.)
            outputs.append(TxOutput(0, Script() << Ops.OP_RETURN))
        tx = Tx(1, [tx_in], outputs, 0)
        utxos = [TxOutput(self.channel_output_value(), self.channel_locking_script())]
        return tx, utxos

    def sign_state_tx(self, state: State) -> tuple[Tx, list[TxOutput]]:
        """Build, n-of-n sign, and return the state transaction.

        The confirm-before-sign discipline is enforced.
        """
        self._require_confirmed()
        tx, utxos = self.build_state_tx(state)
        sigs = [
            sign_input(tx, 0, utxos[0].value, utxos[0].script_pubkey,
                       self.keybook.private(i), SIGHASH_ALL_FORKID)
            for i in range(self.cfg.n)
        ]
        tx.inputs[0] = TxInput(
            tx.inputs[0].prev_hash, tx.inputs[0].prev_idx,
            channel_funding_unlock(sigs), tx.inputs[0].sequence,
        )
        return tx, utxos

    # ----- cooperative close ----------------------------------------------

    def build_close_tx(self, state: State) -> tuple[Tx, list[TxOutput]]:
        """Build the cooperative-close transaction (unsigned).

        Spends:
            input 0: channel output
            input i (1..n): bond i-1 (returning to owner)

        Pays each party ``q_i + b_i`` via a single P2PKH output (when
        ``q_i + b_i > 0``).
        """
        q = quantise(state, self.cfg)
        # Inputs: channel output + each bond. All inputs marked final
        # (FINAL_SEQUENCE) because a cooperative close is final on broadcast.
        inputs: list[TxInput] = [
            TxInput(self.funding_txid(), 0, Script(b""), FINAL_SEQUENCE)
        ]
        utxos: list[TxOutput] = [
            TxOutput(self.channel_output_value(), self.channel_locking_script())
        ]
        for i in range(self.cfg.n):
            inputs.append(TxInput(
                self.funding_txid(), 1 + i, Script(b""), FINAL_SEQUENCE,
            ))
            utxos.append(self.bonds[i].utxo())

        outputs: list[TxOutput] = []
        for i in range(self.cfg.n):
            payout = q[i] + self.cfg.bonds[i]
            ensure_whole_satoshi(payout)
            if payout > 0:
                outputs.append(TxOutput(
                    payout, p2pkh_script(self.keybook.public(i)),
                ))
        tx = Tx(1, inputs, outputs, COOP_LOCKTIME)
        return tx, utxos

    def cooperative_close(self, state: State | None = None) -> tuple[Tx, list[TxOutput]]:
        """Co-sign and return the cooperative-close transaction.

        On all-party signatures the close is final immediately and settles
        ahead of the channel's horizon.
        """
        self._require_confirmed()
        s = state if state is not None else self.state
        tx, utxos = self.build_close_tx(s)

        # Input 0: n-of-n channel-output signatures.
        chan_sigs = [
            sign_input(tx, 0, utxos[0].value, utxos[0].script_pubkey,
                       self.keybook.private(i), SIGHASH_ALL_FORKID)
            for i in range(self.cfg.n)
        ]
        tx.inputs[0] = TxInput(
            tx.inputs[0].prev_hash, tx.inputs[0].prev_idx,
            channel_funding_unlock(chan_sigs), tx.inputs[0].sequence,
        )

        # Inputs 1..n: bond return branches.
        for i in range(self.cfg.n):
            in_idx = 1 + i
            script_sig = sign_bond_return(
                tx, in_idx, self.bonds[i], self.keybook.private(i),
            )
            tx.inputs[in_idx] = TxInput(
                tx.inputs[in_idx].prev_hash, tx.inputs[in_idx].prev_idx,
                script_sig, tx.inputs[in_idx].sequence,
            )

        verify_all_inputs(tx, utxos)
        return tx, utxos

    # ----- contested close ------------------------------------------------

    def superseded_state_tx_for(self, version: int, allocation: tuple[int, ...]) -> tuple[Tx, list[TxOutput]]:
        """Build and n-of-n co-sign a (potentially superseded) state tx.

        ``version < current`` simulates the offender holding an old state.
        Used by the contested-close test.
        """
        self._require_confirmed()
        s = State(allocation, version=version)
        s.conservation_check(self.cfg)
        # Temporarily swap state and reuse sign_state_tx.
        saved = self.state
        try:
            self.state = s
            tx, utxos = self.sign_state_tx(s)
        finally:
            self.state = saved
        return tx, utxos

    def forfeit_bond_tx(self, offender: int,
                         tower_pubkey: "PublicKey | None" = None,
                         tower_fee: int = 0,
                         ) -> tuple[Tx, list[TxOutput]]:
        """Build and co-sign the bond-forfeiture transaction.

        Pays the offender's bond:
        - If ``tower_pubkey`` is given and ``tower_fee > 0``, the first
          output of the forfeiture transaction is a P2PKH paying the
          tower ``tower_fee`` satoshis. The remainder goes to the honest
          counterparties pro-rata.
        - Otherwise the full bond is split among the honest counterparties
          (the path used when no watchtower is involved).

        D14 — Script-enforced tower payment. The honest counterparties
        sign the forfeit branch with ``SIGHASH_ALL | FORKID``, which
        commits to every output of the transaction. A tower that
        attempts to broadcast a modified forfeit (e.g. one that omits
        the tower-fee output or redirects it elsewhere) will fail the
        ``OP_CHECKMULTISIG`` check because the signatures do not match
        the tampered output set. The tower therefore profits **only by
        broadcasting the exact forfeit the counterparties pre-signed**,
        and gains nothing from inaction (no forfeit broadcast → no fee
        paid) or from attempted collusion (any tampering invalidates
        the multisig). This is the property §17 of the spec calls for.
        """
        self._require_confirmed()
        if not 0 <= offender < self.cfg.n:
            raise StateError(f"offender {offender} out of [0, {self.cfg.n})")
        if tower_fee < 0:
            raise StateError(f"tower_fee must be >= 0 (got {tower_fee})")

        bond = self.bonds[offender]
        if tower_fee > bond.value:
            raise StateError(
                f"tower_fee {tower_fee} exceeds bond value {bond.value}"
            )
        honest_indices = [i for i in range(self.cfg.n) if i != offender]

        tx_in = TxInput(self.funding_txid(), 1 + offender, Script(b""),
                        FINAL_SEQUENCE)

        outputs: list[TxOutput] = []
        # Tower output first (deterministic position): the tower's payee
        # script is committed-to by the counterparties' SIGHASH_ALL sigs.
        if tower_pubkey is not None and tower_fee > 0:
            ensure_whole_satoshi(tower_fee)
            outputs.append(TxOutput(tower_fee, p2pkh_script(tower_pubkey)))

        # Remainder split among honest counterparties.
        remaining = bond.value - (tower_fee if tower_pubkey is not None else 0)
        m = len(honest_indices)
        share = remaining // m
        rem = remaining - share * m
        for k, idx in enumerate(honest_indices):
            v = share + (rem if k == m - 1 else 0)
            ensure_whole_satoshi(v)
            if v > 0:
                outputs.append(TxOutput(v, p2pkh_script(self.keybook.public(idx))))

        tx = Tx(1, [tx_in], outputs, 0)
        utxos = [bond.utxo()]

        cp_privs = [self.keybook.private(i) for i in honest_indices]
        script_sig = sign_bond_forfeit(tx, 0, bond, cp_privs)
        tx.inputs[0] = TxInput(tx_in.prev_hash, tx_in.prev_idx, script_sig,
                                tx_in.sequence)
        verify_all_inputs(tx, utxos)
        return tx, utxos


# ---------------------------------------------------------------------------
# Refresh (roll the channel forward into a successor with later horizon)
# ---------------------------------------------------------------------------


def refresh_channel(ch: Channel, new_L: int) -> Channel:
    """Roll ``ch`` forward into a successor channel with horizon ``new_L > L0``.

    Conservation: the new channel's initial state has the same per-party
    micro-unit allocation as ``ch.state`` (parties index-aligned). The
    funder index of the successor is taken from the largest balance in
    ``ch.state`` (deterministic, only used to seed the initial single-owner
    invariant of :func:`initial_state`; we then immediately overwrite the
    state to preserve the carried allocation).
    """
    if new_L <= ch.cfg.L0:
        raise StateError(f"new_L {new_L} must exceed cfg.L0 {ch.cfg.L0}")
    new_cfg = ChannelConfig(
        n=ch.cfg.n, k=ch.cfg.k, S=ch.cfg.S, bonds=ch.cfg.bonds,
        L0=new_L, delta=ch.cfg.delta,
    )
    new_book = ch.keybook.copy()
    successor = Channel.open(new_cfg, new_book)
    successor.mark_confirmed()
    # Preserve the carried allocation (version resets; refresh is a fresh
    # channel funded by the cooperative close of the predecessor).
    successor.state = State(ch.state.balances, version=0)
    return successor


__all__ = [
    "Channel",
    "refresh_channel",
    "sequence_for_version",
]
