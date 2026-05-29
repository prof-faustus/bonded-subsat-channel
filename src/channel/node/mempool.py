"""Transaction mempool: admission, relay queue, and replacement detection.

Admission validates each tx against the UTXO set through
:func:`channel.node.validation.validate_tx`, which runs every input
through the real Bitcoin Script interpreter. Admission is rejected on
double-spend (any input is also spent by another tx in the mempool) and
on validation failure.

Replacement: the mempool tracks the **highest sequence number per
spent input** seen so far; a newer transaction whose inputs all carry
strictly higher sequence numbers and are not yet final replaces the
older transaction. This is the original-protocol replacement rule and
is what the channel construction relies on to overtake a superseded
state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from bitcoinx import Tx

from ..errors import ChannelError
from .blockstore import BlockStore
from .validation import ValidationResult, validate_tx


_log = logging.getLogger(__name__)


class MempoolError(ChannelError):
    pass


@dataclass
class MempoolEntry:
    tx: Tx
    fee: int
    sequence_by_input: tuple[int, ...] = ()


@dataclass
class Mempool:
    """In-memory transaction mempool with conflict detection."""

    store: BlockStore
    entries: dict[bytes, MempoolEntry] = field(default_factory=dict)
    spent_by: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    # Observers receive (event, tx); event in {"admit", "evict", "replace"}.
    observers: list[Callable[[str, Tx], None]] = field(default_factory=list)

    def add_observer(self, fn: Callable[[str, Tx], None]) -> None:
        self.observers.append(fn)

    def _notify(self, event: str, tx: Tx) -> None:
        for fn in self.observers:
            try:
                fn(event, tx)
            except Exception:  # noqa: BLE001 -- observer failure should not crash
                _log.exception("mempool observer failed")

    def size(self) -> int:
        return len(self.entries)

    def contains(self, txid: bytes) -> bool:
        return txid in self.entries

    def get(self, txid: bytes) -> Optional[Tx]:
        e = self.entries.get(txid)
        return e.tx if e else None

    def admit(self, tx: Tx) -> ValidationResult:
        """Try to admit ``tx`` to the mempool.

        Replacement semantics: if every input of ``tx`` conflicts with
        an existing entry's input but carries a strictly higher sequence
        number, evict the conflict and admit ``tx``. Otherwise reject.
        """
        txid = tx.hash()
        if txid in self.entries:
            return ValidationResult(True, "already in mempool")

        # Conflict detection.
        conflicting_txids: set[bytes] = set()
        for tin in tx.inputs:
            owner = self.spent_by.get((bytes(tin.prev_hash), int(tin.prev_idx)))
            if owner is not None and owner != txid:
                conflicting_txids.add(owner)

        if conflicting_txids:
            # Replacement rule: every input of ``tx`` that conflicts must
            # carry a strictly higher sequence number than the conflicting
            # input. We accept replacement of exactly one conflict at a
            # time (the typical case for channel states).
            if len(conflicting_txids) != 1:
                return ValidationResult(False, "multi-conflict replacement not accepted")
            (old_txid,) = conflicting_txids
            old = self.entries[old_txid]
            # Find old's inputs against the conflicting outpoints.
            old_seqs: dict[tuple[bytes, int], int] = {
                (bytes(ti.prev_hash), int(ti.prev_idx)): int(ti.sequence)
                for ti in old.tx.inputs
            }
            for tin in tx.inputs:
                key = (bytes(tin.prev_hash), int(tin.prev_idx))
                if key in old_seqs:
                    if int(tin.sequence) <= old_seqs[key]:
                        return ValidationResult(
                            False,
                            f"replacement rejected: input {key[0][::-1].hex()}:{key[1]} "
                            f"seq {tin.sequence} <= existing seq {old_seqs[key]}",
                        )
            # Validate new tx through the interpreter.
            result = validate_tx(tx, self.store)
            if not result.ok:
                return result
            # Evict old.
            self._evict_internal(old_txid, reason="replaced")
            self._insert(tx, result)
            self._notify("replace", tx)
            return result

        # No conflict — straight admit.
        result = validate_tx(tx, self.store)
        if not result.ok:
            return result
        self._insert(tx, result)
        self._notify("admit", tx)
        return result

    def _insert(self, tx: Tx, result: ValidationResult) -> None:
        txid = tx.hash()
        seqs = tuple(int(ti.sequence) for ti in tx.inputs)
        self.entries[txid] = MempoolEntry(tx=tx, fee=result.fee, sequence_by_input=seqs)
        for tin in tx.inputs:
            self.spent_by[(bytes(tin.prev_hash), int(tin.prev_idx))] = txid

    def _evict_internal(self, txid: bytes, reason: str = "") -> Optional[Tx]:
        entry = self.entries.pop(txid, None)
        if entry is None:
            return None
        for tin in entry.tx.inputs:
            key = (bytes(tin.prev_hash), int(tin.prev_idx))
            if self.spent_by.get(key) == txid:
                del self.spent_by[key]
        self._notify("evict", entry.tx)
        return entry.tx

    def evict(self, txid: bytes) -> Optional[Tx]:
        return self._evict_internal(txid)

    def all_txs(self) -> list[Tx]:
        return [e.tx for e in self.entries.values()]


__all__ = ["Mempool", "MempoolEntry", "MempoolError"]
