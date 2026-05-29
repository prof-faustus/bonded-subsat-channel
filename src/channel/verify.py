"""Interpreter-backed spend verification.

This module exposes the single point of contact with the real Bitcoin Script
interpreter from :mod:`bitcoinx`. Every spend in the test suite **must**
flow through :func:`verify_spend` or :func:`spend_verifies`; signature-only
spot-checks are explicitly disallowed because they would not exercise the
locking + unlocking script through the VM.
"""

from __future__ import annotations

import logging
from typing import Optional

from bitcoinx import Tx, TxOutput, TxInputContext

from .config import make_interpreter_limits
from .errors import VerificationError


_log = logging.getLogger(__name__)


def verify_spend(tx: Tx, input_index: int, utxo: TxOutput) -> bool:
    """Run the interpreter on ``tx``'s ``input_index``th input.

    Returns ``True`` if the script succeeds. Raises :class:`VerificationError`
    or propagates the underlying ``bitcoinx`` exception otherwise. Callers
    that want a boolean rather than an exception should use
    :func:`spend_verifies`.
    """
    limits = make_interpreter_limits()
    ctx = TxInputContext(tx, input_index, utxo)
    result = ctx.verify_input(limits, is_utxo_after_genesis=True)
    if not result:
        raise VerificationError(
            f"interpreter rejected input {input_index} of tx {tx.hex_hash()}"
        )
    return True


def spend_verifies(tx: Tx, input_index: int, utxo: TxOutput) -> bool:
    """Return ``True`` if the interpreter accepts the spend, else ``False``.

    Any interpreter-side exception (script error, signature failure, opcode
    misuse) is caught and converted to ``False``. This is the function the
    negative tests should call; the positive tests should call
    :func:`verify_spend` so a failure is loud.
    """
    try:
        return verify_spend(tx, input_index, utxo)
    except Exception as e:  # noqa: BLE001 -- interpreter raises many types
        _log.debug("spend rejected: %s: %s", type(e).__name__, e)
        return False


def verify_all_inputs(tx: Tx, utxos: list[TxOutput]) -> bool:
    """Verify every input of ``tx`` against the corresponding ``utxos`` entry.

    Useful for end-to-end transaction checks (e.g. a close that spends both
    the channel output and every bond output).
    """
    if len(utxos) != len(tx.inputs):
        raise VerificationError(
            f"utxos length {len(utxos)} != tx.inputs length {len(tx.inputs)}"
        )
    for i, utxo in enumerate(utxos):
        verify_spend(tx, i, utxo)
    return True


__all__ = ["verify_spend", "spend_verifies", "verify_all_inputs"]
