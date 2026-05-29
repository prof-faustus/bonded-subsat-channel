"""Transaction validation under post-Genesis BSV rules.

Every input is executed through the real Bitcoin Script interpreter via
the package's :mod:`channel.verify` entry point. The validation function
returns a typed result and never silently accepts an invalid spend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from bitcoinx import Tx, TxOutput

from ..errors import ChannelError, VerificationError
from ..verify import verify_spend
from .blockstore import BlockStore, UtxoEntry


class ValidationError(ChannelError):
    """Transaction or block validation failure."""


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a transaction against the UTXO set."""

    ok: bool
    reason: str = ""
    inputs_value: int = 0
    outputs_value: int = 0
    spent_inputs: tuple[tuple[bytes, int, int, bytes], ...] = ()  # (txid, vout, value, script)

    @property
    def fee(self) -> int:
        return self.inputs_value - self.outputs_value


def validate_tx(tx: Tx, store: BlockStore, *, allow_coinbase: bool = False) -> ValidationResult:
    """Validate a transaction against the current UTXO set.

    Steps:
        1. Reject coinbase transactions (unless ``allow_coinbase``).
        2. Every output is a non-negative integer satoshi value.
        3. Every input refers to a UTXO present in the store.
        4. Every input verifies through :func:`channel.verify.verify_spend`.
        5. Sum of inputs >= sum of outputs (fee is the difference).
    """
    if tx.is_coinbase():
        if allow_coinbase:
            # Coinbase: only check output integrality and pass.
            total_out = 0
            for o in tx.outputs:
                if not isinstance(o.value, int) or o.value < 0:
                    return ValidationResult(False, "non-integer/negative output value")
                total_out += o.value
            return ValidationResult(True, "coinbase", inputs_value=total_out,
                                    outputs_value=total_out)
        return ValidationResult(False, "coinbase tx not accepted to mempool")

    # Output integrality.
    total_out = 0
    for o in tx.outputs:
        if not isinstance(o.value, int) or o.value < 0:
            return ValidationResult(False, "non-integer/negative output value")
        total_out += o.value

    # Inputs: each must resolve to a UTXO and verify in the interpreter.
    total_in = 0
    spent: list[tuple[bytes, int, int, bytes]] = []
    for idx, tin in enumerate(tx.inputs):
        entry = store.get_utxo(bytes(tin.prev_hash), int(tin.prev_idx))
        if entry is None:
            return ValidationResult(False, f"input {idx}: UTXO not found")
        utxo = entry.as_txoutput()
        try:
            verify_spend(tx, idx, utxo)
        except VerificationError as e:
            return ValidationResult(False, f"input {idx}: script rejected: {e}")
        except Exception as e:  # noqa: BLE001 -- interpreter raises many types
            return ValidationResult(False, f"input {idx}: interpreter error: {type(e).__name__}: {e}")
        total_in += entry.value
        spent.append((entry.txid, entry.vout, entry.value, entry.script_pubkey))

    if total_in < total_out:
        return ValidationResult(False,
                                 f"sum inputs {total_in} < sum outputs {total_out}")

    return ValidationResult(True, "ok",
                             inputs_value=total_in,
                             outputs_value=total_out,
                             spent_inputs=tuple(spent))


__all__ = ["ValidationError", "ValidationResult", "validate_tx"]
