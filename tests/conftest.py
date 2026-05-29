"""Shared test fixtures and helpers.

Centralises:
- Path setup so ``src/`` is importable without an editable install.
- Deterministic key generation for reproducible test runs.
- The single helper :func:`spend_to_burn` that wraps an input + a single
  small OP_RETURN-ish output so every test exercises a self-contained
  transaction through the interpreter.
"""

from __future__ import annotations

import os
import sys
from typing import Sequence

# Make src/ importable when running pytest from the repository root.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from bitcoinx import (  # noqa: E402  (imports after sys.path mutation)
    Ops, PrivateKey, PublicKey, Script, Tx, TxInput, TxOutput,
)

from channel.config import FINAL_SEQUENCE  # noqa: E402


def deterministic_key(seed: int) -> PrivateKey:
    """Return a :class:`PrivateKey` derived from a 32-byte seed integer.

    Deterministic key generation keeps tests reproducible. The seed is
    expanded to 32 bytes via big-endian encoding with leading zeros.
    """
    if seed <= 0:
        raise ValueError("seed must be a positive integer")
    return PrivateKey(seed.to_bytes(32, "big"))


def deterministic_keys(n: int, start: int = 1) -> list[PrivateKey]:
    """Return ``n`` distinct deterministic keys, starting from ``start``."""
    return [deterministic_key(start + i) for i in range(n)]


def burn_output(value: int = 0) -> TxOutput:
    """A throwaway OP_RETURN-style output for tests that need an output.

    On post-Genesis BSV an OP_RETURN output may carry zero value, so we can
    use these freely to balance inputs of arbitrary value into the
    interpreter.
    """
    return TxOutput(value, Script() << Ops.OP_RETURN)


def simple_spend_tx(
    prev_hash: bytes,
    prev_idx: int,
    out_value: int,
    out_script: Script,
    sequence: int = FINAL_SEQUENCE,
    locktime: int = 0,
) -> Tx:
    """Build a one-input one-output transaction (script_sig empty for now)."""
    tx_in = TxInput(prev_hash, prev_idx, Script(b""), sequence)
    tx_out = TxOutput(out_value, out_script)
    return Tx(1, [tx_in], [tx_out], locktime)
