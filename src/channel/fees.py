"""Fee model: per-byte rate and per-transaction estimators.

Sizes the fee for funding, settlement, refresh, hop, and bond
transactions. Because only whole satoshis settle, the fee is rounded
**up** to the nearest satoshi; the implementation never produces a
fractional-satoshi fee.
"""

from __future__ import annotations

from dataclasses import dataclass

from .accounting import ensure_whole_satoshi


@dataclass(frozen=True)
class FeeModel:
    """A flat per-byte fee rate with a per-tx minimum."""

    sat_per_byte: int = 1
    min_tx_fee: int = 1  # at least 1 satoshi (the whole-satoshi premise)

    def fee_for_size(self, size_bytes: int) -> int:
        if size_bytes < 0:
            raise ValueError(f"size_bytes must be >= 0 (got {size_bytes})")
        # Ceiling division by 1 is the value; the formula is written
        # explicitly so future per-fractional-byte rates compile cleanly.
        raw = size_bytes * self.sat_per_byte
        fee = max(self.min_tx_fee, raw)
        return ensure_whole_satoshi(fee)


DEFAULT_FEE_MODEL = FeeModel()


__all__ = ["FeeModel", "DEFAULT_FEE_MODEL"]
