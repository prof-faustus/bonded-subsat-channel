"""Tower incentive accounting.

The tower's revenue is paid out of the forfeited bond (or by a separate
pre-arranged side payment). The incentive model is simple: a fixed
satoshi fee per successful intervention, capped at the offender's bond.
The bookkeeping is local; the wallet records each fee as income from
the tower.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import ChannelError


class IncentiveError(ChannelError):
    pass


@dataclass
class IncentiveLedger:
    """A trivial running tally of tower fees earned."""

    fee_per_intervention: int = 0  # satoshis
    intervention_fees: list[int] = field(default_factory=list)

    def record(self, bond_value: int) -> int:
        """Record a successful intervention; return the fee credited."""
        if bond_value < 0:
            raise IncentiveError(f"bond_value must be >= 0 (got {bond_value})")
        fee = min(self.fee_per_intervention, bond_value)
        self.intervention_fees.append(fee)
        return fee

    def total(self) -> int:
        return sum(self.intervention_fees)


__all__ = ["IncentiveLedger", "IncentiveError"]
