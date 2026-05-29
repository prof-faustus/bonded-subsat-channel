"""Configuration constants and factories for interpreter limits.

All magic numbers used elsewhere in the package are anchored here so the
production-grade implementation has a single source of truth for limits,
sighash flag conventions, and post-Genesis interpreter configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from bitcoinx import InterpreterLimits, MinerPolicy, SigHash

from .errors import ConfigError


# ---------------------------------------------------------------------------
# Sighash convention
# ---------------------------------------------------------------------------
#
# We always sign with SIGHASH_ALL | SIGHASH_FORKID. FORKID is the BSV
# (post-Genesis) sighash variant; ALL commits to every input and output of
# the transaction so a co-signed state cannot be re-arranged after signing.
SIGHASH_ALL_FORKID: Final[SigHash] = SigHash(SigHash.ALL | SigHash.FORKID)


# ---------------------------------------------------------------------------
# Sequence-number scheme for state versioning
# ---------------------------------------------------------------------------
#
# State of version ``t`` carries every input ``nSequence = START_SEQUENCE + t``
# (see DECISIONS.md, D4). The settlement-final value 0xFFFFFFFF exits the
# non-final regime entirely and is reserved for the cooperative close.
START_SEQUENCE: Final[int] = 0
FINAL_SEQUENCE: Final[int] = 0xFFFFFFFF
MAX_NON_FINAL_SEQUENCE: Final[int] = 0xFFFFFFFE


# ---------------------------------------------------------------------------
# Locktime horizons
# ---------------------------------------------------------------------------
#
# nLockTime is block-height when below the BIP113 threshold (5e8). We model
# horizons as block-heights. ``DEFAULT_DELTA`` is the worst-case confirmation
# bound for staggering hop horizons (see §7).
DEFAULT_DELTA: Final[int] = 144  # ~ one day at 10 min blocks
DEFAULT_L0: Final[int] = 100_000  # initial channel horizon (well below 5e8)
COOP_LOCKTIME: Final[int] = 0  # cooperative close: immediately final


# ---------------------------------------------------------------------------
# Interpreter limits factory
# ---------------------------------------------------------------------------
#
# The post-Genesis BSV interpreter requires explicit limits. We choose
# permissively-large but finite values; the test suite exercises scripts
# many orders of magnitude below these caps.
MAX_SCRIPT_SIZE: Final[int] = 10**9
MAX_SCRIPT_NUM_LENGTH: Final[int] = 750_000
MAX_STACK_MEMORY: Final[int] = 10**10
MAX_OPS_PER_SCRIPT: Final[int] = 10**8
MAX_PUBKEYS_PER_MULTISIG: Final[int] = 20_000


def make_miner_policy() -> MinerPolicy:
    """Return a permissive :class:`MinerPolicy` suitable for tests/scale."""
    return MinerPolicy(
        MAX_SCRIPT_SIZE,
        MAX_SCRIPT_NUM_LENGTH,
        MAX_STACK_MEMORY,
        MAX_OPS_PER_SCRIPT,
        MAX_PUBKEYS_PER_MULTISIG,
    )


def make_interpreter_limits() -> InterpreterLimits:
    """Return :class:`InterpreterLimits` configured for post-Genesis BSV.

    ``is_genesis_enabled=True`` selects post-Genesis semantics (which is the
    only configuration this implementation supports); ``is_consensus=True``
    selects the consensus flag set, not the (stricter) standard relay set.
    """
    return InterpreterLimits(
        make_miner_policy(),
        is_genesis_enabled=True,
        is_consensus=True,
    )


# ---------------------------------------------------------------------------
# Channel-wide configuration object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelConfig:
    """Per-channel configuration: party count, subdivision, funding, bonds."""

    n: int  # number of participants
    k: int  # micro-units per satoshi
    S: int  # funded satoshis under the channel output
    bonds: tuple[int, ...]  # per-participant bond, in satoshis
    L0: int = DEFAULT_L0  # initial settlement horizon
    delta: int = DEFAULT_DELTA  # worst-case confirmation bound for staggering

    def __post_init__(self) -> None:
        if self.n < 2:
            raise ConfigError(f"n must be >= 2 (got {self.n})")
        if self.k < 1:
            raise ConfigError(f"k must be >= 1 (got {self.k})")
        if self.S < 1:
            raise ConfigError(f"S must be >= 1 (got {self.S})")
        if len(self.bonds) != self.n:
            raise ConfigError(
                f"bonds tuple length {len(self.bonds)} != n={self.n}"
            )
        for i, b in enumerate(self.bonds):
            if b < 1:
                raise ConfigError(f"bond[{i}] must be >= 1 (got {b})")
        if self.L0 < 1:
            raise ConfigError(f"L0 must be >= 1 (got {self.L0})")
        if self.delta < 1:
            raise ConfigError(f"delta must be >= 1 (got {self.delta})")
        if self.L0 >= 500_000_000:
            # nLockTime values >= 5e8 are interpreted as Unix timestamps,
            # not block heights; we always model heights.
            raise ConfigError(
                "L0 must be below the BIP113 nLockTime height/time threshold"
            )

    @classmethod
    def uniform_bond(cls, n: int, k: int, S: int, bond: int = 1,
                     L0: int = DEFAULT_L0, delta: int = DEFAULT_DELTA) -> "ChannelConfig":
        """Build a config with a uniform per-party bond."""
        return cls(n=n, k=k, S=S, bonds=tuple([bond] * n), L0=L0, delta=delta)


@dataclass(frozen=True)
class _Sentinel:
    """Internal marker used in dataclass defaults."""
    _unused: int = field(default=0)
