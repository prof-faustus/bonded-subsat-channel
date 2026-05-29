"""Micro-unit accounting, conservation, and the netting quantisation ``Q*``.

A channel state is an allocation ``a = (a_1, ..., a_n)`` of non-negative
integer micro-unit balances summing to ``k*S``, where ``k`` is the per-channel
subdivision parameter and ``S`` the funded satoshis under the channel output.
Every state carries a monotone version counter ``t``: a transfer increments
``t`` by exactly 1.

The netting quantisation ``Q*`` maps a micro-unit state ``a`` to a vector
``q`` of non-negative integer satoshi payouts such that ``sum(q) == S``. It
is the deterministic rounding function settled at close.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .config import ChannelConfig
from .errors import AccountingError, FractionalSatoshiError


# ---------------------------------------------------------------------------
# Whole-satoshi guard
# ---------------------------------------------------------------------------


def ensure_whole_satoshi(value: object) -> int:
    """Return ``value`` if it is a non-negative ``int``, else raise.

    Floats, negative integers, or non-int types raise
    :class:`FractionalSatoshiError`. This is the boundary check applied
    before every settlement output is constructed.
    """
    if isinstance(value, bool):
        # bool is a subclass of int but is never a satoshi count.
        raise FractionalSatoshiError(f"satoshi value must not be bool ({value!r})")
    if not isinstance(value, int):
        raise FractionalSatoshiError(
            f"satoshi value must be int (got {type(value).__name__}: {value!r})"
        )
    if value < 0:
        raise FractionalSatoshiError(f"satoshi value must be >= 0 (got {value})")
    return value


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class State:
    """An immutable channel allocation.

    Attributes
    ----------
    balances
        Tuple of non-negative integer micro-unit balances, one per party,
        summing to ``k*S``.
    version
        The monotone version counter ``t``; transfers increment by 1.
    """

    balances: tuple[int, ...]
    version: int

    def __post_init__(self) -> None:
        if self.version < 0:
            raise AccountingError(f"version must be >= 0 (got {self.version})")
        for i, b in enumerate(self.balances):
            if not isinstance(b, int):
                raise AccountingError(
                    f"balance[{i}] must be int (got {type(b).__name__})"
                )
            if b < 0:
                raise AccountingError(f"balance[{i}] must be >= 0 (got {b})")

    def total_micro(self) -> int:
        return sum(self.balances)

    def conservation_check(self, cfg: ChannelConfig) -> None:
        """Raise :class:`AccountingError` if the total is not ``k*S``."""
        expected = cfg.k * cfg.S
        actual = self.total_micro()
        if actual != expected:
            raise AccountingError(
                f"conservation violated: sum(a)={actual} != k*S={expected}"
            )
        if len(self.balances) != cfg.n:
            raise AccountingError(
                f"state has {len(self.balances)} balances; cfg.n={cfg.n}"
            )


def initial_state(cfg: ChannelConfig, funder_index: int = 0) -> State:
    """Initial state: the funder holds all ``k*S`` micro-units; version 0."""
    if not 0 <= funder_index < cfg.n:
        raise AccountingError(f"funder_index {funder_index} out of [0, {cfg.n})")
    balances = [0] * cfg.n
    balances[funder_index] = cfg.k * cfg.S
    s = State(tuple(balances), version=0)
    s.conservation_check(cfg)
    return s


def transfer(state: State, sender: int, recipient: int, delta: int,
             cfg: ChannelConfig) -> State:
    """Return a new state with ``delta`` micro-units moved sender -> recipient.

    Raises :class:`AccountingError` on out-of-range indices, negative
    ``delta``, or insufficient balance.
    """
    if sender == recipient:
        raise AccountingError("sender and recipient must differ")
    if not 0 <= sender < cfg.n:
        raise AccountingError(f"sender {sender} out of [0, {cfg.n})")
    if not 0 <= recipient < cfg.n:
        raise AccountingError(f"recipient {recipient} out of [0, {cfg.n})")
    if not isinstance(delta, int) or delta < 0:
        raise AccountingError(f"delta must be a non-negative int (got {delta!r})")
    if delta > state.balances[sender]:
        raise AccountingError(
            f"transfer of {delta} exceeds sender balance {state.balances[sender]}"
        )
    new_balances = list(state.balances)
    new_balances[sender] -= delta
    new_balances[recipient] += delta
    new_state = State(tuple(new_balances), version=state.version + 1)
    new_state.conservation_check(cfg)
    return new_state


# ---------------------------------------------------------------------------
# Q* netting quantisation
# ---------------------------------------------------------------------------


def quantise(state: State, cfg: ChannelConfig) -> tuple[int, ...]:
    """The netting quantisation ``Q*(a)``.

    Algorithm. Each party ``i`` receives ``floor(a_i / k)`` satoshis. The
    remainder ``R = S - sum(floor(a_i/k))`` is a non-negative integer
    strictly less than ``n`` (proof: write ``a_i = k*q_i + r_i`` with
    ``0 <= r_i < k``; then ``sum(a_i) = k*S = k*sum(q_i) + sum(r_i)``, so
    ``R = sum(r_i) / k`` is a non-negative integer; since each ``r_i < k``
    and there are ``n`` of them, ``sum(r_i) < n*k`` and thus ``R < n``).
    The ``R`` remaining satoshis are distributed one each to the parties
    with the largest ``a_i mod k``, ties broken by the fixed participant
    ordering (smaller index wins).
    """
    state.conservation_check(cfg)
    k, S, n = cfg.k, cfg.S, cfg.n

    floors = [ai // k for ai in state.balances]
    remainders = [ai % k for ai in state.balances]
    total_floor = sum(floors)
    R = S - total_floor
    if R < 0 or R >= n:
        # This branch is unreachable for a valid state; assert with a
        # message that names the violated invariant for debugging.
        raise AccountingError(
            f"netting invariant violated: R={R} not in [0, n={n})"
        )

    # Recipients of the +1 satoshi: top-R parties by remainder, ties by
    # smaller index. Sort by (-remainder, index) and take the first R.
    order = sorted(range(n), key=lambda i: (-remainders[i], i))
    winners = set(order[:R])
    q = tuple(floors[i] + (1 if i in winners else 0) for i in range(n))

    # Defensive post-conditions (cheap; keep them in code).
    s = sum(q)
    if s != S:
        raise AccountingError(f"Q* sum {s} != S {S}")
    for i, qi in enumerate(q):
        ensure_whole_satoshi(qi)
    return q


# ---------------------------------------------------------------------------
# Conservation invariants over a sequence of transfers
# ---------------------------------------------------------------------------


def assert_conservation_over_sequence(
    initial: State, transfers: Sequence[tuple[int, int, int]],
    cfg: ChannelConfig,
) -> State:
    """Apply a sequence of transfers and assert conservation at each step."""
    cur = initial
    cur.conservation_check(cfg)
    for s, r, d in transfers:
        cur = transfer(cur, s, r, d, cfg)
        cur.conservation_check(cfg)
    return cur


__all__ = [
    "State",
    "ensure_whole_satoshi",
    "initial_state",
    "transfer",
    "quantise",
    "assert_conservation_over_sequence",
]
