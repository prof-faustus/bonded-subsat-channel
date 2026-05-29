"""Phase 2 GATE tests for ``channel.accounting``.

Verifies:
- whole-satoshi guard rejects floats / negatives;
- Q* sums exactly to S, all q_i integer >= 0, R < n strictly;
- total micro-units conserved across random transfer sequences.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from hypothesis import given, settings, strategies as st  # noqa: E402

from channel.accounting import (  # noqa: E402
    State,
    assert_conservation_over_sequence,
    ensure_whole_satoshi,
    initial_state,
    quantise,
    transfer,
)
from channel.config import ChannelConfig  # noqa: E402
from channel.errors import AccountingError, FractionalSatoshiError  # noqa: E402


# ---------------------------------------------------------------------------
# Whole-satoshi guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [0.5, 1.5, -1, -1000, "1", None, 1.0, True])
def test_ensure_whole_satoshi_rejects(bad: object) -> None:
    with pytest.raises(FractionalSatoshiError):
        ensure_whole_satoshi(bad)


@pytest.mark.parametrize("good", [0, 1, 7, 1_000_000])
def test_ensure_whole_satoshi_accepts(good: int) -> None:
    assert ensure_whole_satoshi(good) == good


# ---------------------------------------------------------------------------
# State construction & conservation
# ---------------------------------------------------------------------------


def test_initial_state_conserves() -> None:
    cfg = ChannelConfig.uniform_bond(n=4, k=1000, S=1)
    s = initial_state(cfg)
    assert s.total_micro() == cfg.k * cfg.S
    assert s.balances[0] == 1000
    assert s.balances[1:] == (0, 0, 0)
    assert s.version == 0


def test_transfer_advances_version_and_conserves() -> None:
    cfg = ChannelConfig.uniform_bond(n=3, k=100, S=2)
    s0 = initial_state(cfg)
    s1 = transfer(s0, 0, 1, 37, cfg)
    assert s1.version == 1
    assert s1.balances == (200 - 37, 37, 0)
    assert s1.total_micro() == cfg.k * cfg.S


def test_transfer_rejects_overdraft() -> None:
    cfg = ChannelConfig.uniform_bond(n=3, k=100, S=1)
    s0 = initial_state(cfg)
    with pytest.raises(AccountingError):
        transfer(s0, 1, 0, 1, cfg)  # party 1 has 0


def test_transfer_rejects_self_transfer() -> None:
    cfg = ChannelConfig.uniform_bond(n=3, k=100, S=1)
    s0 = initial_state(cfg)
    with pytest.raises(AccountingError):
        transfer(s0, 0, 0, 10, cfg)


# ---------------------------------------------------------------------------
# Q* netting
# ---------------------------------------------------------------------------


def test_quantise_simple_floor() -> None:
    """4 parties, k=4, S=1, allocation (1,1,1,1) micro-units -> floor 0."""
    cfg = ChannelConfig.uniform_bond(n=4, k=4, S=1)
    s = State((1, 1, 1, 1), version=0)
    q = quantise(s, cfg)
    # Each remainder is 1; first one (index 0) wins the +1 satoshi.
    assert q == (1, 0, 0, 0)
    assert sum(q) == cfg.S


def test_quantise_ties_broken_by_index() -> None:
    """Equal-remainder ties go to the smaller-index party."""
    cfg = ChannelConfig.uniform_bond(n=3, k=10, S=1)
    # balances (3, 3, 4): floor (0,0,0); remainders (3,3,4); R = 1
    # winner = max-remainder (4) -> index 2
    q = quantise(State((3, 3, 4), version=0), cfg)
    assert q == (0, 0, 1)
    # balances (5, 5, 0): floor (0,0,0); remainders (5,5,0); R = 1
    # tie at remainder 5 between indices 0 and 1 -> index 0 wins
    q = quantise(State((5, 5, 0), version=0), cfg)
    assert q == (1, 0, 0)


@pytest.mark.parametrize("seed", list(range(20)))
def test_quantise_random_states_sum_and_R_bound(seed: int) -> None:
    rng = random.Random(seed)
    n = rng.randint(2, 12)
    k = rng.randint(1, 1000)
    S = rng.randint(1, 100)
    # Draw a random partition of k*S into n non-negative parts.
    total = k * S
    cuts = sorted(rng.randint(0, total) for _ in range(n - 1))
    balances = tuple(b - a for a, b in zip([0] + cuts, cuts + [total]))
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S)
    s = State(balances, version=0)
    q = quantise(s, cfg)
    assert sum(q) == S
    for qi in q:
        assert isinstance(qi, int) and qi >= 0
    # R = S - sum(floor). Verify R in [0, n).
    R = S - sum(b // k for b in balances)
    assert 0 <= R < n


# ---------------------------------------------------------------------------
# Hypothesis property tests
# ---------------------------------------------------------------------------


@settings(max_examples=120, deadline=None)
@given(
    n=st.integers(min_value=2, max_value=10),
    k=st.integers(min_value=1, max_value=500),
    S=st.integers(min_value=1, max_value=50),
    draws=st.lists(st.floats(min_value=0.0, max_value=1.0),
                   min_size=2, max_size=10),
)
def test_quantise_property(n: int, k: int, S: int, draws: list[float]) -> None:
    # Build a state of length n by truncating/padding draws and scaling.
    weights = (draws + [0.0] * n)[:n]
    total = k * S
    raw = [int(w * 1_000_000) for w in weights]
    sraw = sum(raw) or 1
    balances = [(r * total) // sraw for r in raw]
    # Fix rounding drift.
    balances[0] += total - sum(balances)
    if any(b < 0 for b in balances):
        return  # skip degenerate draw
    cfg = ChannelConfig.uniform_bond(n=n, k=k, S=S)
    s = State(tuple(balances), version=0)
    q = quantise(s, cfg)
    assert sum(q) == S
    assert all(isinstance(qi, int) and qi >= 0 for qi in q)


def test_conservation_over_random_sequence() -> None:
    rng = random.Random(0xC0FFEE)
    cfg = ChannelConfig.uniform_bond(n=8, k=10_000, S=3)
    s = initial_state(cfg)
    start_version = s.version
    steps = 0
    for _ in range(300):
        sender = rng.randint(0, cfg.n - 1)
        if s.balances[sender] == 0:
            continue
        recipient = rng.randint(0, cfg.n - 1)
        while recipient == sender:
            recipient = rng.randint(0, cfg.n - 1)
        delta = rng.randint(0, s.balances[sender])
        s = transfer(s, sender, recipient, delta, cfg)
        s.conservation_check(cfg)
        steps += 1
    assert s.total_micro() == cfg.k * cfg.S
    assert s.version == start_version + steps
