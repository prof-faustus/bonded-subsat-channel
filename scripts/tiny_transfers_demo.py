"""Tiny-transfers demo — the paper's central claim, made visible.

This script opens a channel funded with **a single satoshi** subdivided into
``k = 1000`` micro-units (so one micro-unit is one milli-satoshi), then
performs many transfers each one micro-unit in size. Every transfer is a
strictly sub-satoshi payment — on no plain Bitcoin construction could
these amounts move on-chain.

At the end the channel closes cooperatively. The on-chain close pays out
**whole satoshis only** (the netting quantisation ``Q*`` rounds the
micro-unit balances to integer satoshis), and the total settled equals
``S + sum(bonds)`` exactly. The script prints the per-party micro-unit
balances, the per-party ``Q*`` payouts, and the conservation check, so a
reader can see in one screenful that:

    (a) sub-satoshi value moved off-chain;
    (b) on-chain only integer satoshis appeared;
    (c) no value was created or destroyed.

Run:

    python scripts/tiny_transfers_demo.py
    python scripts/tiny_transfers_demo.py --parties 5 --transfers 250

Exit code 0 on success; non-zero on any conservation failure (which
would indicate a bug — the assertions are real, not decorative).
"""

from __future__ import annotations

import argparse
import os
import random
import sys

# Make the package importable when run from the repo without `pip install -e .`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from channel.accounting import quantise  # noqa: E402
from channel.config import ChannelConfig  # noqa: E402
from channel.keymgmt import KeyBook  # noqa: E402
from channel.lifecycle import Channel  # noqa: E402
from channel.verify import verify_all_inputs  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Tiny-transfers demo: many sub-satoshi transfers, one cooperative close, "
            "exact whole-satoshi settlement."
        ),
    )
    p.add_argument("--parties", type=int, default=4,
                   help="number of channel participants (default: 4)")
    p.add_argument("--k", type=int, default=1000,
                   help="subdivision: micro-units per satoshi (default: 1000)")
    p.add_argument("--funded", type=int, default=1,
                   help="S, funded satoshis (default: 1)")
    p.add_argument("--bond", type=int, default=1,
                   help="per-party bond in satoshis (default: 1)")
    p.add_argument("--transfers", type=int, default=200,
                   help="number of sub-satoshi transfers to perform (default: 200)")
    p.add_argument("--seed", type=int, default=42,
                   help="RNG seed for the transfer pattern (default: 42)")
    args = p.parse_args(argv)

    n = args.parties
    cfg = ChannelConfig.uniform_bond(n=n, k=args.k, S=args.funded, bond=args.bond)
    book = KeyBook.from_ints(list(range(100_000, 100_000 + n)))
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()

    micro_per_sat = cfg.k
    total_micro = cfg.k * cfg.S

    print("=" * 72)
    print("Tiny-transfers demo")
    print("=" * 72)
    print(f"  parties (n)                    : {n}")
    print(f"  subdivision (k, micro-units/sat)   : {cfg.k}")
    print(f"  funded satoshis (S)            : {cfg.S}")
    print(f"  per-party bond                 : {cfg.bonds[0]} satoshi")
    print(f"  total micro-units in channel       : {total_micro}")
    print(f"  one micro-unit                     : 1/{cfg.k} satoshi"
          f"  ({1.0 / cfg.k:.6f} sat)")
    print()
    print(f"Performing {args.transfers} transfers of 1 micro-unit each, "
          f"random sender/recipient.")
    print()

    rng = random.Random(args.seed)
    applied = 0
    attempted = 0
    while applied < args.transfers:
        attempted += 1
        sender = rng.randint(0, n - 1)
        if ch.state.balances[sender] == 0:
            continue
        recipient = rng.randint(0, n - 1)
        while recipient == sender:
            recipient = rng.randint(0, n - 1)
        ch.apply_transfer(sender, recipient, 1)  # exactly 1 micro-unit (sub-satoshi)
        applied += 1

    print(f"  applied {applied} sub-satoshi transfers"
          f"  (state version = {ch.state.version})")
    print()

    # ----- Off-chain micro-unit balances (sub-satoshi) ---------------------
    print("Off-chain micro-unit balances (each strictly sub-satoshi):")
    for i, bal in enumerate(ch.state.balances):
        sats = bal / micro_per_sat
        print(f"  party {i}: {bal:>6d} micro-units  = {sats:.6f} satoshi")
    assert sum(ch.state.balances) == total_micro, (
        f"conservation: micro-units sum to {sum(ch.state.balances)} "
        f"!= expected {total_micro}"
    )
    print(f"  total      : {sum(ch.state.balances)} micro-units"
          f"  (== k*S = {total_micro}) [OK]")
    print()

    # ----- Q* netting (on-chain integer satoshi payouts) -------------------
    q = quantise(ch.state, cfg)
    print("On-chain settlement via Q* (whole satoshis only):")
    for i, qi in enumerate(q):
        print(f"  party {i}: q_i = {qi} satoshi  (from {ch.state.balances[i]} micro-units)")
    assert sum(q) == cfg.S, f"Q* failed conservation: sum(q)={sum(q)} != S={cfg.S}"
    print(f"  sum        : {sum(q)} satoshi"
          f"  (== S = {cfg.S}) [OK]")
    print()

    # ----- Cooperative close (verified through the real interpreter) ------
    tx, utxos = ch.cooperative_close()
    verify_all_inputs(tx, utxos)
    total_out = sum(o.value for o in tx.outputs)
    expected = cfg.S + sum(cfg.bonds)
    print("Cooperative close (every input verified through the Script interpreter):")
    print(f"  tx size                : {tx.size()} bytes")
    print(f"  outputs (party payouts): {len(tx.outputs)}")
    for i, o in enumerate(tx.outputs):
        print(f"    party {i}: {o.value} satoshi  "
              f"(= Q*_i + bond_i = {q[i]} + {cfg.bonds[i]})")
    print(f"  total settled          : {total_out} satoshi")
    print(f"  expected (S + sum(bonds)): {expected} satoshi")
    if total_out != expected:
        print(f"\n  CONSERVATION VIOLATION: {total_out} != {expected}", file=sys.stderr)
        return 1
    print(f"  conservation           : OK [OK]")
    print()

    print("=" * 72)
    print(" SUMMARY")
    print("=" * 72)
    print(f"  {applied} sub-satoshi transfers moved value at granularity"
          f" 1/{cfg.k} satoshi off-chain;")
    print(f"  the cooperative close settles exactly {total_out} satoshi"
          f" in {len(tx.outputs)} whole-satoshi outputs;")
    print(f"  Q* maps {total_micro} micro-units -> {sum(q)} satoshi"
          f" with conservation guaranteed by construction.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
