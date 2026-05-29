"""Command-line control surface.

Part I subcommands (channel lifecycle on local JSON state):
    channel open       --parties N --k K --funded S --bond B [--out PATH]
    channel transfer   --script transfers.json [--state PATH]
    channel close      [--state PATH]
    channel contested  --offender I [--state PATH]

Part II subcommands (control of a running daemon over the local socket):
    channel daemon start [--port P]
    channel ping       --port P
    channel status     --port P
    channel daemon stop --port P
    channel node generate --port P --payout-hex HEX

Use ``--log-level`` to control logging verbosity throughout.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from .accounting import quantise
from .config import ChannelConfig
from .errors import ChannelError
from .keymgmt import KeyBook
from .lifecycle import Channel
from .persistence import load_channel, save_channel
from .safety import Mode, emit_banner_once, set_mode
from .verify import verify_all_inputs, verify_spend


_log = logging.getLogger(__name__)
_DEFAULT_PATH = Path("channel_state.json")


# ---------------------------------------------------------------------------
# Part I commands (lifecycle on local JSON state)
# ---------------------------------------------------------------------------


def cmd_open(args: argparse.Namespace) -> int:
    cfg = ChannelConfig.uniform_bond(
        n=args.parties, k=args.k, S=args.funded, bond=args.bond,
    )
    book = KeyBook.random(args.parties)
    ch = Channel.open(cfg, book)
    ch.mark_confirmed()
    save_channel(ch, args.out)
    _log.info("opened channel: parties=%d k=%d S=%d bond=%d -> %s",
              args.parties, args.k, args.funded, args.bond, args.out)
    print(f"opened channel; saved to {args.out}")
    return 0


def cmd_transfer(args: argparse.Namespace) -> int:
    ch = load_channel(args.state)
    with open(args.script) as fh:
        ops = json.load(fh)
    if not isinstance(ops, list):
        raise ChannelError("transfer script must be a JSON array")
    seq = [tuple(op) for op in ops]
    for op in seq:
        if len(op) != 3:
            raise ChannelError(f"bad transfer entry {op!r}")
    ch.apply_sequence(seq)
    save_channel(ch, args.state)
    _log.info("applied %d transfers; new version=%d", len(seq), ch.state.version)
    print(f"applied {len(seq)} transfers; new version={ch.state.version}")
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    ch = load_channel(args.state)
    tx, utxos = ch.cooperative_close()
    verify_all_inputs(tx, utxos)
    q = quantise(ch.state, ch.cfg)
    print("cooperative close payouts (q_i + b_i, satoshis):")
    for i in range(ch.cfg.n):
        print(f"  party {i}: q={q[i]}  bond={ch.cfg.bonds[i]}  total={q[i] + ch.cfg.bonds[i]}")
    total = sum(o.value for o in tx.outputs)
    print(f"total settled: {total} satoshis")
    print(f"tx size: {tx.size()} bytes")
    return 0


def cmd_contested(args: argparse.Namespace) -> int:
    ch = load_channel(args.state)
    forfeit_tx, forfeit_utxos = ch.forfeit_bond_tx(offender=args.offender)
    verify_spend(forfeit_tx, 0, forfeit_utxos[0])
    forfeited = sum(o.value for o in forfeit_tx.outputs)
    print(f"contested close: offender={args.offender}")
    print(f"  bond forfeited: {ch.cfg.bonds[args.offender]} satoshis")
    print(f"  distributed to {ch.cfg.n - 1} honest counterparties; total out={forfeited}")
    return 0


# ---------------------------------------------------------------------------
# Part II commands (daemon control)
# ---------------------------------------------------------------------------


def cmd_daemon_start(args: argparse.Namespace) -> int:
    """Start a foreground daemon. Blocks until SIGINT or 'shutdown' command."""
    from .daemon import Daemon, Service
    from .store.store import SystemStore

    store = SystemStore(args.db)
    svc = Service(store=store)
    daemon = Daemon(service=svc, port=args.port)
    actual_port = daemon.start()
    print(f"daemon listening on 127.0.0.1:{actual_port}")
    if args.foreground:
        try:
            # Block until the daemon receives a shutdown command.
            while daemon._server is not None and not daemon._server.shutdown_signal.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        daemon.stop()
        store.close()
    return 0


def cmd_daemon_call(args: argparse.Namespace, req: dict) -> int:
    from .daemon import call
    try:
        resp = call("127.0.0.1", args.port, req)
    except Exception as e:  # noqa: BLE001
        print(f"daemon call failed: {e}", file=sys.stderr)
        return 1
    print(json.dumps(resp, indent=2))
    return 0 if resp.get("ok") else 2


def cmd_ping(args: argparse.Namespace) -> int:
    return cmd_daemon_call(args, {"cmd": "ping"})


def cmd_status(args: argparse.Namespace) -> int:
    return cmd_daemon_call(args, {"cmd": "status"})


def cmd_daemon_stop(args: argparse.Namespace) -> int:
    return cmd_daemon_call(args, {"cmd": "shutdown"})


def cmd_node_generate(args: argparse.Namespace) -> int:
    return cmd_daemon_call(args, {"cmd": "node.generate",
                                    "payout_pk_hex": args.payout_hex})


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="channel",
        description=(
            "Bonded sub-satoshi channels (BSV, post-Genesis). "
            "RESEARCH CODE — regtest only by default. Mainnet is opt-in "
            "via --mainnet + --i-understand-this-is-research-code."
        ),
    )
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument(
        "--mainnet", action="store_true",
        help="opt-in to mainnet mode (also requires "
             "--i-understand-this-is-research-code); off by default",
    )
    p.add_argument(
        "--i-understand-this-is-research-code", action="store_true",
        dest="confirmed",
        help="required alongside --mainnet to acknowledge the risks",
    )
    p.add_argument(
        "--no-banner", action="store_true",
        help="suppress the standard research-code warning banner",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Part I
    op = sub.add_parser("open", help="open a new channel")
    op.add_argument("--parties", type=int, required=True)
    op.add_argument("--k", type=int, required=True, help="subdivision (micro-units per satoshi)")
    op.add_argument("--funded", type=int, required=True, help="S, funded satoshis")
    op.add_argument("--bond", type=int, default=1, help="per-party bond")
    op.add_argument("--out", type=Path, default=_DEFAULT_PATH)
    op.set_defaults(func=cmd_open)

    tr = sub.add_parser("transfer", help="apply a script of transfers")
    tr.add_argument("--script", type=Path, required=True,
                    help="JSON file: list of [sender, recipient, delta]")
    tr.add_argument("--state", type=Path, default=_DEFAULT_PATH)
    tr.set_defaults(func=cmd_transfer)

    cl = sub.add_parser("close", help="cooperative close")
    cl.add_argument("--state", type=Path, default=_DEFAULT_PATH)
    cl.set_defaults(func=cmd_close)

    co = sub.add_parser("contested", help="forfeit a misbehaver's bond")
    co.add_argument("--offender", type=int, required=True)
    co.add_argument("--state", type=Path, default=_DEFAULT_PATH)
    co.set_defaults(func=cmd_contested)

    # Part II
    dms = sub.add_parser("daemon-start", help="start the system daemon (foreground)")
    dms.add_argument("--port", type=int, default=0)
    dms.add_argument("--db", type=str, default=":memory:")
    dms.add_argument("--foreground", action="store_true", default=True)
    dms.set_defaults(func=cmd_daemon_start)

    ping = sub.add_parser("ping", help="ping the running daemon")
    ping.add_argument("--port", type=int, required=True)
    ping.set_defaults(func=cmd_ping)

    st = sub.add_parser("status", help="query daemon status")
    st.add_argument("--port", type=int, required=True)
    st.set_defaults(func=cmd_status)

    sd = sub.add_parser("daemon-stop", help="ask the daemon to shut down")
    sd.add_argument("--port", type=int, required=True)
    sd.set_defaults(func=cmd_daemon_stop)

    ng = sub.add_parser("node-generate", help="mine a block via the daemon")
    ng.add_argument("--port", type=int, required=True)
    ng.add_argument("--payout-hex", type=str, required=True,
                    help="hex of the payout pubkey")
    ng.set_defaults(func=cmd_node_generate)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Emit the research-code banner once, unless explicitly suppressed.
    if not getattr(args, "no_banner", False):
        emit_banner_once()

    # Mainnet is opt-in and requires an explicit acknowledgement flag.
    if getattr(args, "mainnet", False):
        if not getattr(args, "confirmed", False):
            print(
                "error: --mainnet requires --i-understand-this-is-research-code",
                file=sys.stderr,
            )
            return 2
        set_mode(Mode.MAINNET, i_understand_this_is_research_code=True)

    try:
        return int(args.func(args))
    except ChannelError as e:
        _log.error("%s: %s", type(e).__name__, e)
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
