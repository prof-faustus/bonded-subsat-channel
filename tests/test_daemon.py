"""Phase 11 GATE: fees, observability, daemon, CLI.

The daemon hosts node + wallet + manager + tower. The local control
socket lets a separate CLI process drive operations against it. Here we
exercise ping/status/node.generate/shutdown via the in-process Daemon
class.
"""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "src")))

from bitcoinx import PrivateKey  # noqa: E402

from channel.daemon import Daemon, Service, call  # noqa: E402
from channel.fees import DEFAULT_FEE_MODEL, FeeModel  # noqa: E402
from channel.obs.health import collect  # noqa: E402
from channel.obs.metrics import Metrics  # noqa: E402
from channel.store.store import SystemStore  # noqa: E402


# ---------------------------------------------------------------------------
# Fees
# ---------------------------------------------------------------------------


def test_fee_model_for_size() -> None:
    fm = FeeModel(sat_per_byte=2, min_tx_fee=10)
    assert fm.fee_for_size(100) == 200
    assert fm.fee_for_size(0) == 10
    assert fm.fee_for_size(3) == 10  # under min


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_counters() -> None:
    m = Metrics()
    m.inc("tx.admitted")
    m.inc("tx.admitted", 3)
    m.set_gauge("mempool.size", 7.0)
    snap = m.snapshot()
    assert snap["counters"]["tx.admitted"] == 4
    assert snap["gauges"]["mempool.size"] == 7.0


# ---------------------------------------------------------------------------
# Daemon ping/status/generate/shutdown
# ---------------------------------------------------------------------------


@pytest.fixture
def daemon():
    store = SystemStore(":memory:")
    svc = Service(store=store)
    d = Daemon(service=svc)
    d.start()
    yield d
    d.stop()
    store.close()


def test_daemon_ping(daemon: Daemon) -> None:
    resp = call("127.0.0.1", daemon.port, {"cmd": "ping"})
    assert resp == {"ok": True, "pong": True}


def test_daemon_status_shape(daemon: Daemon) -> None:
    resp = call("127.0.0.1", daemon.port, {"cmd": "status"})
    assert resp["ok"]
    s = resp["status"]
    assert "node_height" in s
    assert "mempool_size" in s
    assert s["node_height"] == 0


def test_daemon_node_generate(daemon: Daemon) -> None:
    priv = PrivateKey.from_random()
    resp = call("127.0.0.1", daemon.port, {
        "cmd": "node.generate",
        "payout_pk_hex": priv.public_key.to_hex(),
    })
    assert resp["ok"]
    assert resp["txs"] == 1
    # And height advanced.
    resp = call("127.0.0.1", daemon.port, {"cmd": "node.height"})
    assert resp == {"ok": True, "height": 1}


def test_daemon_unknown_command_returns_error(daemon: Daemon) -> None:
    resp = call("127.0.0.1", daemon.port, {"cmd": "does-not-exist"})
    assert resp["ok"] is False


def test_daemon_shutdown(daemon: Daemon) -> None:
    resp = call("127.0.0.1", daemon.port, {"cmd": "shutdown"})
    assert resp == {"ok": True}
    # Give the server a moment to process; further calls may fail.
    time.sleep(0.05)
