"""Service daemon: hosts the embedded node, wallet, channel manager, watchtower.

The daemon exposes a tiny JSON-over-TCP control surface bound to
``127.0.0.1:<port>``. This is **local-only**: it is the system controlling
itself; it is not an external API and does not replace the native node
protocol. (Unix-domain sockets are not used because the target platform
matrix includes Windows.)

Control protocol: each request is a single line of JSON terminated by
``\\n``; each response is a single line of JSON terminated by ``\\n``.
Commands:

- ``{"cmd":"status"}`` -> :func:`channel.obs.health.collect`
- ``{"cmd":"shutdown"}`` -> ``{"ok":true}`` then the server exits
- ``{"cmd":"ping"}`` -> ``{"ok":true,"pong":true}``
- ``{"cmd":"node.generate","payout_pk_hex":"..."}`` -> mine one block
"""

from __future__ import annotations

import json
import logging
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from bitcoinx import PublicKey

from .errors import ChannelError
from .node.network import EmbeddedNode
from .obs.health import collect
from .obs.metrics import Metrics
from .runtime.manager import ChannelManager
from .scripts import p2pkh_script
from .store.store import SystemStore
from .watchtower.registry import Registry
from .watchtower.tower import Tower


_log = logging.getLogger(__name__)


class DaemonError(ChannelError):
    pass


# ---------------------------------------------------------------------------
# Service container
# ---------------------------------------------------------------------------


@dataclass
class Service:
    """The composite of node + wallet (via manager + store) + tower."""

    store: SystemStore
    node: EmbeddedNode = field(default_factory=EmbeddedNode)
    manager: ChannelManager = field(init=False)
    tower: Tower = field(init=False)
    metrics: Metrics = field(default_factory=Metrics)

    def __post_init__(self) -> None:
        self.manager = ChannelManager(store=self.store)
        self.tower = Tower(node=self.node, registry=Registry())

    def status(self) -> dict[str, int]:
        return collect(self.node, self.manager, self.tower).as_dict()


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    service: "Service"  # set by server subclass

    def handle(self) -> None:
        try:
            line = self.rfile.readline()
            if not line:
                return
            req = json.loads(line.decode("utf-8"))
            resp = self.dispatch(req)
            out = json.dumps(resp).encode("utf-8") + b"\n"
            self.wfile.write(out)
            self.wfile.flush()
        except Exception as e:  # noqa: BLE001
            _log.exception("daemon request handler failed")
            err = json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"})
            try:
                self.wfile.write(err.encode("utf-8") + b"\n")
                self.wfile.flush()
            except Exception:  # noqa: BLE001
                pass

    def dispatch(self, req: dict) -> dict:
        cmd = req.get("cmd")
        srv: Service = self.service
        if cmd == "ping":
            return {"ok": True, "pong": True}
        if cmd == "status":
            return {"ok": True, "status": srv.status()}
        if cmd == "shutdown":
            assert isinstance(self.server, _Server)
            self.server.shutdown_signal.set()
            return {"ok": True}
        if cmd == "node.generate":
            pk = PublicKey.from_hex(req["payout_pk_hex"])
            bh, txs = srv.node.generate_block(p2pkh_script(pk))
            srv.metrics.inc("blocks.generated")
            return {"ok": True, "block_hash": bh.hex(), "txs": len(txs)}
        if cmd == "node.height":
            return {"ok": True, "height": srv.node.height()}
        return {"ok": False, "error": f"unknown cmd: {cmd!r}"}


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server with a shutdown signal."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int],
                 handler: type[socketserver.BaseRequestHandler],
                 service: "Service") -> None:
        # Inject the service into the handler class.
        handler_cls = type(handler.__name__, (handler,), {"service": service})
        super().__init__(address, handler_cls)
        self.shutdown_signal = threading.Event()


@dataclass
class Daemon:
    """A runnable service daemon bound to a local TCP port."""

    service: Service
    host: str = "127.0.0.1"
    port: int = 0
    _server: Optional[_Server] = None
    _thread: Optional[threading.Thread] = None

    def start(self) -> int:
        if self._server is not None:
            raise DaemonError("daemon already started")
        self._server = _Server((self.host, self.port), _Handler, self.service)
        self.port = self._server.server_address[1]
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        self._thread = t
        _log.info("daemon listening on %s:%d", self.host, self.port)
        return self.port

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def address(self) -> tuple[str, int]:
        return (self.host, self.port)


# ---------------------------------------------------------------------------
# Client helper (used by the CLI)
# ---------------------------------------------------------------------------


def call(host: str, port: int, req: dict, timeout: float = 3.0) -> dict:
    """One-shot request/response against a running daemon."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(json.dumps(req).encode("utf-8") + b"\n")
        # Read one line.
        buf = b""
        sock.settimeout(timeout)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
        line, _, _ = buf.partition(b"\n")
    return json.loads(line.decode("utf-8"))


__all__ = ["Service", "Daemon", "DaemonError", "call"]
