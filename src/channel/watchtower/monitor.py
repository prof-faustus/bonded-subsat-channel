"""Background monitor loop for the watchtower.

The simple synchronous design relies on the embedded node's mempool
observers (the tower attaches itself via :meth:`Mempool.add_observer`).
For an event-driven daemon, the monitor wraps the tower's polling in a
runnable callable so it can be scheduled by the runtime's executor.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .tower import Tower


_log = logging.getLogger(__name__)


@dataclass
class Monitor:
    """A non-essential, periodic 'tick' loop for the tower.

    The tower already reacts to mempool admit events synchronously via
    its observer; this monitor exists to (a) survive a temporary mempool
    observer detach and (b) emit periodic health logs.
    """

    tower: Tower
    interval_s: float = 1.0
    _stop: threading.Event = threading.Event()
    _thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        t = threading.Thread(target=self._run, name="watchtower-monitor",
                              daemon=True)
        t.start()
        self._thread = t

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                _log.debug("watchtower tick: %d records, %d interventions",
                            len(self.tower.registry), self.tower.interventions)
            except Exception:  # noqa: BLE001
                _log.exception("watchtower tick error")
            self._stop.wait(self.interval_s)


__all__ = ["Monitor"]
