"""Background monitor loop for the watchtower.

The simple synchronous design relies on the embedded node's mempool
observers (the tower attaches itself via :meth:`Mempool.add_observer`).
For an event-driven daemon, the monitor wraps the tower's polling in a
runnable callable so it can be scheduled by the runtime's executor.

The monitor exposes an observable :attr:`ticks` counter so a test (or a
status command) can verify it is alive without having to inspect log
output.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

from .tower import Tower


_log = logging.getLogger(__name__)


@dataclass
class Monitor:
    """A non-essential, periodic 'tick' loop for the tower.

    The tower already reacts to mempool admit events synchronously via
    its observer; this monitor exists to (a) survive a temporary mempool
    observer detach and (b) emit periodic health logs and an observable
    tick counter.

    Lifecycle: ``start()`` spawns a daemon thread that increments
    :attr:`ticks` once per ``interval_s``; ``stop()`` signals the thread
    to exit and joins it.
    """

    tower: Tower
    interval_s: float = 1.0
    ticks: int = 0
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self.ticks = 0
        t = threading.Thread(target=self._run, name="watchtower-monitor",
                              daemon=True)
        t.start()
        self._thread = t

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.ticks += 1
                _log.debug("watchtower tick %d: %d records, %d interventions",
                            self.ticks, len(self.tower.registry),
                            self.tower.interventions)
            except Exception:  # noqa: BLE001
                _log.exception("watchtower tick error")
            # ``wait`` returns True if stop was set, False on timeout — we
            # rely on the loop guard to exit either way.
            self._stop.wait(self.interval_s)


__all__ = ["Monitor"]
