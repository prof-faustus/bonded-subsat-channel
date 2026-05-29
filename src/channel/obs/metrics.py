"""In-process metrics counters.

A tiny zero-dependency metrics registry; designed to be polled by a
status command rather than scraped by an external collector (the spec
forbids external services).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class Metrics:
    """Concurrent counters and gauges."""

    _counters: dict[str, int] = field(default_factory=dict)
    _gauges: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def gauge(self, name: str) -> float:
        with self._lock:
            return self._gauges.get(name, 0.0)

    def snapshot(self) -> dict[str, dict[str, float]]:
        with self._lock:
            return {
                "counters": {k: float(v) for k, v in self._counters.items()},
                "gauges": dict(self._gauges),
            }


__all__ = ["Metrics"]
