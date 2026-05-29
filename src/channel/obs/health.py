"""Health checks: a snapshot of the system's vital signs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..node.network import EmbeddedNode
    from ..runtime.manager import ChannelManager
    from ..watchtower.tower import Tower


@dataclass(frozen=True)
class Health:
    node_height: int
    mempool_size: int
    open_channels: int
    closed_channels: int
    tower_records: int
    tower_interventions: int

    def as_dict(self) -> dict[str, int]:
        return {
            "node_height": self.node_height,
            "mempool_size": self.mempool_size,
            "open_channels": self.open_channels,
            "closed_channels": self.closed_channels,
            "tower_records": self.tower_records,
            "tower_interventions": self.tower_interventions,
        }


def collect(node: "EmbeddedNode", mgr: "ChannelManager",
            tower: "Tower | None" = None) -> Health:
    return Health(
        node_height=node.height(),
        mempool_size=node.mempool.size(),
        open_channels=len(mgr.channels) - len(mgr.closed_channels),
        closed_channels=len(mgr.closed_channels),
        tower_records=len(tower.registry) if tower else 0,
        tower_interventions=tower.interventions if tower else 0,
    )


__all__ = ["Health", "collect"]
