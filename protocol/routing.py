"""
NullSec LoRa Mesh - AODV Mesh Routing

Ad-hoc On-Demand Distance Vector routing for LoRa mesh networks.
Adapted for low-bandwidth, high-latency LoRa characteristics.
"""

import time
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import IntEnum


# Route timeouts (seconds)
ROUTE_LIFETIME = 300        # Active route lifetime
ROUTE_DELETE_PERIOD = 600   # Time before route deletion
HELLO_INTERVAL = 30         # Beacon interval
RREQ_RETRIES = 3            # Max route request retries
RREQ_TIMEOUT = 10           # Wait time for RREP
MAX_HOP_COUNT = 15          # Maximum hops in mesh
BROADCAST_ID_CACHE_TIME = 60  # Time to cache seen broadcasts


@dataclass
class RouteEntry:
    """An entry in the routing table."""
    destination: int          # Destination node ID
    next_hop: int             # Next hop node ID
    hop_count: int            # Distance in hops
    sequence_number: int      # Destination sequence number
    lifetime: float           # Expiry timestamp
    precursors: Set[int] = field(default_factory=set)  # Nodes using this route
    is_valid: bool = True

    @property
    def is_expired(self) -> bool:
        return time.time() > self.lifetime


@dataclass
class RREQEntry:
    """Cached Route Request to prevent rebroadcast."""
    src_id: int
    broadcast_id: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class NeighborEntry:
    """A known neighbor node."""
    node_id: int
    last_seen: float = field(default_factory=time.time)
    rssi: int = 0           # Signal strength
    hop_count: int = 1
    link_quality: float = 1.0

    @property
    def is_alive(self) -> bool:
        return (time.time() - self.last_seen) < (HELLO_INTERVAL * 3)


class MeshRouter:
    """
    AODV-inspired mesh routing engine for LoRa.

    Features:
    - On-demand route discovery (RREQ/RREP)
    - Route maintenance with sequence numbers
    - Neighbor discovery via HELLO beacons
    - Broken link detection and RERR propagation
    - Route caching to minimize discovery overhead
    """

    def __init__(self, node_id: int):
        self.node_id = node_id
        self.sequence_number = 0

        # Routing table: destination -> RouteEntry
        self.routes: Dict[int, RouteEntry] = {}

        # Neighbor table: node_id -> NeighborEntry
        self.neighbors: Dict[int, NeighborEntry] = {}

        # RREQ cache to prevent rebroadcast
        self._rreq_cache: List[RREQEntry] = []
        self._broadcast_id = 0

        # Pending route requests
        self._pending_rreq: Dict[int, float] = {}

    def get_next_hop(self, destination: int) -> Optional[int]:
        """
        Get the next hop for a destination.

        Returns None if no route exists (triggers RREQ).
        """
        route = self.routes.get(destination)
        if route and route.is_valid and not route.is_expired:
            # Refresh lifetime on use
            route.lifetime = time.time() + ROUTE_LIFETIME
            return route.next_hop

        # Direct neighbor?
        if destination in self.neighbors:
            neighbor = self.neighbors[destination]
            if neighbor.is_alive:
                return destination

        return None

    def has_route(self, destination: int) -> bool:
        """Check if a valid route exists to destination."""
        return self.get_next_hop(destination) is not None

    def create_rreq(self, destination: int) -> bytes:
        """
        Create a Route Request (RREQ) message.

        RREQ format:
        ┌──────┬──────┬──────┬──────┬──────┬──────┐
        │ Bcast│ Src  │ SrcSq│ Dst  │ DstSq│ Hops │
        │ 4B   │ 4B   │ 4B   │ 4B   │ 4B   │ 1B   │
        └──────┴──────┴──────┴──────┴──────┴──────┘
        """
        self._broadcast_id += 1
        self.sequence_number += 1

        # Get last known destination sequence
        dst_seq = 0
        if destination in self.routes:
            dst_seq = self.routes[destination].sequence_number

        payload = struct.pack(
            ">IIIII B",
            self._broadcast_id,
            self.node_id,
            self.sequence_number,
            destination,
            dst_seq,
            0,  # hop count starts at 0
        )

        # Cache this RREQ
        self._rreq_cache.append(RREQEntry(
            src_id=self.node_id,
            broadcast_id=self._broadcast_id,
        ))
        self._pending_rreq[destination] = time.time()

        return payload

    def process_rreq(self, payload: bytes, from_node: int, rssi: int = 0) -> Optional[bytes]:
        """
        Process a received RREQ.

        Returns RREP payload if we are the destination or have a route,
        or modified RREQ payload for rebroadcast.
        """
        (
            broadcast_id, src_id, src_seq,
            dst_id, dst_seq, hop_count,
        ) = struct.unpack(">IIIII B", payload[:21])

        # Check if we've seen this RREQ before
        for cached in self._rreq_cache:
            if cached.src_id == src_id and cached.broadcast_id == broadcast_id:
                return None  # Already processed, drop

        # Cache this RREQ
        self._rreq_cache.append(RREQEntry(
            src_id=src_id,
            broadcast_id=broadcast_id,
        ))

        # Update neighbor table
        self._update_neighbor(from_node, rssi)

        # Create/update reverse route to source
        self._update_route(
            destination=src_id,
            next_hop=from_node,
            hop_count=hop_count + 1,
            sequence_number=src_seq,
        )

        # Are we the destination?
        if dst_id == self.node_id:
            return self._create_rrep(
                src_id=src_id,
                dst_id=self.node_id,
                dst_seq=max(self.sequence_number, dst_seq),
                hop_count=0,
            )

        # Do we have a fresh route to destination?
        if dst_id in self.routes:
            route = self.routes[dst_id]
            if route.is_valid and route.sequence_number >= dst_seq:
                return self._create_rrep(
                    src_id=src_id,
                    dst_id=dst_id,
                    dst_seq=route.sequence_number,
                    hop_count=route.hop_count,
                )

        # Rebroadcast with incremented hop count
        if hop_count < MAX_HOP_COUNT:
            return struct.pack(
                ">IIIII B",
                broadcast_id, src_id, src_seq,
                dst_id, dst_seq, hop_count + 1,
            )

        return None  # Exceeded max hops

    def process_rrep(self, payload: bytes, from_node: int, rssi: int = 0) -> Optional[bytes]:
        """
        Process a received RREP.

        Returns forwarded RREP if we're not the original source.
        """
        (
            dst_id, dst_seq, src_id, hop_count,
        ) = struct.unpack(">IIII", payload[:16])

        # Update neighbor
        self._update_neighbor(from_node, rssi)

        # Create forward route to destination
        self._update_route(
            destination=dst_id,
            next_hop=from_node,
            hop_count=hop_count + 1,
            sequence_number=dst_seq,
        )

        # Clear pending RREQ
        self._pending_rreq.pop(dst_id, None)

        # Are we the original requester?
        if src_id == self.node_id:
            return None  # Route found!

        # Forward RREP toward source
        if src_id in self.routes:
            return struct.pack(
                ">IIII",
                dst_id, dst_seq, src_id, hop_count + 1,
            )

        return None

    def process_hello(self, from_node: int, payload: bytes, rssi: int = 0):
        """Process a HELLO beacon from a neighbor."""
        hop_count = struct.unpack(">B", payload[:1])[0] if payload else 0
        self._update_neighbor(from_node, rssi, hop_count)

    def create_rerr(self, unreachable_dest: int) -> bytes:
        """Create a Route Error message for a broken link."""
        route = self.routes.get(unreachable_dest)
        if route:
            route.is_valid = False

        self.sequence_number += 1
        return struct.pack(
            ">III",
            unreachable_dest,
            route.sequence_number + 1 if route else 0,
            self.node_id,
        )

    def process_rerr(self, payload: bytes):
        """Process a Route Error — invalidate affected routes."""
        dest, seq, reporter = struct.unpack(">III", payload[:12])

        if dest in self.routes:
            route = self.routes[dest]
            if route.next_hop == reporter or route.sequence_number <= seq:
                route.is_valid = False

    def get_neighbors(self) -> List[NeighborEntry]:
        """Get list of alive neighbors."""
        return [n for n in self.neighbors.values() if n.is_alive]

    def get_route_table(self) -> List[RouteEntry]:
        """Get all valid routes."""
        return [r for r in self.routes.values() if r.is_valid and not r.is_expired]

    def cleanup(self):
        """Remove expired routes and stale RREQ cache entries."""
        now = time.time()

        # Expire routes
        for dest in list(self.routes.keys()):
            if self.routes[dest].is_expired:
                del self.routes[dest]

        # Clean RREQ cache
        self._rreq_cache = [
            r for r in self._rreq_cache
            if (now - r.timestamp) < BROADCAST_ID_CACHE_TIME
        ]

        # Clean stale neighbors
        for nid in list(self.neighbors.keys()):
            if not self.neighbors[nid].is_alive:
                del self.neighbors[nid]

    # ── Internal ──

    def _update_route(self, destination: int, next_hop: int,
                      hop_count: int, sequence_number: int):
        """Update or create a route entry."""
        existing = self.routes.get(destination)

        if existing:
            # Only update if new route is fresher or shorter
            if (sequence_number > existing.sequence_number or
                (sequence_number == existing.sequence_number and
                 hop_count < existing.hop_count)):
                existing.next_hop = next_hop
                existing.hop_count = hop_count
                existing.sequence_number = sequence_number
                existing.lifetime = time.time() + ROUTE_LIFETIME
                existing.is_valid = True
        else:
            self.routes[destination] = RouteEntry(
                destination=destination,
                next_hop=next_hop,
                hop_count=hop_count,
                sequence_number=sequence_number,
                lifetime=time.time() + ROUTE_LIFETIME,
            )

    def _update_neighbor(self, node_id: int, rssi: int = 0,
                         hop_count: int = 1):
        """Update neighbor table."""
        if node_id in self.neighbors:
            self.neighbors[node_id].last_seen = time.time()
            self.neighbors[node_id].rssi = rssi
        else:
            self.neighbors[node_id] = NeighborEntry(
                node_id=node_id,
                rssi=rssi,
                hop_count=hop_count,
            )

    def _create_rrep(self, src_id: int, dst_id: int,
                     dst_seq: int, hop_count: int) -> bytes:
        """Create a RREP payload."""
        return struct.pack(
            ">IIII",
            dst_id,
            dst_seq,
            src_id,
            hop_count,
        )
