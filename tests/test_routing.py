"""
NullSec LoRa Mesh - Tests for AODV Routing
"""

import pytest
import time
from protocol.routing import MeshRouter, RouteEntry, ROUTE_LIFETIME


class TestMeshRouter:
    def test_direct_neighbor(self):
        """Should route to direct neighbors."""
        router = MeshRouter(node_id=1)
        router._update_neighbor(2, rssi=-50)
        assert router.get_next_hop(2) == 2

    def test_no_route(self):
        """Should return None for unknown destinations."""
        router = MeshRouter(node_id=1)
        assert router.get_next_hop(99) is None

    def test_rreq_creation(self):
        """Should create valid RREQ payload."""
        router = MeshRouter(node_id=1)
        payload = router.create_rreq(destination=5)
        assert len(payload) == 21  # 4+4+4+4+4+1 bytes

    def test_rreq_processing_destination(self):
        """Destination should reply with RREP."""
        router_a = MeshRouter(node_id=1)
        router_b = MeshRouter(node_id=2)

        rreq = router_a.create_rreq(destination=2)
        result = router_b.process_rreq(rreq, from_node=1)

        # Should be RREP (16 bytes)
        assert result is not None
        assert len(result) == 16

    def test_rreq_dedup(self):
        """Should not rebroadcast duplicate RREQ."""
        router = MeshRouter(node_id=3)
        src_router = MeshRouter(node_id=1)

        rreq = src_router.create_rreq(destination=5)

        # First time: process and forward
        result1 = router.process_rreq(rreq, from_node=1)
        # Second time: should be dropped
        result2 = router.process_rreq(rreq, from_node=2)

        assert result1 is not None
        assert result2 is None

    def test_rrep_creates_route(self):
        """Processing RREP should create a route."""
        router = MeshRouter(node_id=1)
        import struct
        rrep = struct.pack(">IIII", 5, 1, 1, 1)  # dst=5, seq=1, src=1, hops=1

        router.process_rrep(rrep, from_node=3)
        assert router.has_route(5)
        assert router.get_next_hop(5) == 3

    def test_route_update_fresher(self):
        """Should prefer routes with higher sequence numbers."""
        router = MeshRouter(node_id=1)
        router._update_route(5, next_hop=2, hop_count=3, sequence_number=1)
        router._update_route(5, next_hop=3, hop_count=2, sequence_number=2)

        assert router.get_next_hop(5) == 3  # Fresher route

    def test_route_update_shorter(self):
        """Should prefer shorter routes with same sequence."""
        router = MeshRouter(node_id=1)
        router._update_route(5, next_hop=2, hop_count=3, sequence_number=1)
        router._update_route(5, next_hop=3, hop_count=1, sequence_number=1)

        assert router.get_next_hop(5) == 3  # Shorter route

    def test_rerr_invalidates_route(self):
        """RERR should invalidate affected routes."""
        router = MeshRouter(node_id=1)
        router._update_route(5, next_hop=2, hop_count=2, sequence_number=1)

        import struct
        rerr = struct.pack(">III", 5, 2, 2)  # dest=5, seq=2, reporter=2
        router.process_rerr(rerr)

        assert not router.has_route(5)

    def test_neighbor_discovery(self):
        """HELLO processing should add neighbors."""
        router = MeshRouter(node_id=1)
        router.process_hello(from_node=2, payload=b"\x00", rssi=-60)
        router.process_hello(from_node=3, payload=b"\x00", rssi=-70)

        neighbors = router.get_neighbors()
        assert len(neighbors) == 2

    def test_cleanup(self):
        """Cleanup should remove expired entries."""
        router = MeshRouter(node_id=1)
        router._update_route(5, next_hop=2, hop_count=1, sequence_number=1)
        # Artificially expire
        router.routes[5].lifetime = time.time() - 1
        router.cleanup()
        assert 5 not in router.routes
