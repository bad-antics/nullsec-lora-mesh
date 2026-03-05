"""
NullSec LoRa Mesh - Mesh Node

Main MeshNode class that ties together all protocol layers.
"""

import time
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from queue import Queue, Empty

from protocol import (
    MeshFrame, MessageType, FrameFlags,
    create_data_frame, create_ack_frame, create_hello_frame,
    MAX_PAYLOAD_SIZE,
)
from protocol.compression import Compressor, CompressionMode
from protocol.crypto import CryptoEngine
from protocol.routing import MeshRouter, HELLO_INTERVAL
from protocol.fec import ReedSolomon


@dataclass
class LoRaConfig:
    """LoRa radio configuration."""
    frequency: float = 915.0        # MHz
    bandwidth: int = 125000         # Hz
    spreading_factor: int = 7       # SF7-SF12
    coding_rate: int = 5            # 4/5 to 4/8
    tx_power: int = 14              # dBm (max 20)
    sync_word: int = 0x34           # Private network
    preamble_length: int = 8


@dataclass
class ReceivedMessage:
    """A message received from the mesh."""
    src: int
    data: bytes
    rssi: int = 0
    snr: float = 0.0
    hop_count: int = 0
    timestamp: float = 0.0


class MeshNode:
    """
    LoRa Mesh Network Node.

    Integrates all protocol layers into a single interface:
    - Frame encoding/decoding
    - Adaptive compression
    - ChaCha20-Poly1305 encryption
    - Reed-Solomon FEC
    - AODV mesh routing
    - Message fragmentation/reassembly
    """

    def __init__(
        self,
        node_id: int,
        config: LoRaConfig = None,
        compression: str = "adaptive",
        encryption: bool = True,
        fec_symbols: int = 16,
    ):
        self.node_id = node_id
        self.config = config or LoRaConfig()
        self.encryption_enabled = encryption

        # Protocol layers
        self.router = MeshRouter(node_id)
        self.crypto = CryptoEngine()
        self.fec = ReedSolomon(nsym=fec_symbols)

        # Compression mode
        comp_modes = {
            "adaptive": CompressionMode.ADAPTIVE,
            "lz4": CompressionMode.LZ4_FAST,
            "zstd": CompressionMode.ZSTD_BALANCED,
            "zstd-max": CompressionMode.ZSTD_MAX,
            "none": CompressionMode.NONE,
        }
        self.compressor = Compressor(
            mode=comp_modes.get(compression, CompressionMode.ADAPTIVE)
        )

        # Message queues
        self._rx_queue: Queue[ReceivedMessage] = Queue()
        self._tx_queue: Queue[MeshFrame] = Queue()

        # Fragment reassembly buffer
        self._fragments: Dict[int, Dict[int, bytes]] = {}

        # Sequence counter
        self._sequence = 0

        # State
        self._running = False
        self._radio = None
        self._threads: List[threading.Thread] = []

        # Callbacks
        self._on_message: Optional[Callable] = None
        self._on_neighbor: Optional[Callable] = None

    def start(self):
        """Start the mesh node."""
        self._running = True

        # Start beacon thread
        beacon = threading.Thread(target=self._beacon_loop, daemon=True)
        beacon.start()
        self._threads.append(beacon)

        # Start route maintenance
        maintenance = threading.Thread(target=self._maintenance_loop, daemon=True)
        maintenance.start()
        self._threads.append(maintenance)

    def stop(self):
        """Stop the mesh node."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()

    def send(self, dest: int, data: bytes, reliable: bool = True) -> bool:
        """
        Send data to a destination node.

        Handles compression, encryption, fragmentation, and routing.
        """
        # Step 1: Compress
        compressed = self.compressor.compress(data)

        # Step 2: Encrypt
        if self.encryption_enabled and dest != MeshFrame.BROADCAST_ADDR:
            if not self.crypto.has_session(dest):
                # Need key exchange first
                self._initiate_key_exchange(dest)
                # Wait briefly for key exchange
                time.sleep(2)
                if not self.crypto.has_session(dest):
                    return False  # Key exchange failed

            ciphertext, auth_tag, seq = self.crypto.encrypt(
                peer_id=dest,
                plaintext=compressed,
                associated_data=b"",
            )
            payload_data = ciphertext
            flags = FrameFlags.ENCRYPTED | FrameFlags.COMPRESSED
        else:
            payload_data = compressed
            auth_tag = b""
            flags = FrameFlags.COMPRESSED

        if reliable:
            flags |= FrameFlags.RELIABLE

        # Step 3: Fragment if needed
        if len(payload_data) > MAX_PAYLOAD_SIZE:
            return self._send_fragmented(dest, payload_data, auth_tag, flags)

        # Step 4: Create frame
        self._sequence += 1
        frame = MeshFrame(
            msg_type=MessageType.DATA,
            src_id=self.node_id,
            dst_id=dest,
            sequence=self._sequence,
            flags=flags,
            payload=payload_data,
            auth_tag=auth_tag,
        )

        # Step 5: Route
        return self._route_and_send(frame)

    def receive(self, timeout: float = None) -> List[ReceivedMessage]:
        """
        Receive pending messages.

        Returns list of received messages.
        """
        messages = []
        try:
            while True:
                msg = self._rx_queue.get(timeout=timeout)
                messages.append(msg)
                timeout = 0  # Don't wait for subsequent messages
        except Empty:
            pass
        return messages

    def on_message(self, callback: Callable[[ReceivedMessage], None]):
        """Register a callback for received messages."""
        self._on_message = callback

    def on_neighbor(self, callback: Callable[[int, int], None]):
        """Register callback for neighbor discovery (node_id, rssi)."""
        self._on_neighbor = callback

    def process_frame(self, raw_data: bytes, rssi: int = 0, snr: float = 0.0):
        """
        Process a received frame through the protocol stack.

        Called by the radio driver when data is received.
        """
        try:
            frame = MeshFrame.decode(raw_data)
        except ValueError:
            return  # Invalid frame

        # Handle by message type
        if frame.msg_type == MessageType.HELLO:
            self.router.process_hello(frame.src_id, frame.payload, rssi)
            if self._on_neighbor:
                self._on_neighbor(frame.src_id, rssi)

        elif frame.msg_type == MessageType.RREQ:
            result = self.router.process_rreq(frame.payload, frame.src_id, rssi)
            if result:
                # Forward RREQ or send RREP
                resp_type = MessageType.RREP if len(result) == 16 else MessageType.RREQ
                resp = MeshFrame(
                    msg_type=resp_type,
                    src_id=self.node_id,
                    dst_id=frame.src_id if resp_type == MessageType.RREP else MeshFrame.BROADCAST_ADDR,
                    payload=result,
                    flags=FrameFlags.BROADCAST if resp_type == MessageType.RREQ else 0,
                )
                self._tx_queue.put(resp)

        elif frame.msg_type == MessageType.RREP:
            result = self.router.process_rrep(frame.payload, frame.src_id, rssi)
            if result:
                # Forward RREP
                next_hop = self.router.get_next_hop(frame.dst_id)
                if next_hop:
                    fwd = MeshFrame(
                        msg_type=MessageType.RREP,
                        src_id=self.node_id,
                        dst_id=frame.dst_id,
                        payload=result,
                    )
                    self._tx_queue.put(fwd)

        elif frame.msg_type == MessageType.RERR:
            self.router.process_rerr(frame.payload)

        elif frame.msg_type == MessageType.KEXCH:
            response = self.crypto.process_key_exchange(
                frame.src_id, frame.payload,
            )
            # Send our public key back
            resp = MeshFrame(
                msg_type=MessageType.KEXCH,
                src_id=self.node_id,
                dst_id=frame.src_id,
                payload=response,
            )
            self._tx_queue.put(resp)

        elif frame.msg_type == MessageType.DATA:
            if frame.dst_id == self.node_id or frame.is_broadcast:
                self._handle_data_frame(frame, rssi, snr)
            elif self.router.has_route(frame.dst_id):
                # Forward
                self._route_and_send(frame)

        elif frame.msg_type == MessageType.ACK:
            pass  # Handle ACK (clear retry timer)

    def _handle_data_frame(self, frame: MeshFrame, rssi: int, snr: float):
        """Process a DATA frame destined for us."""
        payload = frame.payload

        # Decrypt if encrypted
        if frame.is_encrypted:
            try:
                payload = self.crypto.decrypt(
                    peer_id=frame.src_id,
                    ciphertext=frame.payload,
                    auth_tag=frame.auth_tag,
                    sequence=frame.sequence,
                )
            except ValueError:
                return  # Decryption failed

        # Decompress
        if frame.is_compressed:
            try:
                payload = self.compressor.decompress(payload)
            except Exception:
                return  # Decompression failed

        msg = ReceivedMessage(
            src=frame.src_id,
            data=payload,
            rssi=rssi,
            snr=snr,
            timestamp=time.time(),
        )

        self._rx_queue.put(msg)
        if self._on_message:
            self._on_message(msg)

        # Send ACK if reliable
        if frame.is_reliable:
            ack = create_ack_frame(self.node_id, frame.src_id, frame.sequence)
            self._tx_queue.put(ack)

    def _route_and_send(self, frame: MeshFrame) -> bool:
        """Route a frame and queue for transmission."""
        if frame.is_broadcast:
            self._tx_queue.put(frame)
            return True

        next_hop = self.router.get_next_hop(frame.dst_id)
        if next_hop is None:
            # Need route discovery
            rreq_payload = self.router.create_rreq(frame.dst_id)
            rreq = MeshFrame(
                msg_type=MessageType.RREQ,
                src_id=self.node_id,
                dst_id=MeshFrame.BROADCAST_ADDR,
                flags=FrameFlags.BROADCAST,
                payload=rreq_payload,
            )
            self._tx_queue.put(rreq)
            # TODO: Queue frame for retry after route discovery
            return False

        self._tx_queue.put(frame)
        return True

    def _send_fragmented(self, dest: int, data: bytes,
                         auth_tag: bytes, flags: int) -> bool:
        """Fragment and send a large message."""
        self._sequence += 1
        frag_id = self._sequence

        chunk_size = MAX_PAYLOAD_SIZE - 8  # Reserve space for frag header
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        for i, chunk in enumerate(chunks):
            frag_header = (frag_id).to_bytes(4, "big") + \
                          (i).to_bytes(2, "big") + \
                          (len(chunks)).to_bytes(2, "big")

            frame = MeshFrame(
                msg_type=MessageType.FRAG,
                src_id=self.node_id,
                dst_id=dest,
                sequence=self._sequence + i,
                flags=flags | FrameFlags.FRAGMENTED,
                payload=frag_header + chunk,
                auth_tag=auth_tag if i == len(chunks) - 1 else b"",
            )
            self._tx_queue.put(frame)

        return True

    def _initiate_key_exchange(self, peer_id: int):
        """Start key exchange with a peer."""
        payload = self.crypto.create_key_exchange_payload()
        frame = MeshFrame(
            msg_type=MessageType.KEXCH,
            src_id=self.node_id,
            dst_id=peer_id,
            payload=payload,
        )
        self._route_and_send(frame)

    def _beacon_loop(self):
        """Periodically send HELLO beacons."""
        while self._running:
            hello = create_hello_frame(self.node_id, hop_count=0)
            self._tx_queue.put(hello)
            time.sleep(HELLO_INTERVAL)

    def _maintenance_loop(self):
        """Periodic route table maintenance."""
        while self._running:
            self.router.cleanup()
            time.sleep(60)
