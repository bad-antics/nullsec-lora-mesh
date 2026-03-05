"""
NullSec LoRa Mesh - Tests for Frame Protocol
"""

import pytest
from protocol import (
    MeshFrame, MessageType, FrameFlags, SYNC_WORD,
    create_data_frame, create_ack_frame, create_hello_frame,
    MAX_PAYLOAD_SIZE,
)


class TestMeshFrame:
    def test_encode_decode_roundtrip(self):
        """Frame should survive encode/decode cycle."""
        frame = MeshFrame(
            msg_type=MessageType.DATA,
            src_id=0x00000001,
            dst_id=0x00000002,
            sequence=42,
            flags=FrameFlags.ENCRYPTED | FrameFlags.COMPRESSED,
            payload=b"Hello, mesh!",
        )

        encoded = frame.encode()
        decoded = MeshFrame.decode(encoded)

        assert decoded.msg_type == MessageType.DATA
        assert decoded.src_id == 0x00000001
        assert decoded.dst_id == 0x00000002
        assert decoded.sequence == 42
        assert decoded.payload == b"Hello, mesh!"
        assert decoded.is_encrypted
        assert decoded.is_compressed

    def test_sync_word(self):
        """Encoded frame should start with sync word."""
        frame = create_data_frame(1, 2, b"test")
        encoded = frame.encode()
        assert encoded[0:2] == SYNC_WORD.to_bytes(2, "big")

    def test_invalid_sync_word(self):
        """Should reject frames with wrong sync word."""
        frame = create_data_frame(1, 2, b"test")
        encoded = bytearray(frame.encode())
        encoded[0] = 0xFF
        with pytest.raises(ValueError, match="Invalid sync word"):
            MeshFrame.decode(bytes(encoded))

    def test_broadcast_frame(self):
        """Broadcast frames should have correct flags."""
        frame = create_hello_frame(0x00000001)
        assert frame.is_broadcast
        assert frame.dst_id == MeshFrame.BROADCAST_ADDR

    def test_ack_frame(self):
        """ACK frames should carry the acknowledged sequence."""
        ack = create_ack_frame(1, 2, 99)
        assert ack.msg_type == MessageType.ACK
        assert ack.sequence == 99

    def test_max_payload_size(self):
        """Should reject payloads exceeding max size."""
        frame = MeshFrame(
            msg_type=MessageType.DATA,
            src_id=1,
            dst_id=2,
            payload=b"X" * (MAX_PAYLOAD_SIZE + 50),
        )
        with pytest.raises(ValueError, match="Frame too large"):
            frame.encode()

    def test_empty_payload(self):
        """Should handle empty payloads."""
        frame = MeshFrame(
            msg_type=MessageType.PING,
            src_id=1,
            dst_id=2,
            payload=b"",
        )
        encoded = frame.encode()
        decoded = MeshFrame.decode(encoded)
        assert decoded.payload == b""

    def test_flags_properties(self):
        """Flag properties should work correctly."""
        frame = MeshFrame(
            msg_type=MessageType.DATA,
            src_id=1, dst_id=2,
            flags=FrameFlags.ENCRYPTED | FrameFlags.RELIABLE,
        )
        assert frame.is_encrypted
        assert frame.is_reliable
        assert not frame.is_compressed
        assert not frame.is_broadcast


class TestFrameHelpers:
    def test_create_data_frame(self):
        frame = create_data_frame(1, 2, b"data", encrypted=True, reliable=True)
        assert frame.msg_type == MessageType.DATA
        assert frame.is_encrypted
        assert frame.is_reliable

    def test_create_broadcast_data(self):
        frame = create_data_frame(1, MeshFrame.BROADCAST_ADDR, b"broadcast")
        assert frame.is_broadcast
