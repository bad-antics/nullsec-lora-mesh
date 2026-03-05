"""
NullSec LoRa Mesh - Adaptive Compression

Provides LZ4 (fast) and Zstandard (high ratio) compression
with automatic mode selection based on payload characteristics.
"""

import struct
from enum import IntEnum
from typing import Tuple

try:
    import lz4.frame as lz4
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


class CompressionMode(IntEnum):
    """Compression algorithm selection."""
    NONE = 0x00
    LZ4_FAST = 0x01
    ZSTD_BALANCED = 0x02
    ZSTD_MAX = 0x03
    ADAPTIVE = 0xFF


# Thresholds for adaptive mode
ADAPTIVE_SMALL_THRESHOLD = 32     # Don't compress below this size
ADAPTIVE_LARGE_THRESHOLD = 128    # Use Zstd above this size


class Compressor:
    """
    Adaptive compression engine for LoRa mesh payloads.

    Automatically selects the best compression algorithm based on
    payload size and compressibility.

    Compressed format:
    ┌──────┬──────────┬────────────────────┐
    │ Mode │ Orig Len │ Compressed Data    │
    │ 1B   │ 2B       │ variable           │
    └──────┴──────────┴────────────────────┘
    """

    HEADER_SIZE = 3  # 1 byte mode + 2 bytes original length

    def __init__(self, mode: CompressionMode = CompressionMode.ADAPTIVE):
        self.mode = mode
        self._zstd_compressor = None
        self._zstd_decompressor = None

        if HAS_ZSTD:
            self._zstd_compressor = zstd.ZstdCompressor(level=3)
            self._zstd_max_compressor = zstd.ZstdCompressor(level=19)
            self._zstd_decompressor = zstd.ZstdDecompressor()

    def compress(self, data: bytes, mode: CompressionMode = None) -> bytes:
        """
        Compress data with the specified or adaptive mode.

        Returns compressed data with mode header prepended.
        """
        mode = mode or self.mode

        if mode == CompressionMode.ADAPTIVE:
            mode = self._select_mode(data)

        if mode == CompressionMode.NONE or len(data) < ADAPTIVE_SMALL_THRESHOLD:
            return self._pack(CompressionMode.NONE, data, len(data))

        if mode == CompressionMode.LZ4_FAST:
            compressed = self._compress_lz4(data)
        elif mode == CompressionMode.ZSTD_BALANCED:
            compressed = self._compress_zstd(data, level=3)
        elif mode == CompressionMode.ZSTD_MAX:
            compressed = self._compress_zstd(data, level=19)
        else:
            compressed = data

        # Only use compression if it actually saves space
        if len(compressed) >= len(data):
            return self._pack(CompressionMode.NONE, data, len(data))

        return self._pack(mode, compressed, len(data))

    def decompress(self, data: bytes) -> bytes:
        """
        Decompress data, reading mode from header.

        Returns original uncompressed data.
        """
        mode, orig_len, compressed = self._unpack(data)

        if mode == CompressionMode.NONE:
            return compressed

        if mode == CompressionMode.LZ4_FAST:
            return self._decompress_lz4(compressed)
        elif mode in (CompressionMode.ZSTD_BALANCED, CompressionMode.ZSTD_MAX):
            return self._decompress_zstd(compressed)
        else:
            raise ValueError(f"Unknown compression mode: {mode}")

    def estimate_ratio(self, data: bytes) -> float:
        """Estimate compression ratio without full compression."""
        if len(data) < ADAPTIVE_SMALL_THRESHOLD:
            return 1.0

        # Quick entropy estimation
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * (p and __import__("math").log2(p))

        # Higher entropy = less compressible
        # Max entropy = 8 bits (random data)
        return max(1.0, 8.0 / max(entropy, 0.1))

    # ── Internal methods ──

    def _select_mode(self, data: bytes) -> CompressionMode:
        """Adaptively select the best compression mode."""
        size = len(data)

        if size < ADAPTIVE_SMALL_THRESHOLD:
            return CompressionMode.NONE

        ratio = self.estimate_ratio(data)

        if ratio < 1.2:
            return CompressionMode.NONE  # Not worth compressing
        elif size < ADAPTIVE_LARGE_THRESHOLD:
            return CompressionMode.LZ4_FAST  # Speed over ratio
        else:
            return CompressionMode.ZSTD_BALANCED  # Better ratio for larger payloads

    def _compress_lz4(self, data: bytes) -> bytes:
        if not HAS_LZ4:
            raise RuntimeError("LZ4 not installed: pip install lz4")
        return lz4.compress(data)

    def _decompress_lz4(self, data: bytes) -> bytes:
        if not HAS_LZ4:
            raise RuntimeError("LZ4 not installed: pip install lz4")
        return lz4.decompress(data)

    def _compress_zstd(self, data: bytes, level: int = 3) -> bytes:
        if not HAS_ZSTD:
            raise RuntimeError("zstandard not installed: pip install zstandard")
        if level >= 15:
            return self._zstd_max_compressor.compress(data)
        return self._zstd_compressor.compress(data)

    def _decompress_zstd(self, data: bytes) -> bytes:
        if not HAS_ZSTD:
            raise RuntimeError("zstandard not installed: pip install zstandard")
        return self._zstd_decompressor.decompress(data)

    def _pack(self, mode: CompressionMode, data: bytes, orig_len: int) -> bytes:
        """Pack compressed data with header."""
        header = struct.pack(">BH", int(mode), orig_len)
        return header + data

    def _unpack(self, data: bytes) -> Tuple[CompressionMode, int, bytes]:
        """Unpack header and compressed data."""
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Data too short for compression header")
        mode, orig_len = struct.unpack(">BH", data[:self.HEADER_SIZE])
        return CompressionMode(mode), orig_len, data[self.HEADER_SIZE:]
