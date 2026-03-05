"""
NullSec LoRa Mesh - Tests for Compression
"""

import pytest
from protocol.compression import Compressor, CompressionMode


class TestCompressor:
    def setup_method(self):
        self.comp = Compressor(mode=CompressionMode.ADAPTIVE)

    def test_compress_decompress_roundtrip(self):
        """Data should survive compress/decompress cycle."""
        data = b"Hello, this is a test message for LoRa mesh compression!" * 5
        compressed = self.comp.compress(data)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data

    def test_small_data_no_compression(self):
        """Small payloads should not be compressed."""
        data = b"tiny"
        compressed = self.comp.compress(data)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data

    def test_lz4_mode(self):
        """LZ4 compression should work."""
        data = b"A" * 200  # Highly compressible
        compressed = self.comp.compress(data, mode=CompressionMode.LZ4_FAST)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data
        # Should be smaller
        assert len(compressed) < len(data)

    def test_zstd_mode(self):
        """Zstd compression should work."""
        data = b"The quick brown fox " * 20
        compressed = self.comp.compress(data, mode=CompressionMode.ZSTD_BALANCED)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data

    def test_incompressible_data(self):
        """Random data should not grow."""
        import os
        data = os.urandom(100)
        compressed = self.comp.compress(data)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data

    def test_estimate_ratio(self):
        """Ratio estimation should be reasonable."""
        # Highly compressible
        ratio_high = self.comp.estimate_ratio(b"A" * 200)
        assert ratio_high > 2.0

        # Random data (low compressibility)
        import os
        ratio_low = self.comp.estimate_ratio(os.urandom(200))
        assert ratio_low < 2.0

    def test_none_mode(self):
        """NONE mode should pass through unchanged."""
        data = b"unchanged data"
        compressed = self.comp.compress(data, mode=CompressionMode.NONE)
        decompressed = self.comp.decompress(compressed)
        assert decompressed == data
