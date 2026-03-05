"""
NullSec LoRa Mesh - Tests for Cryptographic Layer
"""

import pytest
from protocol.crypto import CryptoEngine, AntiReplay


class TestCryptoEngine:
    def test_key_exchange(self):
        """Two nodes should establish a shared session key."""
        alice = CryptoEngine()
        bob = CryptoEngine()

        alice.derive_session_key(2, bob.public_key_bytes)
        bob.derive_session_key(1, alice.public_key_bytes)

        assert alice.has_session(2)
        assert bob.has_session(1)

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt correctly."""
        alice = CryptoEngine()
        bob = CryptoEngine()

        alice.derive_session_key(2, bob.public_key_bytes)
        bob.derive_session_key(1, alice.public_key_bytes)

        plaintext = b"Secret mesh message"
        ct, tag, seq = alice.encrypt(2, plaintext)
        decrypted = bob.decrypt(1, ct, tag, seq)

        assert decrypted == plaintext

    def test_tampered_ciphertext(self):
        """Tampered ciphertext should fail authentication."""
        alice = CryptoEngine()
        bob = CryptoEngine()

        alice.derive_session_key(2, bob.public_key_bytes)
        bob.derive_session_key(1, alice.public_key_bytes)

        ct, tag, seq = alice.encrypt(2, b"secret")
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]

        with pytest.raises(ValueError):
            bob.decrypt(1, tampered, tag, seq)

    def test_no_session(self):
        """Should fail without key exchange."""
        engine = CryptoEngine()
        with pytest.raises(ValueError, match="No session key"):
            engine.encrypt(99, b"test")

    def test_key_exchange_payload(self):
        """Key exchange payload should be 32 bytes (X25519 public key)."""
        engine = CryptoEngine()
        payload = engine.create_key_exchange_payload()
        assert len(payload) == 32


class TestAntiReplay:
    def test_sequential(self):
        """Sequential sequences should all be accepted."""
        ar = AntiReplay()
        for i in range(1, 100):
            assert ar.check_and_update(i)

    def test_replay(self):
        """Replayed sequence should be rejected."""
        ar = AntiReplay()
        assert ar.check_and_update(1)
        assert ar.check_and_update(2)
        assert not ar.check_and_update(1)  # Replay!
        assert not ar.check_and_update(2)  # Replay!

    def test_out_of_order(self):
        """Out-of-order within window should be accepted."""
        ar = AntiReplay(window_size=128)
        assert ar.check_and_update(10)
        assert ar.check_and_update(5)   # Earlier but within window
        assert ar.check_and_update(8)   # Out of order but valid

    def test_too_old(self):
        """Sequences too far behind should be rejected."""
        ar = AntiReplay(window_size=64)
        assert ar.check_and_update(100)
        assert not ar.check_and_update(1)  # Way too old
