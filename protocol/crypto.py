"""
NullSec LoRa Mesh - Cryptographic Layer

Zero-leakage encryption using ChaCha20-Poly1305 AEAD
with X25519 ephemeral key exchange.
"""

import os
import struct
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Constants
NONCE_SIZE = 12          # ChaCha20-Poly1305 nonce
AUTH_TAG_SIZE = 16       # AEAD authentication tag
KEY_SIZE = 32            # 256-bit symmetric key
REKEY_INTERVAL = 1000    # Messages before rekey
REKEY_TIME = 3600        # Seconds before rekey (1 hour)
ANTI_REPLAY_WINDOW = 128 # Sliding window size


@dataclass
class SessionKey:
    """Symmetric session key with metadata."""
    key: bytes
    created_at: float = field(default_factory=time.time)
    message_count: int = 0
    peer_id: int = 0

    @property
    def needs_rekey(self) -> bool:
        """Check if this key should be rotated."""
        return (
            self.message_count >= REKEY_INTERVAL
            or (time.time() - self.created_at) >= REKEY_TIME
        )


class AntiReplay:
    """
    Sliding window anti-replay protection.

    Prevents replay attacks by tracking seen sequence numbers
    using a bitmap sliding window.
    """

    def __init__(self, window_size: int = ANTI_REPLAY_WINDOW):
        self.window_size = window_size
        self.highest_seq = 0
        self._bitmap = 0  # Bitmask of seen sequences

    def check_and_update(self, seq: int) -> bool:
        """
        Check if a sequence number is valid (not replayed).

        Returns True if the sequence is new and valid.
        """
        if seq == 0:
            return True  # Initial sequence

        if seq > self.highest_seq:
            # New highest - shift window
            shift = min(seq - self.highest_seq, self.window_size)
            self._bitmap = (self._bitmap << shift) & ((1 << self.window_size) - 1)
            self._bitmap |= 1  # Mark current as seen
            self.highest_seq = seq
            return True

        # Check if within window
        diff = self.highest_seq - seq
        if diff >= self.window_size:
            return False  # Too old

        # Check bitmap
        bit = 1 << diff
        if self._bitmap & bit:
            return False  # Already seen (replay)

        self._bitmap |= bit
        return True


class CryptoEngine:
    """
    Mesh network cryptographic engine.

    Provides:
    - X25519 ECDH key exchange
    - ChaCha20-Poly1305 AEAD encryption
    - Anti-replay protection per peer
    - Automatic key rotation
    """

    def __init__(self):
        # Generate identity keypair
        self._private_key = X25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()

        # Per-peer session keys and anti-replay
        self._session_keys: Dict[int, SessionKey] = {}
        self._anti_replay: Dict[int, AntiReplay] = {}

        # Monotonic sequence counter
        self._sequence = 0

    @property
    def public_key_bytes(self) -> bytes:
        """Get our public key as raw bytes."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def derive_session_key(self, peer_id: int, peer_public_key: bytes) -> bytes:
        """
        Perform X25519 ECDH key exchange and derive a session key.

        Uses HKDF-SHA256 to derive a 256-bit symmetric key from
        the shared secret.
        """
        peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = self._private_key.exchange(peer_key)

        # Derive symmetric key using HKDF
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"nullsec-lora-mesh-v1",
        ).derive(shared_secret)

        self._session_keys[peer_id] = SessionKey(
            key=session_key,
            peer_id=peer_id,
        )
        self._anti_replay[peer_id] = AntiReplay()

        return session_key

    def encrypt(self, peer_id: int, plaintext: bytes,
                associated_data: bytes = b"") -> Tuple[bytes, bytes, int]:
        """
        Encrypt data for a specific peer.

        Returns: (ciphertext, auth_tag, sequence_number)
        """
        session = self._session_keys.get(peer_id)
        if not session:
            raise ValueError(f"No session key for peer 0x{peer_id:08X}")

        # Check for rekey
        if session.needs_rekey:
            self._rotate_key(peer_id)
            session = self._session_keys[peer_id]

        # Increment sequence
        self._sequence += 1
        session.message_count += 1

        # Build nonce from sequence number (12 bytes)
        nonce = struct.pack(">I", 0) + struct.pack(">Q", self._sequence)

        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(session.key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)

        # Split ciphertext and auth tag
        ct = ciphertext[:-AUTH_TAG_SIZE]
        tag = ciphertext[-AUTH_TAG_SIZE:]

        return ct, tag, self._sequence

    def decrypt(self, peer_id: int, ciphertext: bytes,
                auth_tag: bytes, sequence: int,
                associated_data: bytes = b"") -> bytes:
        """
        Decrypt data from a specific peer.

        Verifies authentication tag and checks anti-replay.
        """
        session = self._session_keys.get(peer_id)
        if not session:
            raise ValueError(f"No session key for peer 0x{peer_id:08X}")

        # Anti-replay check
        replay = self._anti_replay.get(peer_id)
        if replay and not replay.check_and_update(sequence):
            raise ValueError(f"Replay detected: sequence {sequence}")

        # Reconstruct nonce
        nonce = struct.pack(">I", 0) + struct.pack(">Q", sequence)

        # Reconstruct ciphertext + tag for AEAD
        ct_with_tag = ciphertext + auth_tag

        # Decrypt and verify
        cipher = ChaCha20Poly1305(session.key)
        try:
            plaintext = cipher.decrypt(nonce, ct_with_tag, associated_data)
            return plaintext
        except Exception:
            raise ValueError("Decryption failed: invalid key or tampered data")

    def has_session(self, peer_id: int) -> bool:
        """Check if we have an active session with a peer."""
        return peer_id in self._session_keys

    def _rotate_key(self, peer_id: int):
        """Rotate session key using HKDF on the old key."""
        old_session = self._session_keys[peer_id]

        new_key = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=os.urandom(32),
            info=b"nullsec-lora-mesh-rekey",
        ).derive(old_session.key)

        self._session_keys[peer_id] = SessionKey(
            key=new_key,
            peer_id=peer_id,
        )

    def create_key_exchange_payload(self) -> bytes:
        """Create payload for KEXCH message."""
        return self.public_key_bytes

    def process_key_exchange(self, peer_id: int, payload: bytes) -> bytes:
        """Process received KEXCH message and return our public key."""
        self.derive_session_key(peer_id, payload)
        return self.public_key_bytes
