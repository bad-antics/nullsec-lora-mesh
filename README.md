# NullSec LoRa Mesh

> Zero-leakage, high-speed compressed mesh communications framework for Flipper One and LoRa-enabled devices.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)

## Overview

NullSec LoRa Mesh is a protocol framework for building secure, resilient mesh networks over LoRa radio. Designed for the **Flipper One** and compatible LoRa hardware, it provides:

- **Zero-leakage encryption** — ChaCha20-Poly1305 with ephemeral key exchange
- **High-speed compression** — LZ4/Zstandard adaptive compression for maximum throughput
- **Mesh routing** — Dynamic multi-hop routing with AODV-inspired protocol
- **Forward Error Correction** — Reed-Solomon FEC for reliable delivery over noisy channels
- **Anti-replay protection** — Monotonic counters and sliding window verification
- **Minimal overhead** — Designed for LoRa's low bandwidth (0.3 - 50 kbps)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   APPLICATION                        │
│         Chat │ File Transfer │ Telemetry             │
├─────────────────────────────────────────────────────┤
│                   TRANSPORT                          │
│     Fragmentation │ Reassembly │ Flow Control        │
├─────────────────────────────────────────────────────┤
│                   SECURITY                           │
│  ChaCha20-Poly1305 │ X25519 ECDH │ Anti-Replay      │
├─────────────────────────────────────────────────────┤
│                   COMPRESSION                        │
│      LZ4 (fast) │ Zstd (ratio) │ Adaptive           │
├─────────────────────────────────────────────────────┤
│                   MESH ROUTING                       │
│    AODV │ Flooding │ Gossip │ Route Maintenance      │
├─────────────────────────────────────────────────────┤
│                   LINK LAYER                         │
│   FEC (Reed-Solomon) │ CRC32 │ Duty Cycle Mgmt      │
├─────────────────────────────────────────────────────┤
│                   PHYSICAL                           │
│      LoRa SX1262/SX1276 │ SubGHz │ Flipper One      │
└─────────────────────────────────────────────────────┘
```

## Protocol Design

### Frame Format

```
┌──────┬──────┬──────┬────────┬──────────┬──────────┬─────┐
│ Sync │ Ver  │ Type │ Src ID │ Dst ID   │ Seq/Frag │ Len │
│ 2B   │ 1B   │ 1B   │ 4B     │ 4B       │ 4B       │ 2B  │
├──────┴──────┴──────┴────────┴──────────┴──────────┴─────┤
│                    Payload (encrypted)                    │
│                    0 - 222 bytes                          │
├──────────────────────────────────────────────────────────┤
│                    Auth Tag (16B)                         │
├──────────────────────────────────────────────────────────┤
│                    FEC Parity (variable)                  │
└──────────────────────────────────────────────────────────┘

Total overhead: 18B header + 16B auth + FEC = ~40B minimum
Max payload per frame: 222 bytes (LoRa max 255B - overhead)
```

### Message Types

| Type | ID | Description |
|------|-----|-------------|
| DATA | 0x01 | Encrypted data payload |
| ACK | 0x02 | Acknowledgment |
| RREQ | 0x03 | Route Request (broadcast) |
| RREP | 0x04 | Route Reply (unicast) |
| RERR | 0x05 | Route Error |
| HELLO | 0x06 | Neighbor discovery beacon |
| KEXCH | 0x07 | Key exchange (X25519) |
| FRAG | 0x08 | Fragment of larger message |
| PING | 0x09 | Keepalive / latency test |
| CTRL | 0x0A | Control / management |

### Compression Strategy

| Mode | Algorithm | Ratio | Speed | Use Case |
|------|-----------|-------|-------|----------|
| Fast | LZ4 | ~2:1 | 780 MB/s | Real-time chat, telemetry |
| Balanced | Zstd L3 | ~3:1 | 350 MB/s | General data |
| Maximum | Zstd L19 | ~5:1 | 15 MB/s | File transfer (pre-compress) |
| None | Passthrough | 1:1 | ∞ | Already compressed / encrypted data |

Adaptive mode auto-selects based on payload size and channel conditions.

### Security Model

1. **Key Exchange**: X25519 ECDH with ephemeral keys per session
2. **Encryption**: ChaCha20-Poly1305 AEAD (authenticated encryption)
3. **Anti-Replay**: 64-bit monotonic counter + sliding window (128 entries)
4. **Key Rotation**: Automatic rekeying every 1000 messages or 1 hour
5. **Forward Secrecy**: Ephemeral keys destroyed after session
6. **Zero Metadata Leakage**: Encrypted headers after initial handshake

## Installation

```bash
pip install nullsec-lora-mesh
```

### Hardware Requirements

- **Flipper One** with LoRa module
- **SX1262** or **SX1276** LoRa transceiver
- Any LoRa HAT for Raspberry Pi (for gateway nodes)

## Quick Start

```python
from nullsec_lora import MeshNode, LoRaConfig

# Configure LoRa radio
config = LoRaConfig(
    frequency=915.0,        # MHz (US ISM band)
    bandwidth=125000,       # Hz
    spreading_factor=7,     # SF7-SF12
    coding_rate=5,          # 4/5
    tx_power=14,            # dBm
)

# Create a mesh node
node = MeshNode(
    node_id=0x00000001,
    config=config,
    compression="adaptive",
    encryption=True,
)

# Start the node
node.start()

# Send a message
node.send(
    dest=0x00000002,
    data=b"Hello from the mesh!",
    reliable=True,          # Request ACK
)

# Receive messages
for msg in node.receive():
    print(f"From {msg.src}: {msg.data}")
```

## Project Structure

```
nullsec-lora-mesh/
├── README.md
├── LICENSE
├── pyproject.toml
├── protocol/
│   ├── __init__.py
│   ├── frame.py         # Frame encoding/decoding
│   ├── compression.py   # LZ4/Zstd adaptive compression
│   ├── crypto.py        # ChaCha20-Poly1305 + X25519
│   ├── fec.py           # Reed-Solomon forward error correction
│   └── routing.py       # AODV mesh routing
├── transport/
│   ├── __init__.py
│   ├── fragment.py      # Message fragmentation
│   ├── reassembly.py    # Fragment reassembly
│   └── flow.py          # Flow control / congestion
├── radio/
│   ├── __init__.py
│   ├── lora.py          # LoRa radio abstraction
│   ├── sx1262.py        # SX1262 driver
│   └── flipper.py       # Flipper One integration
├── node/
│   ├── __init__.py
│   ├── mesh.py          # MeshNode main class
│   ├── neighbor.py      # Neighbor table management
│   └── config.py        # Node configuration
├── apps/
│   ├── chat.py          # Mesh chat application
│   ├── file_transfer.py # Compressed file transfer
│   └── telemetry.py     # Sensor telemetry relay
└── tests/
    ├── test_frame.py
    ├── test_compression.py
    ├── test_crypto.py
    └── test_routing.py
```

## Roadmap

- [x] Protocol specification
- [x] Frame encoding/decoding
- [x] Compression layer (LZ4/Zstd)
- [x] Encryption layer (ChaCha20-Poly1305)
- [ ] FEC (Reed-Solomon)
- [ ] AODV routing implementation
- [ ] Flipper One radio driver
- [ ] File transfer application
- [ ] Mesh chat application
- [ ] Performance benchmarks
- [ ] Hardware testing with SX1262

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**NullSec** (bad-antics) — badxantics@gmail.com
