# ADR-003: Compact Binary Security Envelope Format

## Status
Accepted

## Date
2026-09-04

## Context
Storing encrypted payloads in persistence layers requires embedding cryptographic metadata (format version, algorithm ID, key identifier, key version, nonce, and authentication tag) alongside the ciphertext. Using JSON or XML introduces unnecessary CPU overhead, GC pressure, serialization schema drift, and string allocation overhead.

## Decision
We define a compact, deterministic binary serialization format for `SecurityEnvelope`:
- **Byte 0**: Format Version (1 byte, `0x01`)
- **Byte 1**: Algorithm Identifier (1 byte, e.g. `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305)
- **Bytes 2-3**: KeyIdentifier UTF-8 byte length (uint16, little-endian)
- **Next N bytes**: KeyIdentifier UTF-8 payload
- **Next 4 bytes**: KeyVersion (int32, little-endian)
- **Next 12 bytes**: Nonce / IV (96 bits)
- **Next 16 bytes**: Authentication Tag (128 bits)
- **Next 4 bytes**: Associated Data byte length (int32, little-endian)
- **Next M bytes**: Associated Data bytes (if length > 0)
- **Next 4 bytes**: Ciphertext byte length (int32, little-endian)
- **Remaining bytes**: Ciphertext payload

## Consequences
- **Positive**: Strict byte-level validation, zero string-reflection, minimal size footprint, Native AOT trimming safety, fast serialization into pre-allocated spans.
- **Negative**: Binary envelopes are not human-readable without hex/base64 formatting.
