# ADR-007: Cryptographic Memory Scrubbing and Zero-Allocation Primitives

## Status
Accepted

## Date
2026-09-04

## Context
When sensitive cryptographic material (keys, plaintexts, nonces, password derivations) is allocated on the managed GC heap, memory fragments remain resident in RAM until garbage collected and overwritten. Memory dumps, swap files, cold boot attacks, and process inspection can leak plaintext keys.

## Decision
1. **`SecretBuffer` and `CryptographicOperations.ZeroMemory`**: All ephemeral key material, derived tokens, and pooled byte arrays MUST be explicitly wiped upon disposal via `CryptographicOperations.ZeroMemory`.
2. **`ArrayPool<byte>` and `stackalloc` Usage**: Core cryptographic methods provide zero-heap-allocation overloads accepting `ReadOnlySpan<byte>` and `Span<byte>` destinations to prevent heap fragmentation.
3. **Disposal Enforcement**: Sensitive memory types (`SecretBuffer`, `Secret<T>`, `CryptographicKey`) implement `IDisposable` and throw `ObjectDisposedException` upon access after scrubbing.

## Consequences
- **Positive**: Drastically reduced memory exposure window, zero GC pressure on high-throughput cryptographic operations, defense against core dump key leakage.
- **Negative**: Callers must handle `IDisposable` or wrap operations in `using` blocks.
