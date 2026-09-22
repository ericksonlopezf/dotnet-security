# ADR-006: Side-Channel Resistant Constant-Time Comparisons

## Status
Accepted

## Date
2026-09-04

## Context
Standard equality checks (`string.Equals`, `==`, `SequenceEqual`) optimize performance via early-exit branch evaluation on the first mismatched byte or character. When evaluating passwords, authentication tags, HMACs, session tokens, or API keys, early-exit branches leak timing measurements that allow attackers to iteratively reconstruct secret values byte-by-byte (timing side-channel attacks).

## Decision
1. **Mandatory Constant-Time Comparison**: All comparisons of secret cryptographic tokens, digests, HMACs, and auth tags MUST use `CryptographicOperations.FixedTimeEquals`.
2. **`IConstantTimeComparer` Port**: Expose side-channel safe comparison contracts in `Abstractions` implemented in Core.
3. **`TimingSafeString` Value Type**: Provide a strongly typed immutable string wrapper that overrides `Equals`, `operator ==`, and `operator !=` to execute constant-time comparisons without early branch termination.

## Consequences
- **Positive**: Eliminates remote and local timing side-channel attacks across token and credential verification pipelines.
- **Negative**: Minor CPU execution constant time overhead relative to naive short-circuiting comparisons, which is required and acceptable for security primitives.
