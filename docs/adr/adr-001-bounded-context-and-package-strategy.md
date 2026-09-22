# ADR-001: Bounded Context, Responsibilities, and Package Segregation

## Status
Accepted

## Date
2026-09-04

## Context
Enterprise .NET systems frequently blur the lines between security primitives, authentication, authorization, IAM servers, and cloud key vaults. Monolithic security libraries often couple core domain logic to web frameworks (e.g. `Microsoft.AspNetCore.Identity`), cloud SDKs (`Azure.Security.KeyVault.Secrets`), or specific ORMs.

## Decision
1. **Strict Bounded Context**: `EricksonLopez.Security` is strictly a foundational Tier-1 library for **security primitives, authenticated cryptographic envelopes, multi-version key lifecycle management, password hashing abstractions, token security, and secrets protection**.
2. **Explicit Non-Goals**: The core package explicitly rejects becoming an Identity Provider (IdP), OAuth/OpenID server, ASP.NET Identity clone, or proprietary crypto algorithm implementer.
3. **Package Separation**:
   - `EricksonLopez.Security.Abstractions`: Zero-dependency ports, interfaces, immutable value types, and domain error definitions.
   - `EricksonLopez.Security`: High-performance core implementation, Native AOT ready, zero reflection.
   - `EricksonLopez.Security.AspNetCore`: Optional satellite adapter for HTTP security headers and middleware.
   - `EricksonLopez.Security.Testing`: Test doubles and assertion kit for fast unit testing.

## Consequences
- **Positive**: Zero coupling to web or cloud frameworks in core; maximum portability, 100% Native AOT trimming safety, low memory overhead.
- **Negative**: Applications requiring cloud KMS or specialized HSMs must register adapter implementations of `IKeyStore` or `ISecretStore`.
- **Evolution**: See [ADR-017: Satellite Repository Strategy](./adr-017-satellite-repository-strategy.md) for the architecture scaling model governing satellite package growth (expanding from the initial 4 packages to 21 specialized satellites).
