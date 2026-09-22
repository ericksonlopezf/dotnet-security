# ADR-018: SSRF Prevention Architecture

## Status
Accepted

## Date
2026-08-30

**Date**: 2026-08-30  
**Status**: Accepted  
**Context**: Ecosystem-Wide Security

## Context
Applications like `OpusHydra` send outward HTTP requests via Webhooks. Without proper validation, these outgoing HTTP requests can be manipulated into Server-Side Request Forgery (SSRF) attacks. An attacker could use a Webhook delivery to scan internal networks, reach RFC 1918 private IP addresses (e.g., `10.x.x.x`), query loopback interfaces (`127.0.0.1`), or access cloud provider metadata endpoints (e.g., `169.254.169.254`).

Furthermore, DNS rebinding attacks can bypass naive URL validations by resolving a safe IP initially, then returning a malicious private IP during the actual connection phase.

## Decision
We establish **EricksonLopez.Security.Network** as a Tier 0 security package. Any outgoing HTTP client that connects to arbitrary, user-defined endpoints MUST be routed through `SafeSocketsHttpHandler`.

`SafeSocketsHttpHandler` guarantees:
1. **DNS Resolution Interception**: It overrides the default `SocketsHttpHandler.ConnectCallback`.
2. **Safe IP Verification**: Resolved IP addresses are checked against `IpAddressRange` blocklists (RFC 1918, metadata, loopback) via `SafeDnsResolver`.
3. **DNS Rebinding Prevention**: It binds the physical `Socket` directly to the validated IP address, preventing the OS from performing a secondary (potentially malicious) DNS lookup.

## Consequences
- **Positive**: Strict, non-bypassable SSRF protection at the socket layer.
- **Negative**: Adds minor overhead for manual DNS resolution on every connection. Can block legitimate internal webhooks if the environment legitimately uses private IP ranges (requires explicit whitelist configuration in `SsrfProtectionOptions` if needed).
