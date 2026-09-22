// Copyright © Erickson Lopez. MIT License.

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 0: Conceptual Foundations & Architectural Invariants.
/// Explains the core security design principles, threat models, memory safety,
/// and value objects implemented across the EricksonLopez.Security ecosystem.
/// </summary>
public static class Level0_Conceptual
{
    public static void Run()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 0: CONCEPTUAL FOUNDATIONS & ARCHITECTURAL INVARIANTS");
        Console.WriteLine("================================================================================");

        Console.WriteLine("\n[1] Architectural Mission & Security Invariants:");
        Console.WriteLine("  • Misuse-Resistance: Impossible to encrypt with weak defaults (AES-256-GCM / ChaCha20-Poly1305 mandatory).");
        Console.WriteLine("  • Memory Safety: Ephemeral key buffers and secrets wiped via CryptographicOperations.ZeroMemory.");
        Console.WriteLine("  • Native AOT Ready: Zero runtime code generation, zero reflection in hot cryptographic paths.");
        Console.WriteLine("  • Pure Clean Architecture: Abstractions layer has 0 external dependencies besides EricksonLopez.Result.");
        Console.WriteLine("  • Post-Quantum & Hybrid Ready: Pre-integrated ML-KEM/Kyber envelope support.");

        Console.WriteLine("\n[2] Foundational Value Objects & Type Safety:");

        // 1. KeyIdentifier & KeyVersion
        var keyId = KeyIdentifier.New();
        var keyVersion = KeyVersion.Initial;
        Console.WriteLine($"  -> KeyIdentifier: {keyId.Value} (Length: {keyId.Value.Length} chars)");
        Console.WriteLine($"  -> KeyVersion: {keyVersion.Value} (Next: {keyVersion.Next().Value})");

        // 2. Redacted<T> - Zero Accidental Log Leakage
        var sensitivePii = new Redacted<string>("SuperSecretSSN_987-65-4321");
        Console.WriteLine($"  -> Redacted<T>.ToString() output: '{sensitivePii}' (Safe for structured logging)");
        Console.WriteLine($"  -> Redacted<T>.UnsafeValue (Authorized access only): '{sensitivePii.UnsafeValue}'");

        // 3. High-Entropy Cryptographic Primitives
        var nonce = new Nonce(RandomNumberGenerator.GetBytes(12));
        var salt = new Salt(RandomNumberGenerator.GetBytes(16));
        var securityStamp = SecurityStamp.New();

        Console.WriteLine($"  -> Nonce (12-byte GCM IV): {Convert.ToHexString(nonce.Span)}");
        Console.WriteLine($"  -> Salt (16-byte KDF Salt): {Convert.ToHexString(salt.Span)}");
        Console.WriteLine($"  -> SecurityStamp (State Invalidation): {securityStamp.Value}");

        Console.WriteLine("\n[3] Comparison with Alternative Solutions:");
        Console.WriteLine("  • vs. Microsoft.AspNetCore.DataProtection: Native AOT compatible, explicit key lifecycle, structured envelopes.");
        Console.WriteLine("  • vs. BCrypt.Net: Modern memory-hard Argon2id default, configurable work factors, zero unmanaged memory leaks.");
        Console.WriteLine("  • vs. Sustainsys.Saml2: Native XSW (XML Signature Wrapping) defense engine, strict schema validation.");
        Console.WriteLine("  • vs. Fido2NetLib: Allocation-conscious WebAuthn L3 ceremony engine with zero binary serialization overhead.");
        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
