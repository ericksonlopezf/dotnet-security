// Copyright © Erickson Lopez. MIT License.

using FsCheck;
using FsCheck.Xunit;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Cryptography;
using System.Security.Cryptography;
using System;

namespace EricksonLopez.Security.Tests.Adversarial;

public class AdversarialPropertyTests
{
    [Property]
    public bool ConstantTimeComparer_IsSymmetric(string left, string right)
    {
        if (left == null || right == null) return true; // skip nulls
        var comparer = ConstantTimeComparer.Shared;
        var r1 = comparer.FixedTimeEquals(left.AsSpan(), right.AsSpan());
        var r2 = comparer.FixedTimeEquals(right.AsSpan(), left.AsSpan());
        return r1 == r2;
    }

    [Property]
    public bool ConstantTimeComparer_IsReflexive(string s)
    {
        if (s == null) return true; // skip nulls
        return ConstantTimeComparer.Shared.FixedTimeEquals(s.AsSpan(), s.AsSpan());
    }

    [Property]
    public bool Encryption_Roundtrip(byte[] plaintext)
    {
        if (plaintext == null) return true;

        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        var enc = engine.Encrypt(plaintext, key, nonce, ciphertext, tag);
        if (!enc.IsSuccess) return false;

        byte[] decrypted = new byte[plaintext.Length];
        var dec = engine.Decrypt(ciphertext, key, nonce, tag, default, decrypted, out int written);

        return dec.IsSuccess && written == plaintext.Length && decrypted.AsSpan().SequenceEqual(plaintext);
    }
}

