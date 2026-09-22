// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Fakes;

using System;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides a deterministic implementation of <see cref="ICryptographicRandomNumberGenerator"/> seeded with
/// a pseudo-random generator for reproducible cryptographic tests.
/// </summary>
public sealed class DeterministicRandomNumberGenerator : ICryptographicRandomNumberGenerator
{
    private readonly Random _random;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeterministicRandomNumberGenerator"/> class with a fixed seed.
    /// </summary>
    /// <param name="seed">The deterministic random seed (defaults to 42).</param>
    public DeterministicRandomNumberGenerator(int seed = 42)
    {
        _random = new Random(seed);
    }

    /// <inheritdoc />
    public void Fill(Span<byte> destination) => _random.NextBytes(destination);

    /// <inheritdoc />
    public int GetInt32(int fromInclusive, int toExclusive) => _random.Next(fromInclusive, toExclusive);

    /// <inheritdoc />
    public byte[] GetBytes(int count)
    {
        if (count <= 0)
        {
            return [];
        }

        var buffer = new byte[count];
        _random.NextBytes(buffer);
        return buffer;
    }
}
