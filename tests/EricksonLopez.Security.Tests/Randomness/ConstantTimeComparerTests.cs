// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Randomness;

using System;
using EricksonLopez.Security.Randomness;
using Xunit;

public sealed class ConstantTimeComparerTests
{
    [Fact]
    public void FixedTimeEquals_Bytes_EvaluatesCorrectly()
    {
        byte[] a = [1, 2, 3, 4, 5];
        byte[] b = [1, 2, 3, 4, 5];
        byte[] c = [1, 2, 3, 4, 6];
        byte[] d = [1, 2, 3, 4];
        byte[] empty1 = [];
        byte[] empty2 = [];

        Assert.True(ConstantTimeComparer.Shared.FixedTimeEquals(a, b));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(a, c));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(a, d));
        Assert.True(ConstantTimeComparer.Shared.FixedTimeEquals(empty1, empty2));
    }

    [Fact]
    public void FixedTimeEquals_Chars_EvaluatesCorrectly()
    {
        var s1 = "api_key_secret_123456";
        var s2 = "api_key_secret_123456";
        var s3DiffEnd = "api_key_secret_123457";
        var s3DiffStart = "xpi_key_secret_123456";
        var s3DiffMid = "api_key_xxxret_123456";
        var s4Shorter = "api_key_secret_123";
        var s5Longer = "api_key_secret_123456_extra";
        var empty = "";

        Assert.True(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s2.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s3DiffEnd.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s3DiffStart.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s3DiffMid.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s4Shorter.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEquals(s1.AsSpan(), s5Longer.AsSpan()));
        Assert.True(ConstantTimeComparer.Shared.FixedTimeEquals(empty.AsSpan(), empty.AsSpan()));
    }

    [Fact]
    public void Equals_Strings_HandlesNullsAndValuesCorrectly()
    {
        Assert.True(ConstantTimeComparer.Equals((string?)null, (string?)null));
        Assert.False(ConstantTimeComparer.Equals("secret", null));
        Assert.False(ConstantTimeComparer.Equals(null, "secret"));
        Assert.False(ConstantTimeComparer.Equals("", null));
        Assert.False(ConstantTimeComparer.Equals(null, ""));
        Assert.True(ConstantTimeComparer.Equals("token123", "token123"));
        Assert.False(ConstantTimeComparer.Equals("token123", "token124"));
        Assert.False(ConstantTimeComparer.Equals("token123", "token12"));
        Assert.True(ConstantTimeComparer.Equals("", ""));
    }

    [Fact]
    public void FixedTimeEqualsSecure_Chars_EvaluatesCorrectly()
    {
        var s1 = "api_key_secret_123456";
        var s2 = "api_key_secret_123456";
        var s3Diff = "api_key_secret_123457";
        var s4Shorter = "api_key_secret_123";
        var s5Longer = "api_key_secret_123456_extra";
        var empty = "";

        Assert.True(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(s1.AsSpan(), s2.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(s1.AsSpan(), s3Diff.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(s1.AsSpan(), s4Shorter.AsSpan()));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(s1.AsSpan(), s5Longer.AsSpan()));
        Assert.True(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(empty.AsSpan(), empty.AsSpan()));
    }

    [Fact]
    public void FixedTimeEqualsSecure_Bytes_EvaluatesCorrectly()
    {
        byte[] a = [1, 2, 3, 4, 5];
        byte[] b = [1, 2, 3, 4, 5];
        byte[] c = [1, 2, 3, 4, 6];
        byte[] d = [1, 2, 3, 4];
        byte[] empty1 = [];
        byte[] empty2 = [];

        Assert.True(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(a, b));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(a, c));
        Assert.False(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(a, d));
        Assert.True(ConstantTimeComparer.Shared.FixedTimeEqualsSecure(empty1, empty2));
    }
}
