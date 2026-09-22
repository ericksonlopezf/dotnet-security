// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Randomness;

using System;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Testing.Assertions;
using Xunit;

public sealed class TimingSafeStringTests
{
    [Fact]
    public void TimingSafeString_Properties_And_Constructors_WorkCorrectly()
    {
        TimingSafeString sNull = new((string?)null);
        TimingSafeString sEmpty = new("");
        TimingSafeString sVal = new("my-token-123");
        TimingSafeString sImplicit = "implicit-token";

        Assert.Equal(0, sNull.Length);
        Assert.True(sNull.IsEmpty);
        Assert.True(sNull.AsSpan().IsEmpty);
        Assert.Equal(0, sNull.GetHashCode());

        Assert.Equal(0, sEmpty.Length);
        Assert.True(sEmpty.IsEmpty);
        Assert.True(sEmpty.AsSpan().IsEmpty);
        Assert.Equal(string.Empty.GetHashCode(StringComparison.Ordinal), sEmpty.GetHashCode());

        Assert.Equal(12, sVal.Length);
        Assert.False(sVal.IsEmpty);
        Assert.Equal(12, sVal.AsSpan().Length);
        Assert.Equal(string.GetHashCode("my-token-123", StringComparison.Ordinal), sVal.GetHashCode());

        Assert.Equal(14, sImplicit.Length);
        Assert.False(sImplicit.IsEmpty);

        Assert.Equal("[REDACTED TIMING-SAFE STRING]", sVal.ToString());
        SecurityAssert.IsRedacted(sVal);
    }

    [Fact]
    public void TimingSafeString_EqualityAndOperators_CoverAllBranches()
    {
        TimingSafeString s1 = "sensitive-hash-value-1";
        TimingSafeString s2 = "sensitive-hash-value-1";
        TimingSafeString s3 = "sensitive-hash-value-2";
        TimingSafeString sNull1 = new((string?)null);
        TimingSafeString sNull2 = new((string?)null);

        // Same content
        Assert.True(s1 == s2);
        Assert.False(s1 != s2);
        Assert.True(s1.Equals(s2));
        Assert.True(s1.Equals((object)s2));

        // Different content
        Assert.False(s1 == s3);
        Assert.True(s1 != s3);
        Assert.False(s1.Equals(s3));
        Assert.False(s1.Equals((object)s3));

        // Null comparisons
        Assert.True(sNull1 == sNull2);
        Assert.False(sNull1 != sNull2);
        Assert.True(sNull1.Equals(sNull2));

        Assert.False(s1 == sNull1);
        Assert.True(s1 != sNull1);
        Assert.False(s1.Equals(sNull1));

        // Object equality
        Assert.False(s1.Equals((object?)null));
        Assert.False(s1.Equals("plain-string"));
        Assert.False(s1.Equals(12345));
    }
}
