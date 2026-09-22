// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust.Tests;

using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Xunit;

public sealed class AbacContextTests
{
    [Fact]
    public void Context_FluentSetters_StoreAndRetrieveAttributes()
    {
        string[] roles = ["Admin", "Auditor"];
        var context = new AbacContext()
            .WithSubject("UserId", "user-123")
            .WithSubject("Roles", roles)
            .WithResource("DocumentId", "doc-456")
            .WithResource("Department", "Finance")
            .WithAction("Approve")
            .WithEnvironment("IpAddress", "192.168.1.100")
            .WithEnvironment("IsSecure", true);

        context.Get<string>(AbacAttributeCategory.Subject, "UserId").Should().Be("user-123");
        context.Get<string[]>(AbacAttributeCategory.Subject, "Roles").Should().Contain("Admin");
        context.Get<string>(AbacAttributeCategory.Resource, "Department").Should().Be("Finance");
        context.Get<string>(AbacAttributeCategory.Action, "Name").Should().Be("Approve");
        context.Get<string>(AbacAttributeCategory.Environment, "IpAddress").Should().Be("192.168.1.100");
        context.Get<bool>(AbacAttributeCategory.Environment, "IsSecure").Should().BeTrue();

        context.Has(AbacAttributeCategory.Subject, "UserId").Should().BeTrue();
        context.Has(AbacAttributeCategory.Subject, "NonExistent").Should().BeFalse();
    }

    [Fact]
    public void Set_NullArguments_ThrowsArgumentNullException()
    {
        var context = new AbacContext();

        Assert.Throws<ArgumentNullException>(() => context.Set(null!, "Name", "Val"));
        Assert.Throws<ArgumentNullException>(() => context.Set("Category", null!, "Val"));
        Assert.Throws<ArgumentNullException>(() => context.Set("Category", "Name", null!));
    }

    [Fact]
    public void TryGet_ExistingAttribute_ReturnsTrueAndValue()
    {
        var context = new AbacContext().WithSubject("Clearance", 3);

        var exists = context.TryGet<int>(AbacAttributeCategory.Subject, "Clearance", out var clearance);

        exists.Should().BeTrue();
        clearance.Should().Be(3);

        // Mismatched type
        var wrongType = context.TryGet<string>(AbacAttributeCategory.Subject, "Clearance", out var strClearance);
        wrongType.Should().BeFalse();
        strClearance.Should().BeNull();

        // Non-existent
        var notFound = context.TryGet<int>(AbacAttributeCategory.Subject, "Missing", out var missing);
        notFound.Should().BeFalse();
        missing.Should().Be(0);

        // Null arguments
        Assert.Throws<ArgumentNullException>(() => context.TryGet<int>(null!, "Clearance", out _));
        Assert.Throws<ArgumentNullException>(() => context.TryGet<int>("Subject", null!, out _));
    }

    [Fact]
    public void Get_MissingAttribute_ThrowsKeyNotFoundException()
    {
        var context = new AbacContext().WithSubject("Clearance", 3);

        var act1 = () => context.Get<string>(AbacAttributeCategory.Subject, "NonExistent");
        act1.Should().Throw<KeyNotFoundException>()
            .WithMessage("ABAC attribute 'Subject.NonExistent' of type String was not found in the context.");

        // Value type non-existent
        var actValueType = () => context.Get<int>(AbacAttributeCategory.Subject, "NonExistent");
        actValueType.Should().Throw<KeyNotFoundException>()
            .WithMessage("ABAC attribute 'Subject.NonExistent' of type Int32 was not found in the context.");

        // Incompatible type
        var act2 = () => context.Get<string>(AbacAttributeCategory.Subject, "Clearance");
        act2.Should().Throw<KeyNotFoundException>()
            .WithMessage("ABAC attribute 'Subject.Clearance' of type String was not found in the context.");
    }
}
