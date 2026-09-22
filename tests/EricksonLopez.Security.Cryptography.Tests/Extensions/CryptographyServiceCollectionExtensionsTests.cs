// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Tests.Extensions;

using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Cryptography.Encryption;
using EricksonLopez.Security.Cryptography.Passwords;
using EricksonLopez.Security.Cryptography.Randomness;
using AwesomeAssertions;
using Xunit;

public sealed class CryptographyServiceCollectionExtensionsTests
{
    [Fact]
    public void AddEricksonLopezCryptographyCore_RegistersAllExpectedSingletons()
    {
        var services = new ServiceCollection();

        var returned = services.AddEricksonLopezCryptographyCore();
        returned.Should().BeSameAs(services);

        using var provider = services.BuildServiceProvider();

        var rng = provider.GetService<ICryptographicRandomNumberGenerator>();
        var comparer = provider.GetService<IConstantTimeComparer>();
        var engine = provider.GetService<IAuthenticatedEncryptionEngine>();
        var hasher = provider.GetService<IPasswordHasher>();

        rng.Should().NotBeNull().And.BeOfType<CryptographicRandomNumberGenerator>();
        comparer.Should().NotBeNull().And.BeOfType<ConstantTimeComparer>();
        engine.Should().NotBeNull().And.BeOfType<AesGcmAuthenticatedEncryptionEngine>();
        hasher.Should().NotBeNull().And.BeOfType<Pbkdf2PasswordHasher>();
    }
}
