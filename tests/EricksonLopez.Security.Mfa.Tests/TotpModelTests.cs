// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using AwesomeAssertions;
using Xunit;

public sealed class TotpModelTests
{
    [Fact]
    public void TotpOptions_Defaults_AreConfiguredProperly()
    {
        var options = new TotpOptions();

        options.Digits.Should().Be(6);
        options.PeriodSeconds.Should().Be(30);
        options.Algorithm.Should().Be(TotpHashAlgorithm.Sha1);
        options.AllowedDriftSteps.Should().Be(1);

        options.Digits = 8;
        options.PeriodSeconds = 60;
        options.Algorithm = TotpHashAlgorithm.Sha512;
        options.AllowedDriftSteps = 2;

        options.Digits.Should().Be(8);
        options.PeriodSeconds.Should().Be(60);
        options.Algorithm.Should().Be(TotpHashAlgorithm.Sha512);
        options.AllowedDriftSteps.Should().Be(2);
    }

    [Fact]
    public void TotpHashAlgorithm_EnumValues_MatchExpected()
    {
        ((int)TotpHashAlgorithm.Sha1).Should().Be(0);
        ((int)TotpHashAlgorithm.Sha256).Should().Be(1);
        ((int)TotpHashAlgorithm.Sha512).Should().Be(2);
    }

    [Fact]
    public void TotpSetupInfo_RecordProperties_Work()
    {
        var info1 = new TotpSetupInfo("SECRET", "SEC RET", "otpauth://totp/URI");
        var info2 = new TotpSetupInfo("SECRET", "SEC RET", "otpauth://totp/URI");
        var info3 = info1 with { SecretKey = "OTHER" };

        info1.SecretKey.Should().Be("SECRET");
        info1.FormattedSecretKey.Should().Be("SEC RET");
        info1.AuthenticatorUri.Should().Be("otpauth://totp/URI");

        info1.Should().Be(info2);
        info1.Should().NotBe(info3);
        info1.ToString().Should().NotBeNullOrWhiteSpace();
    }
}
