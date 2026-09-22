// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Tests.Signing;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using Xunit;

public sealed class Pkcs11NativeLibraryTests
{
    [Fact]
    public void Constructor_WithInvalidPath_ThrowsDllNotFoundException()
    {
        var invalidPath = "non_existent_pkcs11_driver_12345.dll";

        Action act = () => _ = new Pkcs11NativeLibrary(invalidPath);

        act.Should().Throw<DllNotFoundException>()
           .WithMessage($"*non_existent_pkcs11_driver_12345.dll*");
    }

    [Fact]
    public void Constructor_WithDllMissingExports_ThrowsEntryPointNotFoundException()
    {
        // kernel32.dll exists on all Windows machines but does not export PKCS#11 functions like C_Initialize
        if (OperatingSystem.IsWindows())
        {
            Action act = () => _ = new Pkcs11NativeLibrary("kernel32.dll");

            act.Should().Throw<EntryPointNotFoundException>()
               .WithMessage("*does not export the required function 'C_Initialize'*");
        }
    }
}
