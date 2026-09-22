// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa;

using System;

/// <summary>
/// Defines a contract for generating cryptographically secure emergency recovery backup codes.
/// </summary>
public interface IRecoveryCodeGenerator
{
    /// <summary>
    /// Generates a collection of unique, formatted recovery codes.
    /// </summary>
    /// <param name="count">The number of recovery codes to generate, defaulting to 10</param>
    /// <param name="codeLength">The length of each code before formatting, defaulting to 10</param>
    /// <returns>An array of formatted recovery codes.</returns>
    string[] GenerateCodes(int count = 10, int codeLength = 10);
}
