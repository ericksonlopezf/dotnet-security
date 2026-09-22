// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Identity;

using System;
using Microsoft.AspNetCore.Identity;
using ElPasswordHasher = EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher;
using ElPasswordVerificationResult = EricksonLopez.Security.Abstractions.Passwords.PasswordVerificationResult;

/// <summary>
/// Bridges ASP.NET Core Identity's <see cref="IPasswordHasher{TUser}"/> to the canonical
/// <see cref="ElPasswordHasher"/> from EricksonLopez.Security, enabling zero-downtime, transparent password migration.
/// </summary>
/// <typeparam name="TUser">The user entity type.</typeparam>
public sealed class IdentityPasswordHasherBridge<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly ElPasswordHasher _hasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityPasswordHasherBridge{TUser}"/> class.
    /// </summary>
    /// <param name="hasher">The underlying EricksonLopez.Security password hasher.</param>
    /// <exception cref="ArgumentNullException"><paramref name="hasher"/> is <see langword="null"/></exception>
    public IdentityPasswordHasherBridge(ElPasswordHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        _hasher = hasher;
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return _hasher.HashPassword(password.AsSpan());
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(providedPassword))
        {
            return PasswordVerificationResult.Failed;
        }

        var result = _hasher.VerifyPassword(providedPassword.AsSpan(), hashedPassword);
        return result switch
        {
            ElPasswordVerificationResult.Success => PasswordVerificationResult.Success,
            ElPasswordVerificationResult.SuccessRehashNeeded => PasswordVerificationResult.SuccessRehashNeeded,
            _ => PasswordVerificationResult.Failed
        };
    }
}
