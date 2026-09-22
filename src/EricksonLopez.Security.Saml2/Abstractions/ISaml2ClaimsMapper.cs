// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Abstractions;

using System.Security.Claims;
using EricksonLopez.Security.Saml2.Models;

/// <summary>
/// Defines the contract for transforming validated SAML 2.0 assertions and attributes into .NET <see cref="ClaimsPrincipal"/> objects.
/// </summary>
public interface ISaml2ClaimsMapper
{
    /// <summary>
    /// Maps a SAML 2.0 assertion into a strongly-typed <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="assertion">The validated SAML 2.0 assertion.</param>
    /// <param name="options">The SAML 2.0 options.</param>
    /// <returns>A new <see cref="ClaimsPrincipal"/> populated with standard claims.</returns>
    ClaimsPrincipal MapToPrincipal(Saml2Assertion assertion, Saml2Options options);
}
