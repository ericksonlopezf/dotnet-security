// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Claims;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.Models;

/// <summary>
/// Maps SAML 2.0 assertion attributes and NameID into standard .NET <see cref="ClaimsPrincipal"/> instances.
/// </summary>
public sealed class Saml2ClaimsMapper : ISaml2ClaimsMapper
{
    private static readonly Dictionary<string, string> StandardClaimMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        { "email", ClaimTypes.Email },
        { "mail", ClaimTypes.Email },
        { "emailaddress", ClaimTypes.Email },
        { "name", ClaimTypes.Name },
        { "displayname", ClaimTypes.Name },
        { "givenname", ClaimTypes.GivenName },
        { "surname", ClaimTypes.Surname },
        { "sn", ClaimTypes.Surname },
        { "role", ClaimTypes.Role },
        { "roles", ClaimTypes.Role },
        { "upn", ClaimTypes.Upn }
    };

    /// <inheritdoc />
    public ClaimsPrincipal MapToPrincipal(Saml2Assertion assertion, Saml2Options options)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(options);

        var claims = new List<Claim>();

        // 1. Map NameID
        var nameIdClaimType = options.NameIdClaimType;
        claims.Add(new Claim(nameIdClaimType, assertion.Subject.NameId.Value, ClaimValueTypes.String, assertion.Issuer));

        // 2. Map Authentication Instant and Session Index
        if (assertion.AuthnStatement is not null)
        {
            claims.Add(new Claim(ClaimTypes.AuthenticationInstant, assertion.AuthnStatement.AuthnInstant.ToString("o"), ClaimValueTypes.DateTime, assertion.Issuer));
            if (!string.IsNullOrEmpty(assertion.AuthnStatement.SessionIndex))
            {
                claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/sessionindex", assertion.AuthnStatement.SessionIndex, ClaimValueTypes.String, assertion.Issuer));
            }
        }

        // 3. Map Attributes
        foreach (var attr in assertion.Attributes)
        {
            var targetClaimType = StandardClaimMappings.TryGetValue(attr.Name, out var mappedType)
                ? mappedType
                : attr.Name;

            foreach (var val in attr.Values)
            {
                claims.Add(new Claim(targetClaimType, val, ClaimValueTypes.String, assertion.Issuer));
            }
        }

        var identity = new ClaimsIdentity(claims, "SAML2", ClaimTypes.Name, ClaimTypes.Role);
        return new ClaimsPrincipal(identity);
    }
}
