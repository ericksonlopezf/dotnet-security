// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Pki;

/// <summary>
/// Provides X.509 certificate chain validation and revocation verification using <see cref="X509Chain"/>.
/// </summary>
public sealed class CertificateChainValidator : ICertificateChainValidator
{
    /// <inheritdoc />
    public Result<bool> ValidateCertificate(X509Certificate2 certificate, CertificateValidationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var opt = options ?? new CertificateValidationOptions();

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = opt.RevocationMode;
        chain.ChainPolicy.RevocationFlag = opt.RevocationFlag;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (opt.CustomTrustAnchors.Count != 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var anchor in opt.CustomTrustAnchors)
            {
                chain.ChainPolicy.CustomTrustStore.Add(anchor);
            }
        }

        var isChainValid = chain.Build(certificate);
        if (!isChainValid)
        {
            var errors = new List<string>();
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.NoError)
                {
                    errors.Add(FormatChainStatus(status));
                }
            }

            return Error.Unauthorized(
                "Pki.CertificateChainInvalid",
                $"X.509 certificate chain validation failed: {string.Join("; ", errors)}");
        }

        if (!string.IsNullOrWhiteSpace(opt.ExpectedHostName))
        {
            if (!certificate.MatchesHostname(opt.ExpectedHostName))
            {
                return Error.Unauthorized(
                    "Pki.CertificateHostnameMismatch",
                    $"The certificate does not match the expected hostname '{opt.ExpectedHostName}'.");
            }
        }

        if (!string.IsNullOrWhiteSpace(opt.RequiredExtendedKeyUsageOid))
        {
            bool hasMatchingEku = false;
            foreach (var extension in certificate.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension ekuExtension)
                {
                    foreach (var oid in ekuExtension.EnhancedKeyUsages)
                    {
                        if (string.Equals(oid.Value, opt.RequiredExtendedKeyUsageOid, StringComparison.Ordinal))
                        {
                            hasMatchingEku = true;
                            break;
                        }
                    }
                }
            }

            if (!hasMatchingEku)
            {
                return Error.Unauthorized(
                    "Pki.CertificateEkuMismatch",
                    $"The certificate is missing the required Extended Key Usage (EKU) with OID '{opt.RequiredExtendedKeyUsageOid}'.");
            }
        }

        return Result<bool>.Success(true);
    }

    private static string FormatChainStatus(in X509ChainStatus status) =>
        $"{status.Status}: {status.StatusInformation}";
}
