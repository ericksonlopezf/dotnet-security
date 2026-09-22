// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;

/// <summary>
/// Provides access to FIDO Alliance Metadata Service v3 (MDS3) authenticator entries.
/// </summary>
/// <remarks>
/// Implementations MUST cache the MDS3 blob and refresh it periodically (typically once per day,
/// or whenever the `nextUpdate` field in the JWT payload has been reached).
/// </remarks>
public interface IMds3MetadataService
{
    /// <summary>
    /// Retrieves the metadata for an authenticator by its AAGUID.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator to look up.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the
    /// <see cref="AuthenticatorMetadata"/> if found; otherwise, a failure result.
    /// </returns>
    Task<Result<AuthenticatorMetadata>> GetMetadataAsync(Guid aaguid, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether an authenticator with the given AAGUID is considered trustworthy
    /// based on its current status reports.
    /// </summary>
    /// <param name="aaguid">The AAGUID to evaluate.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result"/>
    /// indicating whether the authenticator is trustworthy.
    /// </returns>
    Task<Result> ValidateAuthenticatorStatusAsync(Guid aaguid, CancellationToken cancellationToken = default);

    /// <summary>
    /// Forces a refresh of the MDS3 blob from the FIDO Alliance endpoint, regardless of the current cache state.
    /// Useful for background refresh jobs or testing.
    /// </summary>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RefreshAsync(CancellationToken cancellationToken = default);
}
