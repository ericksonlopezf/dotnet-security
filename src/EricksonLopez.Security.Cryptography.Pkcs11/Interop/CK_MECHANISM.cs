// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Interop;

using System;

/// <summary>
/// Represents a PKCS#11 mechanism structure (<c>CK_MECHANISM</c>) specifying a cryptographic operation and parameters.
/// </summary>
public struct CK_MECHANISM
{
    /// <summary>
    /// Gets or sets the mechanism type identifier.
    /// </summary>
    public uint mechanism;

    /// <summary>
    /// Gets or sets a pointer to parameter data required by the mechanism, or <see cref="IntPtr.Zero"/> if none.
    /// </summary>
    public IntPtr pParameter;

    /// <summary>
    /// Gets or sets the length in bytes of the parameter data pointed to by <see cref="pParameter"/>.
    /// </summary>
    public uint ulParameterLen;
}
