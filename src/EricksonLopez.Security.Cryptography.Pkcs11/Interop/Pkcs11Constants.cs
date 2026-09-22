// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Interop;

using System;

/// <summary>
/// Defines constants and return values specified by the PKCS#11 standard (Cryptoki).
/// </summary>
public static class Pkcs11Constants
{
    /// <summary>
    /// Indicates successful execution of a PKCS#11 function (<c>CKR_OK</c>).
    /// </summary>
    public const uint CKR_OK = 0x00000000;

    /// <summary>
    /// Indicates that the specified session handle was invalid or closed (<c>CKR_SESSION_HANDLE_INVALID</c>).
    /// </summary>
    public const uint CKR_SESSION_HANDLE_INVALID = 0x000000B3;

    /// <summary>
    /// Indicates that the signature is invalid (<c>CKR_SIGNATURE_INVALID</c>).
    /// </summary>
    public const uint CKR_SIGNATURE_INVALID = 0x000000C0;

    /// <summary>
    /// Specifies that the session is a serial session (<c>CKF_SERIAL_SESSION</c>). Required for all Cryptoki applications.
    /// </summary>
    public const uint CKF_SERIAL_SESSION = 0x00000004;

    /// <summary>
    /// Specifies that the session is read/write (<c>CKF_RW_SESSION</c>).
    /// </summary>
    public const uint CKF_RW_SESSION = 0x00000002;

    /// <summary>
    /// Specifies a read-only public session state (<c>CKS_RO_PUBLIC_SESSION</c>).
    /// </summary>
    public const uint CKS_RO_PUBLIC_SESSION = 0;

    /// <summary>
    /// Specifies a read-only user functions session state (<c>CKS_RO_USER_FUNCTIONS</c>).
    /// </summary>
    public const uint CKS_RO_USER_FUNCTIONS = 1;

    /// <summary>
    /// Specifies a read/write public session state (<c>CKS_RW_PUBLIC_SESSION</c>).
    /// </summary>
    public const uint CKS_RW_PUBLIC_SESSION = 2;

    /// <summary>
    /// Specifies a read/write user functions session state (<c>CKS_RW_USER_FUNCTIONS</c>).
    /// </summary>
    public const uint CKS_RW_USER_FUNCTIONS = 3;

    /// <summary>
    /// Specifies the Security Officer user type (<c>CKU_SO</c>).
    /// </summary>
    public const uint CKU_SO = 0;

    /// <summary>
    /// Specifies the normal application user type (<c>CKU_USER</c>).
    /// </summary>
    public const uint CKU_USER = 1;

    // Mechanism types

    /// <summary>
    /// Specifies the RSA PKCS #1 v1.5 mechanism type (<c>CKM_RSA_PKCS</c>).
    /// </summary>
    public const uint CKM_RSA_PKCS = 0x00000001;

    /// <summary>
    /// Specifies the SHA-256 with RSA PKCS #1 v1.5 signature mechanism (<c>CKM_SHA256_RSA_PKCS</c>).
    /// </summary>
    public const uint CKM_SHA256_RSA_PKCS = 0x00000040;

    /// <summary>
    /// Specifies the Elliptic Curve Digital Signature Algorithm mechanism (<c>CKM_ECDSA</c>).
    /// </summary>
    public const uint CKM_ECDSA = 0x00001041;
}
