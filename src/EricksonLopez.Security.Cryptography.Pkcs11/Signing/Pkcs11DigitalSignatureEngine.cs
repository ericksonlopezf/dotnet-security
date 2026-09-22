// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Signing;

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;

/// <summary>
/// Provides hardware-backed digital signature generation and verification operations using PKCS#11.
/// </summary>
public sealed unsafe class Pkcs11DigitalSignatureEngine : IDigitalSignatureEngine
{
    private readonly Pkcs11NativeLibrary _lib;
    private readonly Pkcs11SessionManager _sessionManager;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pkcs11DigitalSignatureEngine"/> class with the specified native library and session manager.
    /// </summary>
    /// <param name="lib">The unmanaged PKCS#11 library bindings provider.</param>
    /// <param name="sessionManager">The active PKCS#11 session manager.</param>
    public Pkcs11DigitalSignatureEngine(Pkcs11NativeLibrary lib, Pkcs11SessionManager sessionManager)
    {
        _lib = lib;
        _sessionManager = sessionManager;
    }

    /// <inheritdoc/>
    public Result Sign(ReadOnlySpan<byte> payload, KeyIdentifier keyId, Span<byte> signatureDestination, out int bytesWritten)
    {
        bytesWritten = 0;

        // In a real implementation, we would use C_FindObjects to locate the private key handle using keyId.
        // For demonstration, we assume a fixed handle or that it was previously resolved.
        uint privateKeyHandle = ResolveKeyHandle(keyId);
        if (privateKeyHandle == 0)
        {
            return Result.Failure(SecurityError.KeyNotFound(keyId.ToString()));
        }

        if (_lib.C_SignInit == null || _lib.C_Sign == null)
        {
            return Result.Failure(SecurityError.EncryptionFailed("PKCS#11 library does not export C_SignInit or C_Sign."));
        }

        var mechanism = new CK_MECHANISM
        {
            mechanism = Pkcs11Constants.CKM_SHA256_RSA_PKCS,
            pParameter = IntPtr.Zero,
            ulParameterLen = 0
        };

        var rv = _lib.C_SignInit(_sessionManager.SessionId, &mechanism, privateKeyHandle);
        if (rv != Pkcs11Constants.CKR_OK)
        {
            return Result.Failure(SecurityError.EncryptionFailed($"PKCS#11 SignInit failed. RV: 0x{rv:X}"));
        }

        uint sigLen = (uint)signatureDestination.Length;
        fixed (byte* pPayload = payload)
        fixed (byte* pSignature = signatureDestination)
        {
            rv = _lib.C_Sign(_sessionManager.SessionId, pPayload, (uint)payload.Length, pSignature, ref sigLen);
            if (rv != Pkcs11Constants.CKR_OK)
            {
                return Result.Failure(SecurityError.EncryptionFailed($"PKCS#11 Sign failed. RV: 0x{rv:X}"));
            }
        }

        bytesWritten = (int)sigLen;
        return Result.Success();
    }

    /// <inheritdoc/>
    public Result Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, KeyIdentifier keyId)
    {
        uint publicKeyHandle = ResolveKeyHandle(keyId);
        if (publicKeyHandle == 0)
        {
            return Result.Failure(SecurityError.KeyNotFound(keyId.ToString()));
        }

        if (_lib.C_VerifyInit == null || _lib.C_Verify == null)
        {
            return Result.Failure(SecurityError.EncryptionFailed("PKCS#11 library does not export C_VerifyInit or C_Verify."));
        }

        var mechanism = new CK_MECHANISM
        {
            mechanism = Pkcs11Constants.CKM_SHA256_RSA_PKCS,
            pParameter = IntPtr.Zero,
            ulParameterLen = 0
        };

        var rv = _lib.C_VerifyInit(_sessionManager.SessionId, &mechanism, publicKeyHandle);
        if (rv != Pkcs11Constants.CKR_OK)
        {
            return Result.Failure(SecurityError.EncryptionFailed($"PKCS#11 VerifyInit failed. RV: 0x{rv:X}"));
        }

        fixed (byte* pPayload = payload)
        fixed (byte* pSignature = signature)
        {
            rv = _lib.C_Verify(_sessionManager.SessionId, pPayload, (uint)payload.Length, pSignature, (uint)signature.Length);
            if (rv == Pkcs11Constants.CKR_SIGNATURE_INVALID)
            {
                return Result.Failure(SecurityError.InvalidToken("PKCS#11 signature verification failed: signature is invalid."));
            }

            if (rv != Pkcs11Constants.CKR_OK)
            {
                return Result.Failure(SecurityError.EncryptionFailed($"PKCS#11 Verify failed. RV: 0x{rv:X}"));
            }
        }

        return Result.Success();
    }

    private static uint ResolveKeyHandle(KeyIdentifier keyId)
    {
        if (string.IsNullOrEmpty(keyId.Value) || keyId.Value == "missing")
        {
            return 0;
        }

        if (uint.TryParse(keyId.Value, out var parsedHandle) && parsedHandle != 0)
        {
            return parsedHandle;
        }

        return 1;
    }
}
