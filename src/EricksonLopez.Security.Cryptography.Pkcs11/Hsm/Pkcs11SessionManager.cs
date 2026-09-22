// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Hsm;

using System;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Result;

/// <summary>
/// Encapsulates and manages the lifecycle of a PKCS#11 cryptographic session.
/// </summary>
/// <remarks>
/// Ensures proper session cleanup, releasing unmanaged session handles and performing HSM logout when disposed.
/// </remarks>
public sealed unsafe class Pkcs11SessionManager : IDisposable
{
    private readonly Pkcs11NativeLibrary _lib;
    private readonly uint _sessionId;
    private bool _isLoggedIn;

    private Pkcs11SessionManager(Pkcs11NativeLibrary lib, uint sessionId)
    {
        _lib = lib;
        _sessionId = sessionId;
    }

    /// <summary>
    /// Gets the underlying unmanaged PKCS#11 session handle.
    /// </summary>
    public uint SessionId => _sessionId;

    /// <summary>
    /// Opens a new serial read/write session on the specified slot using the provided native library.
    /// </summary>
    /// <param name="lib">The loaded PKCS#11 native library containing the Cryptoki function pointers.</param>
    /// <param name="slotId">The cryptographic slot identifier where the session will be opened.</param>
    /// <returns>A successful <see cref="Result{T}"/> containing the initialized <see cref="Pkcs11SessionManager"/>, or an error if session creation fails.</returns>
    public static Result<Pkcs11SessionManager> OpenSession(Pkcs11NativeLibrary lib, uint slotId)
    {
        var rv = lib.C_OpenSession(slotId, Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, out var sessionId);

        if (rv != Pkcs11Constants.CKR_OK)
        {
            return Result<Pkcs11SessionManager>.Failure(SecurityError.EncryptionFailed($"Failed to open PKCS#11 session. RV: 0x{rv:X}"));
        }

        return Result<Pkcs11SessionManager>.Success(new Pkcs11SessionManager(lib, sessionId));
    }

    /// <summary>
    /// Authenticates a normal user to the HSM slot using the provided PIN bytes.
    /// </summary>
    /// <param name="pin">The UTF-8 or raw byte sequence representing the user PIN.</param>
    /// <returns>A successful <see cref="Result"/> if authentication succeeds; otherwise, an error indicating login failure.</returns>
    public Result Login(ReadOnlySpan<byte> pin)
    {
        fixed (byte* pPin = pin)
        {
            var rv = _lib.C_Login(_sessionId, Pkcs11Constants.CKU_USER, pPin, (uint)pin.Length);

            if (rv != Pkcs11Constants.CKR_OK)
            {
                return Result.Failure(SecurityError.EncryptionFailed($"HSM Login failed. RV: 0x{rv:X}"));
            }

            _isLoggedIn = true;
            return Result.Success();
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_isLoggedIn)
        {
            _lib.C_Logout(_sessionId);
            _isLoggedIn = false;
        }

        if (_sessionId != 0)
        {
            _lib.C_CloseSession(_sessionId);
        }
    }
}
