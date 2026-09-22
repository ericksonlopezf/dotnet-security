// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Interop;

using System;
using System.Runtime.InteropServices;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Result;

/// <summary>
/// Provides Native AOT compatible dynamic loading for PKCS#11 unmanaged libraries using unmanaged function pointers.
/// </summary>
public sealed unsafe class Pkcs11NativeLibrary : IDisposable
{
    private readonly IntPtr _handle;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pkcs11NativeLibrary"/> class by loading the native library at the specified path and resolving entry points.
    /// </summary>
    /// <param name="libraryPath">The file path to the native PKCS#11 shared library.</param>
    /// <exception cref="DllNotFoundException">The native library at <paramref name="libraryPath"/> could not be loaded</exception>
    /// <exception cref="EntryPointNotFoundException">One or more required PKCS#11 function symbols were not exported by the library</exception>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Requires external unmanaged PKCS#11 HSM driver library (.dll/.so) not present in isolated test environments.")]
    public Pkcs11NativeLibrary(string libraryPath)
    {
        if (!NativeLibrary.TryLoad(libraryPath, out _handle))
        {
            throw new DllNotFoundException($"Failed to load PKCS#11 provider library at '{libraryPath}'.");
        }

        // Bind functions
        C_Initialize = (delegate* unmanaged[Cdecl]<IntPtr, uint>)GetExport("C_Initialize");
        C_Finalize = (delegate* unmanaged[Cdecl]<IntPtr, uint>)GetExport("C_Finalize");
        C_OpenSession = (delegate* unmanaged[Cdecl]<uint, uint, IntPtr, IntPtr, out uint, uint>)GetExport("C_OpenSession");
        C_CloseSession = (delegate* unmanaged[Cdecl]<uint, uint>)GetExport("C_CloseSession");
        C_Login = (delegate* unmanaged[Cdecl]<uint, uint, byte*, uint, uint>)GetExport("C_Login");
        C_Logout = (delegate* unmanaged[Cdecl]<uint, uint>)GetExport("C_Logout");
        C_SignInit = (delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint>)GetExport("C_SignInit");
        C_Sign = (delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, ref uint, uint>)GetExport("C_Sign");
        C_VerifyInit = (delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint>)GetExport("C_VerifyInit");
        C_Verify = (delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint, uint>)GetExport("C_Verify");
        C_FindObjectsInit = (delegate* unmanaged[Cdecl]<uint, IntPtr, uint, uint>)GetExport("C_FindObjectsInit");
        C_FindObjects = (delegate* unmanaged[Cdecl]<uint, uint*, uint, out uint, uint>)GetExport("C_FindObjects");
        C_FindObjectsFinal = (delegate* unmanaged[Cdecl]<uint, uint>)GetExport("C_FindObjectsFinal");
    }

    internal Pkcs11NativeLibrary(
        delegate* unmanaged[Cdecl]<IntPtr, uint> initialize,
        delegate* unmanaged[Cdecl]<IntPtr, uint> finalize,
        delegate* unmanaged[Cdecl]<uint, uint, IntPtr, IntPtr, uint*, uint> openSession,
        delegate* unmanaged[Cdecl]<uint, uint> closeSession,
        delegate* unmanaged[Cdecl]<uint, uint, byte*, uint, uint> login,
        delegate* unmanaged[Cdecl]<uint, uint> logout,
        delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> signInit,
        delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint*, uint> sign,
        delegate* unmanaged[Cdecl]<uint, IntPtr, uint, uint> findObjectsInit = null,
        delegate* unmanaged[Cdecl]<uint, uint*, uint, uint*, uint> findObjects = null,
        delegate* unmanaged[Cdecl]<uint, uint> findObjectsFinal = null,
        delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> verifyInit = null,
        delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint, uint> verify = null)
    {
        _handle = IntPtr.Zero;
        C_Initialize = initialize;
        C_Finalize = finalize;
        C_OpenSession = (delegate* unmanaged[Cdecl]<uint, uint, IntPtr, IntPtr, out uint, uint>)openSession;
        C_CloseSession = closeSession;
        C_Login = login;
        C_Logout = logout;
        C_SignInit = signInit;
        C_Sign = (delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, ref uint, uint>)sign;
        C_VerifyInit = verifyInit;
        C_Verify = verify;
        C_FindObjectsInit = findObjectsInit;
        C_FindObjects = (delegate* unmanaged[Cdecl]<uint, uint*, uint, out uint, uint>)findObjects;
        C_FindObjectsFinal = findObjectsFinal;
    }



    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Initialize</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<IntPtr, uint> C_Initialize { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Finalize</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<IntPtr, uint> C_Finalize { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_OpenSession</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint, IntPtr, IntPtr, out uint, uint> C_OpenSession { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_CloseSession</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint> C_CloseSession { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Login</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint, byte*, uint, uint> C_Login { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Logout</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint> C_Logout { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_SignInit</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> C_SignInit { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Sign</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, ref uint, uint> C_Sign { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_VerifyInit</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> C_VerifyInit { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_Verify</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint, uint> C_Verify { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_FindObjectsInit</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, IntPtr, uint, uint> C_FindObjectsInit { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_FindObjects</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint*, uint, out uint, uint> C_FindObjects { get; }

    /// <summary>
    /// Gets the unmanaged function pointer for <c>C_FindObjectsFinal</c>.
    /// </summary>
    public delegate* unmanaged[Cdecl]<uint, uint> C_FindObjectsFinal { get; }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Requires external unmanaged PKCS#11 HSM driver library (.dll/.so) not present in isolated test environments.")]
    private IntPtr GetExport(string name)
    {
        if (NativeLibrary.TryGetExport(_handle, name, out var address))
        {
            return address;
        }
        throw new EntryPointNotFoundException($"The PKCS#11 library does not export the required function '{name}'.");
    }

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Requires external unmanaged PKCS#11 HSM driver library (.dll/.so) not present in isolated test environments.")]
    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            NativeLibrary.Free(_handle);
        }
    }
}
