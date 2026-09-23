// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Tests;

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.Cryptography.Pkcs11.Signing;
using Xunit;

[Collection("Pkcs11HsmTests")]
public sealed unsafe class Pkcs11HsmAndSignatureEngineTests
{
    private static uint _openSessionReturn = Pkcs11Constants.CKR_OK;
    private static uint _openSessionSessionId = 999;
    private static uint _loginReturn = Pkcs11Constants.CKR_OK;
    private static uint _signInitReturn = Pkcs11Constants.CKR_OK;
    private static uint _signReturn = Pkcs11Constants.CKR_OK;
    private static uint _verifyInitReturn = Pkcs11Constants.CKR_OK;
    private static uint _verifyReturn = Pkcs11Constants.CKR_OK;
    private static bool _logoutCalled;
    private static int _logoutCallCount;
    private static bool _closeSessionCalled;

    public Pkcs11HsmAndSignatureEngineTests()
    {
        ResetMockState();
    }

    private static void ResetMockState()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _openSessionSessionId = 999;
        _loginReturn = Pkcs11Constants.CKR_OK;
        _signInitReturn = Pkcs11Constants.CKR_OK;
        _signReturn = Pkcs11Constants.CKR_OK;
        _verifyInitReturn = Pkcs11Constants.CKR_OK;
        _verifyReturn = Pkcs11Constants.CKR_OK;
        _logoutCalled = false;
        _logoutCallCount = 0;
        _closeSessionCalled = false;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockInitialize(IntPtr p) => Pkcs11Constants.CKR_OK;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockFinalize(IntPtr p) => Pkcs11Constants.CKR_OK;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockOpenSession(uint slot, uint flags, IntPtr p1, IntPtr p2, uint* pSession)
    {
        if (flags != (Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION))
        {
            return 0x00000007; // CKR_ARGUMENTS_BAD
        }

        if (pSession != null)
        {
            *pSession = _openSessionSessionId;
        }
        return _openSessionReturn;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockCloseSession(uint sess)
    {
        _closeSessionCalled = true;
        return Pkcs11Constants.CKR_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockLogin(uint sess, uint user, byte* pPin, uint pinLen)
    {
        return _loginReturn;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockLogout(uint sess)
    {
        _logoutCalled = true;
        _logoutCallCount++;
        return Pkcs11Constants.CKR_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockSignInit(uint sess, CK_MECHANISM* mech, uint key)
    {
        if (mech == null || mech->mechanism != Pkcs11Constants.CKM_SHA256_RSA_PKCS)
        {
            return 0x00000070; // CKR_MECHANISM_INVALID
        }

        return _signInitReturn;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockSign(uint sess, byte* pData, uint dataLen, byte* pSig, uint* pSigLen)
    {
        if (_signReturn != Pkcs11Constants.CKR_OK)
        {
            return _signReturn;
        }

        if (pSig != null && pSigLen != null && *pSigLen >= 4)
        {
            pSig[0] = 0xDE;
            pSig[1] = 0xAD;
            pSig[2] = 0xBE;
            pSig[3] = 0xEF;
            *pSigLen = 4;
        }
        return Pkcs11Constants.CKR_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockVerifyInit(uint sess, CK_MECHANISM* mech, uint key)
    {
        if (mech == null || mech->mechanism != Pkcs11Constants.CKM_SHA256_RSA_PKCS)
        {
            return 0x00000070; // CKR_MECHANISM_INVALID
        }

        return _verifyInitReturn;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockVerify(uint sess, byte* pData, uint dataLen, byte* pSig, uint sigLen)
    {
        return _verifyReturn;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockFindObjectsInit(uint sess, IntPtr pTemplate, uint ulCount) => Pkcs11Constants.CKR_OK;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockFindObjects(uint sess, uint* phObject, uint ulMaxObjectCount, uint* pulObjectCount)
    {
        if (pulObjectCount != null)
        {
            *pulObjectCount = 0;
        }
        return Pkcs11Constants.CKR_OK;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockFindObjectsFinal(uint sess) => Pkcs11Constants.CKR_OK;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint MockFailingOpenSession(uint slot, uint flags, IntPtr p1, IntPtr p2, uint* pSession) => Pkcs11Constants.CKR_SESSION_HANDLE_INVALID;

    public static Pkcs11NativeLibrary CreateFailingSessionMockNativeLibrary()
    {
        return new Pkcs11NativeLibrary(
            &MockInitialize,
            &MockFinalize,
            &MockFailingOpenSession,
            &MockCloseSession,
            &MockLogin,
            &MockLogout,
            &MockSignInit,
            &MockSign,
            &MockFindObjectsInit,
            &MockFindObjects,
            &MockFindObjectsFinal,
            &MockVerifyInit,
            &MockVerify);
    }

    public static Pkcs11NativeLibrary CreateMockNativeLibrary()
    {
        return new Pkcs11NativeLibrary(
            &MockInitialize,
            &MockFinalize,
            &MockOpenSession,
            &MockCloseSession,
            &MockLogin,
            &MockLogout,
            &MockSignInit,
            &MockSign,
            &MockFindObjectsInit,
            &MockFindObjects,
            &MockFindObjectsFinal,
            &MockVerifyInit,
            &MockVerify);
    }


    [Fact]
    public void SessionManager_OpenSessionAndLoginAndDispose_Success()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _loginReturn = Pkcs11Constants.CKR_OK;
        _logoutCalled = false;
        _closeSessionCalled = false;

        var lib = CreateMockNativeLibrary();
        var sessionResult = Pkcs11SessionManager.OpenSession(lib, slotId: 1);

        sessionResult.IsSuccess.Should().BeTrue();
        var session = sessionResult.Value;
        session.SessionId.Should().Be(999u);

        var loginResult = session.Login(new byte[] { 0x31, 0x32, 0x33, 0x34 });
        loginResult.IsSuccess.Should().BeTrue();

        session.Dispose();

        _logoutCalled.Should().BeTrue();
        _logoutCallCount.Should().Be(1);
        _closeSessionCalled.Should().BeTrue();

        // Idempotent dispose: subsequent call should not call logout again
        session.Dispose();
        _logoutCallCount.Should().Be(1);
    }

    [Fact]
    public void SessionManager_OpenSessionFailed_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_SESSION_HANDLE_INVALID;
        var lib = CreateMockNativeLibrary();

        var sessionResult = Pkcs11SessionManager.OpenSession(lib, slotId: 1);
        sessionResult.IsFailure.Should().BeTrue();
        sessionResult.Error.Description.Should().Contain("Failed to open PKCS#11 session");
    }

    [Fact]
    public void SessionManager_LoginFailed_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _loginReturn = 0x000000A0; // PIN_INCORRECT
        var lib = CreateMockNativeLibrary();

        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var loginResult = session.Login(new byte[] { 0x39 });

        loginResult.IsFailure.Should().BeTrue();
        loginResult.Error.Description.Should().Contain("HSM Login failed");
    }

    [Fact]
    public void DigitalSignatureEngine_Sign_ValidPayload_ReturnsSuccess()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _signInitReturn = Pkcs11Constants.CKR_OK;
        _signReturn = Pkcs11Constants.CKR_OK;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var sigDest = new byte[64];
        var keyId = new KeyIdentifier("hsm-key-01");

        var result = engine.Sign(payload, keyId, sigDest, out var bytesWritten);

        result.IsSuccess.Should().BeTrue();
        bytesWritten.Should().Be(4);
        sigDest[0].Should().Be(0xDE);
        sigDest[1].Should().Be(0xAD);
        sigDest[2].Should().Be(0xBE);
        sigDest[3].Should().Be(0xEF);
    }

    [Fact]
    public void DigitalSignatureEngine_SignInitFailed_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _signInitReturn = 0x00000005; // CKR_GENERAL_ERROR
        _signReturn = Pkcs11Constants.CKR_OK;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var sigDest = new byte[64];
        var keyId = new KeyIdentifier("hsm-key-01");
        var result = engine.Sign(new byte[] { 1 }, keyId, sigDest, out _);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("PKCS#11 SignInit failed");
    }

    [Fact]
    public void DigitalSignatureEngine_SignFailed_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _signInitReturn = Pkcs11Constants.CKR_OK;
        _signReturn = 0x00000005; // CKR_GENERAL_ERROR

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var sigDest = new byte[64];
        var keyId = new KeyIdentifier("hsm-key-01");
        var result = engine.Sign(new byte[] { 1 }, keyId, sigDest, out _);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("PKCS#11 Sign failed");
    }

    [Fact]
    public void DigitalSignatureEngine_Verify_ValidSignature_ReturnsSuccess()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _verifyInitReturn = Pkcs11Constants.CKR_OK;
        _verifyReturn = Pkcs11Constants.CKR_OK;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var keyId = new KeyIdentifier("hsm-key-01");
        var result = engine.Verify(new byte[] { 1, 2, 3 }, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, keyId);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void DigitalSignatureEngine_Verify_InvalidSignature_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _verifyInitReturn = Pkcs11Constants.CKR_OK;
        _verifyReturn = Pkcs11Constants.CKR_SIGNATURE_INVALID;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var keyId = new KeyIdentifier("hsm-key-01");
        var result = engine.Verify(new byte[] { 1, 2, 3 }, new byte[] { 0x00, 0x00 }, keyId);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidToken");
    }

    [Fact]
    public void DigitalSignatureEngine_Verify_InitFailed_ReturnsFailure()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _verifyInitReturn = 0x00000005; // CKR_GENERAL_ERROR
        _verifyReturn = Pkcs11Constants.CKR_OK;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var keyId = new KeyIdentifier("hsm-key-01");
        var result = engine.Verify(new byte[] { 1 }, new byte[] { 2 }, keyId);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("PKCS#11 VerifyInit failed");
    }

    [Fact]
    public void DigitalSignatureEngine_Verify_KeyNotFound_ReturnsFailure()
    {
        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var result = engine.Verify(new byte[] { 1 }, new byte[] { 2 }, new KeyIdentifier("missing"));

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.KeyNotFound");
    }

    [Fact]
    public void Pkcs11NativeLibrary_FunctionPointerGetters_ReturnNonNullPointers()
    {
        var lib = CreateMockNativeLibrary();
        ((IntPtr)lib.C_Initialize).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_Finalize).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_OpenSession).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_CloseSession).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_Login).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_Logout).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_SignInit).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_Sign).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_FindObjectsInit).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_FindObjects).Should().NotBe(IntPtr.Zero);
        ((IntPtr)lib.C_FindObjectsFinal).Should().NotBe(IntPtr.Zero);
    }

    [Fact]
    public void SessionManager_DisposeWithoutLogin_DoesNotCallLogout()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _logoutCalled = false;
        _closeSessionCalled = false;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;

        session.Dispose();

        _logoutCalled.Should().BeFalse();
        _closeSessionCalled.Should().BeTrue();
    }

    [Fact]
    public void SessionManager_DisposeWhenSessionIdIsZero_DoesNotCallCloseSession()
    {
        _openSessionReturn = Pkcs11Constants.CKR_OK;
        _openSessionSessionId = 0;
        _closeSessionCalled = false;

        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        session.SessionId.Should().Be(0u);

        session.Dispose();

        _closeSessionCalled.Should().BeFalse();
    }

    [Fact]
    public void DigitalSignatureEngine_Sign_KeyNotFound_ReturnsFailure()
    {
        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);

        var sigDest = new byte[64];
        var result = engine.Sign(new byte[] { 1 }, new KeyIdentifier("missing"), sigDest, out _);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.KeyNotFound");
        result.Error.Description.Should().Be("The cryptographic key with identifier 'missing' was not found.");

        var emptyResult = engine.Sign(new byte[] { 1 }, default, sigDest, out _);
        emptyResult.IsFailure.Should().BeTrue();
        emptyResult.Error.Code.Should().Be("Security.KeyNotFound");
    }

    public static Pkcs11NativeLibrary CreatePartialMockNativeLibrary(
        delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> cSignInit,
        delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint*, uint> cSign,
        delegate* unmanaged[Cdecl]<uint, CK_MECHANISM*, uint, uint> cVerifyInit,
        delegate* unmanaged[Cdecl]<uint, byte*, uint, byte*, uint, uint> cVerify)
    {
        return new Pkcs11NativeLibrary(
            &MockInitialize,
            &MockFinalize,
            &MockOpenSession,
            &MockCloseSession,
            &MockLogin,
            &MockLogout,
            cSignInit,
            cSign,
            &MockFindObjectsInit,
            &MockFindObjects,
            &MockFindObjectsFinal,
            cVerifyInit,
            cVerify);
    }

    [Fact]
    public void DigitalSignatureEngine_Sign_NullFunctionPointers_ReturnsFailure()
    {
        var lib1 = CreatePartialMockNativeLibrary(null, &MockSign, &MockVerifyInit, &MockVerify);
        var session1 = Pkcs11SessionManager.OpenSession(lib1, slotId: 1).Value;
        var engine1 = new Pkcs11DigitalSignatureEngine(lib1, session1);
        var sigDest = new byte[64];
        var res1 = engine1.Sign(new byte[] { 1 }, new KeyIdentifier("k"), sigDest, out _);
        res1.IsFailure.Should().BeTrue();
        res1.Error.Description.Should().Contain("does not export C_SignInit or C_Sign");

        var lib2 = CreatePartialMockNativeLibrary(&MockSignInit, null, &MockVerifyInit, &MockVerify);
        var session2 = Pkcs11SessionManager.OpenSession(lib2, slotId: 1).Value;
        var engine2 = new Pkcs11DigitalSignatureEngine(lib2, session2);
        var res2 = engine2.Sign(new byte[] { 1 }, new KeyIdentifier("k"), sigDest, out _);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Description.Should().Contain("does not export C_SignInit or C_Sign");
    }

    [Fact]
    public void DigitalSignatureEngine_Verify_NullFunctionPointers_ReturnsFailure()
    {
        var lib1 = CreatePartialMockNativeLibrary(&MockSignInit, &MockSign, null, &MockVerify);
        var session1 = Pkcs11SessionManager.OpenSession(lib1, slotId: 1).Value;
        var engine1 = new Pkcs11DigitalSignatureEngine(lib1, session1);
        var res1 = engine1.Verify(new byte[] { 1 }, new byte[] { 2 }, new KeyIdentifier("k"));
        res1.IsFailure.Should().BeTrue();
        res1.Error.Description.Should().Contain("does not export C_VerifyInit or C_Verify");

        var lib2 = CreatePartialMockNativeLibrary(&MockSignInit, &MockSign, &MockVerifyInit, null);
        var session2 = Pkcs11SessionManager.OpenSession(lib2, slotId: 1).Value;
        var engine2 = new Pkcs11DigitalSignatureEngine(lib2, session2);
        var res2 = engine2.Verify(new byte[] { 1 }, new byte[] { 2 }, new KeyIdentifier("k"));
        res2.IsFailure.Should().BeTrue();
        res2.Error.Description.Should().Contain("does not export C_VerifyInit or C_Verify");
    }

    [Fact]
    public void DigitalSignatureEngine_NumericKeyHandleResolution_HandlesEdgeCases()
    {
        var lib = CreateMockNativeLibrary();
        var session = Pkcs11SessionManager.OpenSession(lib, slotId: 1).Value;
        var engine = new Pkcs11DigitalSignatureEngine(lib, session);
        var sigDest = new byte[64];

        var resZero = engine.Sign(new byte[] { 1 }, new KeyIdentifier("0"), sigDest, out _);
        resZero.IsFailure.Should().BeTrue();
        resZero.Error.Code.Should().Be("Security.KeyNotFound");

        var resValid = engine.Sign(new byte[] { 1 }, new KeyIdentifier("42"), sigDest, out _);
        resValid.IsSuccess.Should().BeTrue();
    }
}
