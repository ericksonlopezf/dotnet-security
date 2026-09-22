# Native AOT Compilation & Trimming Compatibility — EricksonLopez.Security

> **Version**: v1.0.0  
> **Target Frameworks**: .NET 8.0 | .NET 9.0 | .NET 10.0  
> **Native AOT Status**: Core packages trim-safe & ahead-of-time compatible; 3 packages explicitly opt out (see matrix below)

---

## 1. Native AOT Mandate & Architectural Invariants

`EricksonLopez.Security` is engineered under the strict constraint that modern cloud-native .NET applications require deterministic startup latency, reduced memory footprints, and minimized container image sizes achieved through **Native AOT compilation** (`dotnet publish -c Release /p:PublishAot=true`).

To guarantee seamless Native AOT publishing without warnings or runtime crashes, the entire ecosystem adheres to five non-negotiable invariants:

1. **Zero Runtime Reflection**: No `Type.GetType(string)`, `Activator.CreateInstance()`, or private member reflection across any core or satellite package.
2. **Deterministic Binary Serialization**: Binary payloads and security envelopes (`SecurityEnvelope`) are serialized and parsed exclusively using deterministic span operations via `System.Buffers.Binary.BinaryPrimitives`.
3. **Zero Dynamic Code Generation**: No `System.Reflection.Emit`, expression tree compilation (`Compile()`), or runtime IL weaving.
4. **Explicit Dependency Injection**: Service registrations avoid ambient assembly scanning; all DI descriptors use explicit factory delegates or open-generic registrations vetted by the trimming analyzer.
5. **Strict MSBuild Compilation Guardrails**:
   ```xml
   <IsAotCompatible Condition="'$(IsAotCompatible)' == ''">true</IsAotCompatible>
   <EnableTrimAnalyzer Condition="'$(EnableTrimAnalyzer)' == ''">true</EnableTrimAnalyzer>
   <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
   ```

---

## 2. Package-by-Package AOT Compatibility Matrix

All 21 packages are assessed for Native AOT and trimming safety (20 runtime packages + 1 build-time analyzer). The build-time diagnostic analyzer package (`EricksonLopez.Security.Analyzers`) targets `netstandard2.0` and runs inside the compiler process. Three runtime packages explicitly set `<IsAotCompatible>false</IsAotCompatible>` due to XML reflection or OTel SDK constraints (see `❌ No` entries below):

| # | Package Name | Target Frameworks | Native AOT | Trimming Verification |
|:---:|---|---|:---:|---|
| **01** | `EricksonLopez.Security.Abstractions` | `net8.0;net9.0;net10.0` | ✅ Yes | Zero dependencies; domain primitives and value objects. |
| **02** | `EricksonLopez.Security` | `net8.0;net9.0;net10.0` | ✅ Yes | Direct AES-GCM, ChaCha20-Poly1305, PQC, and binary envelope. |
| **03** | `EricksonLopez.Security.Cryptography` | `net8.0;net9.0;net10.0` | ✅ Yes | CSPRNG, constant-time primitives, and span key derivation. |
| **04** | `EricksonLopez.Security.AspNetCore` | `net8.0;net9.0;net10.0` | ✅ Yes | Middleware and header pipelines compatible with ASP.NET Core AOT. |
| **05** | `EricksonLopez.Security.Network` | `net8.0;net9.0;net10.0` | ✅ Yes | Custom `SocketsHttpHandler` socket filters without dynamic dispatch. |
| **06** | `EricksonLopez.Security.Mfa` | `net8.0;net9.0;net10.0` | ✅ Yes | RFC 6238 TOTP/HOTP span-based integer math and Base32 decoding. |
| **07** | `EricksonLopez.Security.ZeroTrust` | `net8.0;net9.0;net10.0` | ✅ Yes | Strongly-typed multidimensional ABAC policy rule evaluation. |
| **08** | `EricksonLopez.Security.WebAuthn.Fido2` | `net8.0;net9.0;net10.0` | ✅ Yes | Span CBOR parsing via `System.Formats.Cbor.CborReader`. |
| **09** | `EricksonLopez.Security.WebAuthn.Fido2.Mds3` | `net8.0;net9.0;net10.0` | ✅ Yes | HttpClient-based metadata cache and BLOB validation. |
| **10** | `EricksonLopez.Security.Saml2` | `net8.0;net9.0;net10.0` | ❌ No | Depends on `System.Security.Cryptography.Xml` which uses runtime reflection for XML canonicalization. `<IsAotCompatible>false</IsAotCompatible>` explicitly set in project file. |
| **11** | `EricksonLopez.Security.Pki` | `net8.0;net9.0;net10.0` | ✅ Yes | In-box `X509Chain` and `X509CertificateLoader` (on .NET 9+). |
| **12** | `EricksonLopez.Security.Privacy.Hibp` | `net8.0;net9.0;net10.0` | ✅ Yes | Span-based SHA-1 prefix comparison over HTTP responses. |
| **13** | `EricksonLopez.Security.Cryptography.XmlDSig` | `net8.0;net9.0;net10.0` | ❌ No | Depends on `System.Security.Cryptography.Xml` for W3C canonicalization; XML reflection prevents AOT compatibility. `<IsAotCompatible>false</IsAotCompatible>` explicitly set in project file. |
| **14** | `EricksonLopez.Security.Cryptography.Pkcs11` | `net8.0;net9.0;net10.0` | ⚠️ Unverified* | Direct native interop using `[UnmanagedCallersOnly]` and P/Invoke stubs. *Claim is based on static analysis; not covered by `EricksonLopez.Security.AotSmokeTest` in CI. Native AOT execution requires runtime verification against the target HSM vendor's native PKCS#11 library. |
| **15** | `EricksonLopez.Security.Azure` | `net8.0;net9.0;net10.0` | ✅ Yes | In-memory `IKeyStore` and `ISecretStore` stub modeling Azure Key Vault contracts (reflection-free). |
| **16** | `EricksonLopez.Security.Aws` | `net8.0;net9.0;net10.0` | ✅ Yes | In-memory `IKeyStore` and `ISecretStore` stub modeling AWS KMS contracts (reflection-free). |
| **17** | `EricksonLopez.Security.GoogleCloud` | `net8.0;net9.0;net10.0` | ✅ Yes | In-memory `IKeyStore` and `ISecretStore` double modeling Google Cloud KMS and Secret Manager contracts (reflection-free). |
| **18** | `EricksonLopez.Security.HashiCorpVault` | `net8.0;net9.0;net10.0` | ✅ Yes | In-memory `IKeyStore` and `ISecretStore` stub modeling HashiCorp Vault contracts (reflection-free). |
| **19** | `EricksonLopez.Security.OpenTelemetry` | `net8.0;net9.0;net10.0` | ❌ No | OpenTelemetry SDK (`OpenTelemetry` 1.18.0) is not fully AOT-compatible. `<IsAotCompatible>false</IsAotCompatible>` and `<EnableTrimAnalyzer>false</EnableTrimAnalyzer>` explicitly set. Intentional per ADR-019. |
| **20** | `EricksonLopez.Security.Testing` | `net8.0;net9.0;net10.0` | ✅ Yes | In-memory test doubles and deterministic generators. |
| **21** | `EricksonLopez.Security.Analyzers` | `netstandard2.0` | N/A | Build-time Roslyn diagnostic analyzer executed inside compiler. |

---

## 3. Reflection-Free Design Patterns

### 1. Span-Based Binary Parsing with `BinaryPrimitives`
Rather than relying on reflection-based serialization, all security envelope fields are packed deterministically:

```csharp
// Zero reflection, zero trimming ambiguity
public static void WriteEnvelopeHeader(Span<byte> destination, byte formatVersion, byte algorithmId, ushort keyIdLength)
{
    destination[0] = formatVersion;
    destination[1] = algorithmId;
    BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(2, 2), keyIdLength);
}
```

### 2. High-Performance CBOR Decoding without Code Generation
`EricksonLopez.Security.WebAuthn.Fido2` parses WebAuthn authenticator data and attestation statements using the runtime's native `System.Formats.Cbor.CborReader`, navigating maps, byte strings, and integer tags without reflection or source generation overhead.

### 3. XML Digital Signatures & SAML Hardening
`EricksonLopez.Security.Saml2` and `EricksonLopez.Security.Cryptography.XmlDSig` explicitly instantiate `XmlDocument` with safe `XmlReaderSettings`:
```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersInDocument = 10_000_000
};
```

---

## 4. Automated Native AOT Verification (Smoke Test)

The repository includes an executable Native AOT smoke test application located in [`tests/EricksonLopez.Security.AotSmokeTest`](../tests/EricksonLopez.Security.AotSmokeTest):

### Project Configuration
```xml
<PropertyGroup>
  <OutputType>Exe</OutputType>
  <TargetFramework>net10.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <InvariantGlobalization>true</InvariantGlobalization>
  <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
</PropertyGroup>
```

### Running the Smoke Test
Execute full ahead-of-time publishing to compile the application down to a native machine executable:

```bash
# Windows
dotnet publish tests/EricksonLopez.Security.AotSmokeTest/EricksonLopez.Security.AotSmokeTest.csproj -c Release -r win-x64 --self-contained

# Linux
dotnet publish tests/EricksonLopez.Security.AotSmokeTest/EricksonLopez.Security.AotSmokeTest.csproj -c Release -r linux-x64 --self-contained
```

### Verified Subsystems under AOT Execution
1. **Dependency Injection**: Resolution of all registered security singletons and scoped contexts.
2. **AES-256-GCM Encryption**: Hardware-accelerated encryption, authentication tag verification, and decryption.
3. **Binary Security Envelope**: Binary stream serialization and deserialization with tenant AAD binding.
4. **Password Hashing**: PBKDF2-HMAC-SHA512 key derivation and verification.
5. **Token Infrastructure**: High-entropy token generation and constant-time comparison.
6. **Memory Scrubbing**: Verification of zero heap leaks and disposal via `CryptographicOperations.ZeroMemory`.
