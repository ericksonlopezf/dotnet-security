## Description

Briefly describe the motivation and context for this change. Include any relevant issue numbers (e.g. `Fixes #123`).

---

## Type of Change

- [ ] `feat`: New feature or cryptographic capability
- [ ] `fix`: Bug fix or security remediation
- [ ] `perf`: Memory optimization or allocation reduction
- [ ] `refactor`: Structural improvement without behavioral changes
- [ ] `docs`: Documentation, cookbook recipe, or ADR update
- [ ] `test`: Additional test cases or mutation test coverage
- [ ] `chore`: Build, packaging, or dependency update

---

## Packages Affected

Please check all packages affected by this Pull Request:

- [ ] `EricksonLopez.Security.Abstractions`
- [ ] `EricksonLopez.Security`
- [ ] `EricksonLopez.Security.AspNetCore`
- [ ] `EricksonLopez.Security.Aws`
- [ ] `EricksonLopez.Security.Azure`
- [ ] `EricksonLopez.Security.Cryptography`
- [ ] `EricksonLopez.Security.Cryptography.Pkcs11`
- [ ] `EricksonLopez.Security.Cryptography.XmlDSig`
- [ ] `EricksonLopez.Security.GoogleCloud`
- [ ] `EricksonLopez.Security.HashiCorpVault`
- [ ] `EricksonLopez.Security.Mfa`
- [ ] `EricksonLopez.Security.Network`
- [ ] `EricksonLopez.Security.OpenTelemetry`
- [ ] `EricksonLopez.Security.Pki`
- [ ] `EricksonLopez.Security.Privacy.Hibp`
- [ ] `EricksonLopez.Security.Saml2`
- [ ] `EricksonLopez.Security.Testing`
- [ ] `EricksonLopez.Security.WebAuthn.Fido2`
- [ ] `EricksonLopez.Security.WebAuthn.Fido2.Mds3`
- [ ] `EricksonLopez.Security.ZeroTrust`
- [ ] `EricksonLopez.Security.Analyzers`
- [ ] Non-package files (Docs, Samples, Benchmarks, Workflows)

---

## Quality Gates & Verification Checklist

- [ ] **Build**: `dotnet build EricksonLopez.Security.slnx -c Release` completes with 0 errors and 0 warnings (`TreatWarningsAsErrors` enabled).
- [ ] **Automated Tests**: `dotnet test EricksonLopez.Security.slnx -c Release` passes across .NET 8.0, 9.0, and 10.0.
- [ ] **Architecture Rules**: NetArchTest suite passes (`EricksonLopez.Security.ArchitectureTests`).
- [ ] **Native AOT & Trimming**: No trimming warnings; AOT smoke test publishes cleanly.
- [ ] **Memory & Zero-Allocation**:
  - [ ] Sensitive buffers scrub memory on disposal via `CryptographicOperations.ZeroMemory`.
  - [ ] Hotpaths use `ReadOnlySpan<byte>` / `Span<byte>` with zero unnecessary allocations.
  - [ ] Benchmarks executed if core cryptographic routines were modified.
- [ ] **Side-Channel Resistance**: Constant-time comparison used for all secret comparisons.
- [ ] **Error Handling**: Uses `Result` / `Result<T>` from `EricksonLopez.Result` (no exceptions for expected outcomes).
- [ ] **Documentation**: `CHANGELOG.md` updated and relevant `/docs/` guides modified or added.
- [ ] **Commits**: Follows [Conventional Commits](https://www.conventionalcommits.org/).
