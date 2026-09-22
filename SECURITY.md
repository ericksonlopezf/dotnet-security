# Security Policy

## Supported Versions

We provide security updates and patches for active major and minor releases of `EricksonLopez.Security`:

| Version | Supported          | Security Status |
| ------- | ------------------ | --------------- |
| 1.0.x   | :white_check_mark: | Current Active Release |
| < 1.0.0 | :x:                | Unsupported |

---

## Reporting a Vulnerability

The security of `EricksonLopez.Security` and downstream systems relying upon it is paramount. If you discover a potential vulnerability or security flaw, we appreciate your help in disclosing it responsibly.

### Disclosure Process

1. **Do not open public GitHub issues or discussions for suspected security vulnerabilities.**
2. Send an email to **`ericksonlopezf@gmail.com`** with:
   - Detailed steps to reproduce the issue.
   - Proof of concept (PoC) code or demonstration script.
   - Potential impact assessment (e.g., side-channel leakage, plaintext exposure, denial of service).
   - Affected package(s) and version(s).
3. **Acknowledgment**: You will receive an initial response within 24 hours acknowledging receipt.
4. **Coordination & Patching**: The maintainers will investigate, reproduce, and prepare a patch within a private security advisory branch.
5. **Release & Advisory**: Once verified, a patched release will be published to NuGet, and a security advisory will be published with full credit to the reporter.

---

## Supply Chain Security

`EricksonLopez.Security` adheres to strict supply chain security standards:

- **Strong Name Signing**: All shipped assemblies are signed with the official project key (`EricksonLopez.snk`).
  - **Public Key**:
    ```text
    0024000004800000940000000602000000240000525341310004000001000100655c867cb6d2e3a8d53e10d858994a49ea6b428de6e1e2eec19c71f0409345a7bf1649e9208282982347d90153f237f1aef003468e4a913598faa0b96815de53ede401790587fef88c7869884cdbf4372e74a44facf7dd6995e9b832285f8c548f531e1886d6712632139b617cd4f13988021b7cc32b5c3af18f52e19ae2a6cc
    ```
- **Deterministic Builds**: Build outputs are reproducible across environments (`EmbedUntrackedSources=true`).
- **Sigstore Build Provenance Attestation**: Package artifacts (`.nupkg`) are cryptographically attested using GitHub's artifact attestation via Sigstore (`actions/attest-build-provenance@v1`), establishing verifiable tamper-proof supply chain lineage.
- **NuGet Trusted Publishing (OIDC)**: Automated package release utilizes OpenID Connect (OIDC) short-lived identity tokens, eliminating persistent long-lived API keys.
- **SourceLink**: All packages embed SourceLink metadata and symbol packages (`.snupkg`) enabling verified source debugging against GitHub commits.
- **Central Package Management (CPM)**: All package dependencies and versions are pinned centrally in `Directory.Packages.props` with strict transitive dependency auditing.

---

## Security Invariants & Boundaries

`EricksonLopez.Security` enforces the following defense-in-depth invariants by design:

1. **Authenticated Encryption (AEAD)**: Only AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305) are permitted. Legacy CBC or unauthenticated modes are not implemented and cannot be configured.
2. **Memory Scrubbing**: Sensitive buffers implement `IDisposable` and immediately zero their contents via `CryptographicOperations.ZeroMemory`.
3. **Side-Channel Timing Resistance**: All credential, token, and hash verifications use constant-time operations (`CryptographicOperations.FixedTimeEquals`, `ConstantTimeComparer`).
4. **Misuse-Resistant Envelopes**: Payloads are bound to versioned binary security envelopes with unique nonces, authentication tags, and tenant AAD context.
5. **Type-Safe Redaction**: Sensitive values wrapped in `Redacted<T>`, `Secret<T>`, and `ProtectedSecret` never emit plaintext in `ToString()` or debugger representations.
6. **Native AOT & Trimming Safety**: The core codebase avoids reflection, dynamic code generation, and ambient state, ensuring deterministic runtime safety.
