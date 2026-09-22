# Contributing to EricksonLopez.Security

Thank you for your interest in contributing to `EricksonLopez.Security`! We welcome contributions that maintain our high standards of cryptographic rigor, performance, and memory safety.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to [ericksonlopezf@gmail.com](mailto:ericksonlopezf@gmail.com).

---

## Architectural Principles & Invariants

Before writing code, ensure your changes respect the following core tenets:

1. **Clean Architecture & Decoupling**: Keep domain models and abstractions in `EricksonLopez.Security.Abstractions` free of third-party frameworks, persistence providers, or cloud SDKs.
2. **Native AOT & Trim Safety**: The core ecosystem enforces `<EnableTrimAnalyzer>true</EnableTrimAnalyzer>`, `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`, and zero runtime reflection over unknown types.
3. **Memory Scrubbing & Zero Allocations**:
   - Use `ReadOnlySpan<byte>` and `Span<byte>` for all core crypto and hashing pathways.
   - For temporary sensitive material, use `ISecretBuffer` and call `CryptographicOperations.ZeroMemory` upon `Dispose()`.
4. **Side-Channel Resistance**: Use `CryptographicOperations.FixedTimeEquals` or `ConstantTimeComparer` for all security-sensitive comparisons (hashes, tokens, API keys).
5. **Functional Error Handling**: Return `Result` or `Result<T>` from `EricksonLopez.Result`. Do not throw exceptions for anticipated security or validation failures.
6. **English Only**: All source code, XML doc comments, commit messages, and documentation must be written in professional English.

---

## Development Environment & Prerequisites

- **.NET SDK**: .NET 10.0 SDK (version `10.0.400` pinned in [`global.json`](./global.json); multi-targeting frameworks: `net8.0`, `net9.0`, `net10.0`).
- **IDE**: Visual Studio 2022 (v17.12+), JetBrains Rider 2024.3+, or Visual Studio Code with C# Dev Kit.
- **Git**: Configured for LF or native line endings (see `.gitattributes`).

---

## Build & Test Commands

### 1. Build the Solution

Restore dependencies and build all projects across all supported target frameworks in Release mode:

```bash
dotnet build EricksonLopez.Security.slnx -c Release
```

### 2. Execute Automated Tests

Run the full test suite across all packages and target frameworks:

```bash
dotnet test EricksonLopez.Security.slnx -c Release
```

### 3. Architecture Validation Tests

Verify that package boundaries and Clean Architecture layering rules remain intact:

```bash
dotnet test tests/EricksonLopez.Security.ArchitectureTests/EricksonLopez.Security.ArchitectureTests.csproj --no-build -c Release
```

### 4. Native AOT Smoke Test

Validate ahead-of-time compilation and trimming compatibility:

```bash
dotnet publish tests/EricksonLopez.Security.AotSmokeTest/EricksonLopez.Security.AotSmokeTest.csproj -c Release -r win-x64 --self-contained
```

### 5. Mutation Testing (Stryker.NET)

Verify mutation test resilience against the configured quality gates (high: ≥100%, low: ≥98%, break: 95%):

```bash
# Install Stryker.NET (first time only)
dotnet tool install --global dotnet-stryker

# Run against a specific package (config files live in the repository root)
dotnet stryker --config-file stryker-config.json

# Run against a specific satellite package (e.g., Cryptography)
dotnet stryker --config-file stryker-cryptography-config.json
```

> **Quality Gate Thresholds** (defined in each `stryker-*.json`):
> - `high` (≥100%): ✅ HIGH
> - `low` (≥98%): 🟡 LOW (acceptable)
> - `break` (<95%): ❌ FAILED (CI fails with non-zero exit code)

### 6. Benchmarks Execution

When making changes to core cryptographic or allocation-sensitive routines, execute BenchmarkDotNet to ensure zero heap allocations:

```bash
dotnet run -c Release --project benchmarks/EricksonLopez.Security.Benchmarks
```

---

## Commit & Branching Conventions

### Branch Strategy
- `main`: Protected trunk representing stable, tested code. Merges trigger `Release Please` and the NuGet publish pipeline.
- `develop`: Active integration branch. Pushes trigger the full CI pipeline (build, test, AOT smoke test).
- Feature branches: `feat/<feature-name>` or `feature/<feature-name>`.
- Bugfix branches: `fix/<issue-description>`.
- Refactoring or maintenance: `refactor/<scope>` or `chore/<task>`.

### Commit Message Convention
We adhere to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
- `feat(scope): add support for ...`
- `fix(scope): resolve timing leak in ...`
- `docs(scope): update migration guide for ...`
- `perf(scope): eliminate span allocation in ...`
- `refactor(scope): streamline key lifecycle state machine`
- `test(scope): add mutation test cases for ...`

---

## Pull Request Checklist

Before submitting a pull request, ensure the following checklist is completed:

- [ ] The solution builds cleanly with zero errors and zero warnings (`TreatWarningsAsErrors` enabled).
- [ ] All existing and new automated tests pass on .NET 8.0, .NET 9.0, and .NET 10.0.
- [ ] Architecture tests pass without layer violations.
- [ ] Native AOT compatibility is verified (no trim warnings).
- [ ] Any memory-sensitive paths scrub memory on disposal (`ZeroMemory`).
- [ ] Code is documented with XML documentation comments.
- [ ] Commits follow Conventional Commits format.
- [ ] Relevant documentation in `docs/` and `CHANGELOG.md` is updated.
- [ ] Mutation score does not drop below 95% break threshold (verify via `dotnet stryker` locally on affected packages).
- [ ] `./scripts/verify-compliance.ps1` passes without violations.
