# ADR-027: SonarCloud Static Analysis Integration and CI/CD Release Standardization

## Status
Accepted

## Date
2026-09-03

**Status:** Accepted  
**Date:** 2026-09-03  
**Deciders:** EricksonLopez.Security Architecture Team

---

## Context

To achieve full engineering parity with Tier-1 foundational repositories (`dotnet-sql-builder`, `dotnet-processes`, `dotnet-outbox`), `dotnet-security` requires consistent execution of all DevSecOps quality gates across pull requests and releases:
1. **Static Code Analysis**: While `SONAR_TOKEN` was plumbed through `ci.yml`, the reusable workflow `dotnet-build-test.yml` was missing Java 17 runtime setup and `dotnet-sonarscanner` execution commands.
2. **Deterministic Release Publication**: The release pipeline in `publish.yml` previously listened on `release: [published]`, required manual release creation ahead of builds, lacked Strong Name key restoration, and did not run Codecov pre-publish verification.

## Decision

1. **Incorporate SonarCloud Scanner**:
   - Update `.github/workflows/dotnet-build-test.yml` to install Java 17 and `dotnet-sonarscanner`.
   - Run `dotnet sonarscanner begin` before build and `dotnet sonarscanner end` after test execution when `SONAR_TOKEN` is present.
   - Configure exclusion patterns for test projects, benchmarks, and generated code.

2. **Standardize NuGet Publish Workflow**:
   - Trigger `publish.yml` on canonical SemVer Git tags (`push: tags: ['v*.*.*']`) and `workflow_dispatch`.
   - Restore Strong Name key `EricksonLopez.snk` from `secrets.SNK_KEY`.
   - Run full test suite with OpenCover coverage and upload to Codecov (`publish-gate`) before packaging.
   - Deterministically pack each of the 21 packages with `-p:TreatWarningsAsErrors=true` and `-p:VersionPrefix=$VERSION`.
   - Attest build provenance using Sigstore (`actions/attest-build-provenance@v2.2.3`).
   - Authenticate to NuGet.org via official OIDC (`NuGet/login@v1`).
   - Automatically generate GitHub Releases with structured Markdown tables detailing all 21 packages.

## Consequences

### Positive
- Enforces real-time SonarCloud security scanning and code quality inspection on every pull request.
- Eliminates manual release errors through automated, signed, and attested OIDC package publishing.
- Aligns `dotnet-security` with Tier-1 enterprise DevOps standards.

### Negative
- Incremental build time in CI when SonarScanner is executing.
