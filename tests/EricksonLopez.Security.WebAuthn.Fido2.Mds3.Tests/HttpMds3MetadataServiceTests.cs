// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3.Tests;

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using EricksonLopez.Security.Testing.Http;
using EricksonLopez.Security.Testing.Logging;
using Xunit;

public sealed class HttpMds3MetadataServiceTests
{

    private static string BuildMds3Jwt(object payloadObj)
    {
        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"none\"}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payloadObj))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = "";
        return $"{header}.{payload}.{signature}";
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var http = new HttpClient();
        var opts = Options.Create(new Mds3Options());
        var logger = NullLogger<HttpMds3MetadataService>.Instance;

        Assert.Throws<ArgumentNullException>(() => new HttpMds3MetadataService(null!, opts, logger));
        Assert.Throws<ArgumentNullException>(() => new HttpMds3MetadataService(http, null!, logger));
        Assert.Throws<ArgumentNullException>(() => new HttpMds3MetadataService(http, opts, null!));
    }

    [Fact]
    public async Task GetMetadataAsync_ValidAaguid_ReturnsMetadata()
    {
        var targetAaguid = Guid.NewGuid();
        var certBytes = new byte[] { 0x30, 0x82, 0x01, 0x02 };
        var certB64 = Convert.ToBase64String(certBytes);

        var payload = new
        {
            legalHeader = "FIDO Alliance",
            no = 123,
            nextUpdate = "2026-10-01",
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new
                    {
                        description = "YubiKey 5 NFC",
                        attestationRootCertificates = new[] { certB64, "invalid-base64-!!!" }
                    },
                    statusReports = new object[]
                    {
                        new
                        {
                            status = "FIDO_CERTIFIED_L2",
                            effectiveDate = "2026-01-01",
                            url = "https://fidoalliance.org/cert/123",
                            certificate = "cert-id",
                            certificationLevel = "L2"
                        }
                    },
                    timeOfLastStatusChange = "2026-01-01T00:00:00Z"
                },
                new
                {
                    // Valid AAGUID entry with metadataStatement lacking root certs (covers line 290 condition 1089 false branch)
                    aaguid = Guid.NewGuid().ToString(),
                    description = "FIDO Key Without Root Certs",
                    metadataStatement = new
                    {
                        description = "Statement without root certs"
                    }
                },
                new
                {
                    // Valid AAGUID entry with NO metadataStatement (covers line 290 condition 1066 false branch)
                    aaguid = Guid.NewGuid().ToString(),
                    description = "FIDO Key Without Metadata Statement"
                },
                new
                {
                    // Corrupt entry that triggers catch in ParseEntry
                    aaguid = targetAaguid.ToString(),
                    statusReports = "not-an-array"
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref fetchCount);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
            };
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options
        {
            CacheDuration = TimeSpan.FromHours(1),
            AllowUnknownAuthenticators = false
        };

        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Aaguid.Should().Be(targetAaguid);
        result.Value.Description.Should().Be("YubiKey 5 NFC");
        result.Value.StatusReports.Should().HaveCount(1);
        result.Value.StatusReports[0].Status.Should().Be(AuthenticatorStatus.FidoCertifiedL2);
        result.Value.StatusReports[0].EffectiveDate.Should().Be("2026-01-01");
        result.Value.StatusReports[0].Url.Should().Be("https://fidoalliance.org/cert/123");
        result.Value.StatusReports[0].Certificate.Should().Be("cert-id");
        result.Value.StatusReports[0].CertificationLevel.Should().Be("L2");
        result.Value.AttestationRootCertificates.Should().HaveCount(1);
        result.Value.AttestationRootCertificates[0].Should().Equal(certBytes);

        // Fast-path cache hit (does not re-fetch)
        var cachedResult = await service.GetMetadataAsync(targetAaguid);
        cachedResult.IsSuccess.Should().BeTrue();
        cachedResult.Value.Aaguid.Should().Be(targetAaguid);
        fetchCount.Should().Be(1);
    }

    [Fact]
    public async Task GetMetadataAsync_CacheExpired_RefetchesFromHttp()
    {
        var targetAaguid = Guid.NewGuid();
        var payload1 = new
        {
            entries = new[]
            {
                new { aaguid = targetAaguid.ToString(), metadataStatement = new { description = "Initial Key" } }
            }
        };
        var payload2 = new
        {
            entries = new[]
            {
                new { aaguid = targetAaguid.ToString(), metadataStatement = new { description = "Updated Key" } }
            }
        };

        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            var count = Interlocked.Increment(ref fetchCount);
            var payload = count == 1 ? payload1 : payload2;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(BuildMds3Jwt(payload), Encoding.UTF8, "application/jwt")
            };
        });

        var fakeTime = new FakeTimeProvider(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        var client = new HttpClient(handler);
        var options = new Mds3Options
        {
            CacheDuration = TimeSpan.FromHours(1)
        };

        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance, fakeTime);

        var res1 = await service.GetMetadataAsync(targetAaguid);
        res1.IsSuccess.Should().BeTrue();
        res1.Value.Description.Should().Be("Initial Key");

        fakeTime.Advance(TimeSpan.FromHours(2));

        var res2 = await service.GetMetadataAsync(targetAaguid);
        res2.IsSuccess.Should().BeTrue();
        res2.Value.Description.Should().Be("Updated Key");
        fetchCount.Should().Be(2);
    }

    [Fact]
    public async Task GetMetadataAsync_NotFound_AllowUnknownTrue_ReturnsFailure()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(payload);

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options { AllowUnknownAuthenticators = true };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Be($"AAGUID {targetAaguid} not found in FIDO MDS3 metadata.");
        result.Error.Description.Should().NotContain("AllowUnknownAuthenticators is false");
    }

    [Fact]
    public async Task GetMetadataAsync_NotFound_AllowUnknownFalse_ReturnsFailure()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(payload);

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options { AllowUnknownAuthenticators = false };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("AllowUnknownAuthenticators is false");
    }

    [Fact]
    public async Task ValidateAuthenticatorStatusAsync_Trusted_ReturnsSuccess()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Trusted Key" },
                    statusReports = new[]
                    {
                        new { status = "FIDO_CERTIFIED_L3+", effectiveDate = "2026-01-01" }
                    }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.ValidateAuthenticatorStatusAsync(targetAaguid);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAuthenticatorStatusAsync_DisallowedStatus_ReturnsFailure()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Compromised Key" },
                    statusReports = new[]
                    {
                        new { status = "REVOKED", effectiveDate = "2026-05-01" }
                    }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.ValidateAuthenticatorStatusAsync(targetAaguid);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("disallowed status: Revoked");
    }

    [Fact]
    public async Task ValidateAuthenticatorStatusAsync_UnknownAuthenticator_AllowUnknownTrue_ReturnsSuccess()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(payload);

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options { AllowUnknownAuthenticators = true };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.ValidateAuthenticatorStatusAsync(targetAaguid);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAuthenticatorStatusAsync_UnknownAuthenticator_AllowUnknownFalse_ReturnsFailure()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(payload);

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options { AllowUnknownAuthenticators = false };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.ValidateAuthenticatorStatusAsync(targetAaguid);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task LoadMetadata_HttpException_ReturnsFailure()
    {
        var handler = new TestHttpMessageHandler(_ => throw new HttpRequestException("Network failure"));
        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(Guid.NewGuid());
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to fetch FIDO MDS3 BLOB");
    }

    [Fact]
    public async Task LoadMetadata_InvalidJwtFormat_ReturnsFailure()
    {
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("invalid-jwt-without-three-dots", Encoding.UTF8, "application/jwt")
        });
        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(Guid.NewGuid());
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("not a valid JWT");
    }

    [Fact]
    public async Task LoadMetadata_CorruptPayloadBase64_ReturnsFailure()
    {
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("a.???invalid-base64???.c", Encoding.UTF8, "application/jwt")
        });
        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(Guid.NewGuid());
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to decode FIDO MDS3 BLOB JWT payload");
    }

    [Fact]
    public async Task LoadMetadata_InvalidJsonPayload_ReturnsFailure()
    {
        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes("{}")).TrimEnd('=');
        var badPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("{not valid json")).TrimEnd('=');
        var jwt = $"{header}.{badPayload}.sig";

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });
        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(Guid.NewGuid());
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to parse FIDO MDS3 BLOB JSON payload");
    }

    [Fact]
    public async Task RefreshAsync_ForcesReload()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Refreshed Key" },
                    statusReports = Array.Empty<object>()
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        await service.RefreshAsync();
        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Description.Should().Be("Refreshed Key");
    }

    [Fact]
    public async Task Service_CancellationTokenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.GetMetadataAsync(Guid.NewGuid(), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.ValidateAuthenticatorStatusAsync(Guid.NewGuid(), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.RefreshAsync(cts.Token));
    }

    [Theory]
    [InlineData("NOT_FIDO_CERTIFIED", AuthenticatorStatus.NotFidoCertified)]
    [InlineData("FIDO_CERTIFIED", AuthenticatorStatus.FidoCertified)]
    [InlineData("USER_VERIFICATION_BYPASS", AuthenticatorStatus.UserVerificationBypass)]
    [InlineData("ATTESTATION_KEY_COMPROMISE", AuthenticatorStatus.AttestationKeyCompromise)]
    [InlineData("USER_KEY_REMOTE_COMPROMISE", AuthenticatorStatus.UserKeyRemoteCompromise)]
    [InlineData("USER_KEY_PHYSICAL_COMPROMISE", AuthenticatorStatus.UserKeyPhysicalCompromise)]
    [InlineData("UPDATE_AVAILABLE", AuthenticatorStatus.UpdateAvailable)]
    [InlineData("REVOKED", AuthenticatorStatus.Revoked)]
    [InlineData("SELF_ASSERTION_SUBMITTED", AuthenticatorStatus.SelfAssertionSubmitted)]
    [InlineData("FIDO_CERTIFIED_L1+", AuthenticatorStatus.FidoCertifiedL1Plus)]
    [InlineData("FIDO_CERTIFIED_L2", AuthenticatorStatus.FidoCertifiedL2)]
    [InlineData("FIDO_CERTIFIED_L2+", AuthenticatorStatus.FidoCertifiedL2Plus)]
    [InlineData("FIDO_CERTIFIED_L3", AuthenticatorStatus.FidoCertifiedL3)]
    [InlineData("FIDO_CERTIFIED_L3+", AuthenticatorStatus.FidoCertifiedL3Plus)]
    [InlineData("UNKNOWN_STATUS_STRING", AuthenticatorStatus.NotFidoCertified)]
    public async Task ParseEntry_AllStatusValues_ParsedCorrectly(string statusString, AuthenticatorStatus expectedStatus)
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Test Status" },
                    statusReports = new[]
                    {
                        new { status = statusString, effectiveDate = "2026-01-01" }
                    }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsSuccess.Should().BeTrue();
        result.Value.StatusReports[0].Status.Should().Be(expectedStatus);
    }

    [Fact]
    public void Dispose_MultipleCalls_DoesNotThrow()
    {
        var http = new HttpClient();
        var opts = Options.Create(new Mds3Options());
        var service = new HttpMds3MetadataService(http, opts, NullLogger<HttpMds3MetadataService>.Instance);

        service.Dispose();
        service.Dispose(); // idempotent
    }

    [Fact]
    public async Task ParseEntry_MissingOrInvalidTimeOfLastStatusChange_DefaultsToMinValue()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "No Time Key" }
                    // timeOfLastStatusChange omitted
                },
                new
                {
                    // entry with invalid time
                    aaguid = Guid.NewGuid().ToString(),
                    metadataStatement = new { description = "Invalid Time Key" },
                    timeOfLastStatusChange = "invalid-date-string"
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsSuccess.Should().BeTrue();
        result.Value.TimeOfLastStatusChange.Should().Be(DateTimeOffset.MinValue);
    }

    [Fact]
    public async Task EnsureCacheLoadedAsync_ConcurrentCalls_TakesDoubleCheckedLockingBranch()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Concurrent Test" }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref fetchCount);
            Thread.Sleep(30);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
            };
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var task1 = Task.Run(() => service.GetMetadataAsync(targetAaguid));
        var task2 = Task.Run(() => service.GetMetadataAsync(targetAaguid));
        var task3 = Task.Run(() => service.GetMetadataAsync(targetAaguid));

        var results = await Task.WhenAll(task1, task2, task3);
        foreach (var r in results)
        {
            r.IsSuccess.Should().BeTrue();
            r.Value.Description.Should().Be("Concurrent Test");
        }
        fetchCount.Should().Be(1);
    }

    [Fact]
    public async Task GetMetadataAsync_NullDescriptionAndNullEffectiveDate_ReturnsDefaultValues()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new
                    {
                        description = (string?)null
                    },
                    statusReports = new object[]
                    {
                        new
                        {
                            status = "FIDO_CERTIFIED",
                            effectiveDate = "2026-09-03"
                        },
                        new
                        {
                            status = "FIDO_CERTIFIED",
                            effectiveDate = (string?)null
                        },
                        new
                        {
                            status = "FIDO_CERTIFIED"
                        }
                    }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);

        result.IsSuccess.Should().BeTrue();
        result.Value.Description.Should().Be("Unknown authenticator");
        result.Value.StatusReports[0].EffectiveDate.Should().Be("2026-09-03");
        result.Value.StatusReports[1].EffectiveDate.Should().Be(string.Empty);
        result.Value.StatusReports[2].EffectiveDate.Should().Be(string.Empty);
    }

    [Fact]
    public void ParseEntry_BoundaryPayloads_HandlesMissingFieldsAndMalformedJsonSafely()
    {
        // 1. Entry without aaguid returns null (FIDO-U2F / key identifier)
        using var docNoAaguid = JsonDocument.Parse("{\"metadataStatement\":{\"description\":\"u2f\"}}");
        var resNoAaguid = HttpMds3MetadataService.ParseEntry(docNoAaguid.RootElement);
        resNoAaguid.Should().BeNull();

        // 2. Entry with valid timeOfLastStatusChange
        var aaguid = Guid.NewGuid();
        var jsonValidTime = $"{{\"aaguid\":\"{aaguid}\",\"timeOfLastStatusChange\":\"2026-09-03T12:00:00Z\",\"metadataStatement\":{{\"description\":\"Test\"}}}}";
        using var docValidTime = JsonDocument.Parse(jsonValidTime);
        var resValidTime = HttpMds3MetadataService.ParseEntry(docValidTime.RootElement);
        resValidTime.Should().NotBeNull();
        resValidTime!.TimeOfLastStatusChange.Should().Be(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));

        // 3. Malformed JSON element (non-object) returns null via catch block
        using var docNonObject = JsonDocument.Parse("12345");
        var resNonObject = HttpMds3MetadataService.ParseEntry(docNonObject.RootElement);
        resNonObject.Should().BeNull();
    }

    [Theory]
    [InlineData("NOT_FIDO_CERTIFIED", AuthenticatorStatus.NotFidoCertified)]
    [InlineData("FIDO_CERTIFIED", AuthenticatorStatus.FidoCertified)]
    [InlineData("USER_VERIFICATION_BYPASS", AuthenticatorStatus.UserVerificationBypass)]
    [InlineData("ATTESTATION_KEY_COMPROMISE", AuthenticatorStatus.AttestationKeyCompromise)]
    [InlineData("USER_KEY_REMOTE_COMPROMISE", AuthenticatorStatus.UserKeyRemoteCompromise)]
    [InlineData("USER_KEY_PHYSICAL_COMPROMISE", AuthenticatorStatus.UserKeyPhysicalCompromise)]
    [InlineData("UPDATE_AVAILABLE", AuthenticatorStatus.UpdateAvailable)]
    [InlineData("REVOKED", AuthenticatorStatus.Revoked)]
    [InlineData("SELF_ASSERTION_SUBMITTED", AuthenticatorStatus.SelfAssertionSubmitted)]
    [InlineData("FIDO_CERTIFIED_L1+", AuthenticatorStatus.FidoCertifiedL1Plus)]
    [InlineData("FIDO_CERTIFIED_L2", AuthenticatorStatus.FidoCertifiedL2)]
    [InlineData("FIDO_CERTIFIED_L2+", AuthenticatorStatus.FidoCertifiedL2Plus)]
    [InlineData("FIDO_CERTIFIED_L3", AuthenticatorStatus.FidoCertifiedL3)]
    [InlineData("FIDO_CERTIFIED_L3+", AuthenticatorStatus.FidoCertifiedL3Plus)]
    [InlineData("UNKNOWN_CUSTOM_STATUS", AuthenticatorStatus.NotFidoCertified)]
    public void ParseEntry_MapsAllAuthenticatorStatusValues(string statusStr, AuthenticatorStatus expected)
    {
        var aaguid = Guid.NewGuid();
        var json = $$"""
        {
            "aaguid": "{{aaguid}}",
            "metadataStatement": { "description": "Status Test" },
            "statusReports": [
                {
                    "status": "{{statusStr}}",
                    "effectiveDate": "2026-09-03",
                    "url": "https://fidoalliance.org/report",
                    "certificate": "MIIC...",
                    "certificationLevel": "L3"
                }
            ]
        }
        """;
        using var doc = JsonDocument.Parse(json);
        var res = HttpMds3MetadataService.ParseEntry(doc.RootElement);
        res.Should().NotBeNull();
        res!.StatusReports.Should().HaveCount(1);
        res.StatusReports[0].Status.Should().Be(expected);
        res.StatusReports[0].Url.Should().Be("https://fidoalliance.org/report");
        res.StatusReports[0].Certificate.Should().Be("MIIC...");
        res.StatusReports[0].CertificationLevel.Should().Be("L3");
    }

    [Fact]
    public async Task EnsureCacheLoadedAsync_WithTimeProvider_ExpiresAndRefreshesCache()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Cache Test Authenticator" }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref fetchCount);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
            };
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options
        {
            CacheDuration = TimeSpan.FromHours(1)
        };

        var fakeTime = new FakeTimeProvider(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        using var service = new HttpMds3MetadataService(
            client,
            Options.Create(options),
            NullLogger<HttpMds3MetadataService>.Instance,
            fakeTime);

        // First call: fetches from HTTP
        var result1 = await service.GetMetadataAsync(targetAaguid);
        result1.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(1);

        // Advance time by 30 min (within cache lifetime)
        fakeTime.Advance(TimeSpan.FromMinutes(30));
        var result2 = await service.GetMetadataAsync(targetAaguid);
        result2.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(1); // cache hit, no new fetch

        // Advance time past 1 hour (cache expires)
        fakeTime.Advance(TimeSpan.FromMinutes(40));
        var result3 = await service.GetMetadataAsync(targetAaguid);
        result3.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(2); // cache expired, fresh fetch triggered!
    }

    [Fact]
    public async Task Dispose_DisposesResources_IsIdempotentAndDisposesSemaphore()
    {
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = new HttpClient(handler);
        var options = Options.Create(new Mds3Options());
        var service = new HttpMds3MetadataService(client, options, NullLogger<HttpMds3MetadataService>.Instance);

        // Initial dispose
        service.Dispose();

        // Idempotent dispose
        service.Dispose();

        // Ensure underlying semaphore was actually disposed directly
        var semField = typeof(HttpMds3MetadataService).GetField("_refreshLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var sem = (SemaphoreSlim)semField!.GetValue(service)!;
        Assert.Throws<ObjectDisposedException>(() => sem.AvailableWaitHandle);

        // Ensure EnsureCacheLoadedAsync throws ObjectDisposedException with service type name
        var ex = await Assert.ThrowsAsync<ObjectDisposedException>(() => service.GetMetadataAsync(Guid.NewGuid()));
        ex.ObjectName.Should().Be(typeof(HttpMds3MetadataService).FullName);
    }

    [Fact]
    public async Task ParsePayload_NonObjectMetadataStatement_DoesNotThrowAndParsesSuccessfully()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = "not-an-object-string",
                    statusReports = new object[]
                    {
                        new { status = "FIDO_CERTIFIED", effectiveDate = "2024-01-01" }
                    }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });
        var client = new HttpClient(handler);
        var options = Options.Create(new Mds3Options());
        using var service = new HttpMds3MetadataService(client, options, NullLogger<HttpMds3MetadataService>.Instance);

        var result = await service.GetMetadataAsync(targetAaguid);
        result.IsSuccess.Should().BeTrue();
        result.Value.Description.Should().Be("Unknown authenticator");
    }

    [Fact]
    public async Task LoadMetadataAsync_HttpRequestException_LogsErrorAndReturnsFailure()
    {
        var fakeLogger = new FakeLogger<HttpMds3MetadataService>();
        var handler = new TestHttpMessageHandler(_ => throw new HttpRequestException("Connection refused"));
        var client = new HttpClient(handler);
        var options = Options.Create(new Mds3Options());
        using var service = new HttpMds3MetadataService(client, options, fakeLogger);

        var result = await service.GetMetadataAsync(Guid.NewGuid());
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to fetch FIDO MDS3 BLOB");
        result.Error.Description.Should().Contain("Connection refused");

        fakeLogger.HasMessage(LogLevel.Error, "Failed to download FIDO MDS3 BLOB").Should().BeTrue();
    }

    [Fact]
    public async Task EnsureCacheLoadedAsync_CacheExpiryBoundary_RefreshesWhenExpired()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Cache Test" }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref fetchCount);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
            };
        });

        var client = new HttpClient(handler);
        var timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero));
        var options = new Mds3Options
        {
            CacheDuration = TimeSpan.FromHours(1)
        };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance, timeProvider);

        // 1. Initial load -> fetchCount = 1
        var r1 = await service.GetMetadataAsync(targetAaguid);
        r1.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(1);

        // 2. Advance to 59 minutes -> still cached (fast path) -> fetchCount = 1
        timeProvider.Advance(TimeSpan.FromMinutes(59));
        var r2 = await service.GetMetadataAsync(targetAaguid);
        r2.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(1);

        // 3. Advance to exactly 1 hour (expiry point: GetUtcNow() == _cacheExpiresAt)
        // Original code: GetUtcNow() < _cacheExpiresAt is false -> refreshes -> fetchCount = 2
        // Mutated code (<=): GetUtcNow() <= _cacheExpiresAt is true -> doesn't refresh -> fetchCount remains 1!
        timeProvider.Advance(TimeSpan.FromMinutes(1));
        var r3 = await service.GetMetadataAsync(targetAaguid);
        r3.IsSuccess.Should().BeTrue();
        fetchCount.Should().Be(2);
    }

    [Fact]
    public async Task EnsureCacheLoadedAsync_EmptyCacheEntries_DoesNotCacheEmptyState()
    {
        var emptyPayload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(emptyPayload);
        var fetchCount = 0;
        var handler = new TestHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref fetchCount);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
            };
        });

        var client = new HttpClient(handler);
        var timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero));
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance, timeProvider);

        var aaguid = Guid.NewGuid();
        var r1 = await service.GetMetadataAsync(aaguid);
        r1.IsFailure.Should().BeTrue();
        fetchCount.Should().Be(1);

        // Second call: because cache is empty (Count == 0), original code does NOT treat cache as valid and retries fetch.
        // Mutated code (Count >= 0) treats empty cache as valid and does NOT fetch.
        var r2 = await service.GetMetadataAsync(aaguid);
        r2.IsFailure.Should().BeTrue();
        fetchCount.Should().Be(2);
    }

    [Fact]
    public async Task EnsureCacheLoadedAsync_ValidCache_DoesNotBlockOnCancelledTokenOnFastPath()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Fast Path Test" }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), NullLogger<HttpMds3MetadataService>.Instance);

        // 1. Warm cache
        var r1 = await service.GetMetadataAsync(targetAaguid);
        r1.IsSuccess.Should().BeTrue();

        // 2. Fast path with already cancelled token: should NOT call _refreshLock.WaitAsync(ct) which would throw
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var r2 = await service.GetMetadataAsync(targetAaguid, cts.Token);
        r2.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task GetMetadataAsync_AllowUnknownTrue_LogsDebugMessage()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new { entries = Array.Empty<object>() };
        var jwt = BuildMds3Jwt(payload);

        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var fakeLogger = new FakeLogger<HttpMds3MetadataService>();
        var options = new Mds3Options { AllowUnknownAuthenticators = true };
        using var service = new HttpMds3MetadataService(client, Options.Create(options), fakeLogger);

        var result = await service.GetMetadataAsync(targetAaguid);
        result.IsFailure.Should().BeTrue();
        fakeLogger.HasMessage(LogLevel.Debug, "AllowUnknownAuthenticators=true, proceeding.").Should().BeTrue();
    }

    [Fact]
    public async Task LoadMetadataAsync_FetchBlob_LogsInformationMessage()
    {
        var targetAaguid = Guid.NewGuid();
        var payload = new
        {
            entries = new object[]
            {
                new
                {
                    aaguid = targetAaguid.ToString(),
                    metadataStatement = new { description = "Log Info Test" }
                }
            }
        };

        var jwt = BuildMds3Jwt(payload);
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(jwt, Encoding.UTF8, "application/jwt")
        });

        var client = new HttpClient(handler);
        var fakeLogger = new FakeLogger<HttpMds3MetadataService>();
        var options = new Mds3Options();
        using var service = new HttpMds3MetadataService(client, Options.Create(options), fakeLogger);

        var result = await service.GetMetadataAsync(targetAaguid);
        result.IsSuccess.Should().BeTrue();
        fakeLogger.HasMessage(LogLevel.Information, "Fetching FIDO MDS3 BLOB from").Should().BeTrue();
    }
}

