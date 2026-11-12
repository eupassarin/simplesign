using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>
/// Two-phase CAdES signing: the server prepares with the public certificate, another machine signs the
/// signed attributes, and a builder resumed from the stored session completes the signature.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CadesDeferredSignerTests : IDisposable
{
    private const string TsaUrl = "http://198.51.100.1/tsa";
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);

    private readonly byte[] _data = "content signed in two phases"u8.ToArray();
    private readonly X509Certificate2 _rsa = TestCertificateFactory.CreateSelfSignedCert();
    private readonly X509Certificate2 _ecdsa = TestCertificateFactory.CreateEcdsaCert();
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly List<AuthenticationHeaderValue?> _tsaAuthorizations = [];
    private readonly HttpClient _http;

    public CadesDeferredSignerTests()
    {
        byte[] leafCrl = _pki.BuildLeafCrl();
        byte[] intermediateCrl = _pki.BuildIntermediateCrl();
        _http = new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                _tsaAuthorizations.Add(request.Headers.Authorization);
                byte[] tsq = await request.Content!.ReadAsByteArrayAsync();
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(tsq)) };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return response;
            }

            byte[]? crl = request.RequestUri?.ToString() switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            return crl is null ? new HttpResponseMessage(HttpStatusCode.NotFound) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
        }));
    }

    public void Dispose()
    {
        _http.Dispose();
        _pki.Dispose();
        _rsa.Dispose();
        _ecdsa.Dispose();
    }

    private SingleClientProvider Http => new(_http);

    private X509Certificate2 Signer(bool ecdsa) => ecdsa ? _ecdsa : _rsa;

    // ── Round trip, every form and level ──────────────────────────────────

    [Theory]
    [InlineData(CadesContentType.Detached, false)]
    [InlineData(CadesContentType.Detached, true)]
    [InlineData(CadesContentType.Enveloped, false)]
    [InlineData(CadesContentType.Enveloped, true)]
    public async Task CompleteAsync_BasicLevel_ValidatesForEachContentTypeAndKey(CadesContentType contentType, bool ecdsa)
    {
        X509Certificate2 signer = Signer(ecdsa);
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(signer);

        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithContentType(contentType)
            .PrepareAsync();
        byte[] signature = RemoteKey.Sign(signer, prepared.ToSigningRequest());

        // Another process: only the session bytes and the key cross over.
        byte[] cms = await CadesDeferredSigner.Resume([.. prepared.SessionData], s_key).CompleteAsync(signature);

        var validation = new CadesSignatureValidator().Validate(cms, _data, [signer]);
        validation.Errors.ShouldBeEmpty();
        validation.IsValid.ShouldBeTrue();
        CmsParser.ParseAll(cms).EncapsulatedContent.ShouldBe(contentType == CadesContentType.Enveloped ? _data : null);
        CmsParser.Parse(cms).SignedAttrs.ShouldBe(prepared.DataToSign);
    }

    [Theory]
    [InlineData(CadesContentType.Detached)]
    [InlineData(CadesContentType.Enveloped)]
    public async Task CompleteWithDetailsAsync_TimestampedLevel_EmbedsTheSignatureTimestamp(CadesContentType contentType)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithContentType(contentType)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .PrepareAsync();

        CadesSigningResult result = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
        var validation = new CadesSignatureValidator().Validate(result.SignedArtifact, _data, [_rsa]);
        validation.IsValid.ShouldBeTrue(string.Join("; ", validation.Errors));
        validation.HasValidTimestamp.ShouldBe(true);
    }

    [Theory]
    [InlineData(CadesContentType.Detached, false)]
    [InlineData(CadesContentType.Detached, true)]
    [InlineData(CadesContentType.Enveloped, true)]
    public async Task CompleteWithDetailsAsync_LongTermAndArchiveLevels_AreFinishedInPhaseTwo(CadesContentType contentType, bool archive)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        var tsa = new TimestampOptions(new Uri(TsaUrl));
        var validation = new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst };
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithContentType(contentType)
            .WithLevel(archive ? AdesBaselineProfile.Archive(tsa, validation) : AdesBaselineProfile.LongTerm(tsa, validation))
            .PrepareAsync();

        CadesSigningResult result = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        result.AchievedLevel.ShouldBe(archive ? AdesBaselineLevel.Archive : AdesBaselineLevel.LongTerm);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
        result.HasArchiveTimestamp.ShouldBe(archive);
        var validated = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
            .Validate(result.SignedArtifact, _data, [_pki.IntermediateCa, _pki.RootCa]);
        validated.IsValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.IsLtvDataValid.ShouldBe(true);
        if (archive)
        {
            validated.HasValidArchiveTimestamp.ShouldBe(true);
        }
    }

    [Fact]
    public async Task CompleteWithDetailsAsync_ExtendedForm_TravelsInTheSession()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .WithExtendedValidationData(CadesExtendedForm.Archive)
            .PrepareAsync();

        CadesSigningResult result = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        var validated = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
            .Validate(result.SignedArtifact, _data, [_pki.IntermediateCa, _pki.RootCa]);
        validated.Errors.ShouldBeEmpty();
        validated.HasValidArchiveTimestamp.ShouldBe(true);
        CmsParser.Parse(result.SignedArtifact).UnsignedAttributes.ShouldNotBeNull().ContainsKey(Oids.ArchiveTimeStamp).ShouldBeTrue();
    }

    [Fact]
    public async Task PrepareAsync_ExtendedFormWithoutTimestamp_IsRefusedBeforeAnythingIsSigned()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);

        var ex = await Should.ThrowAsync<SigningException>(() => CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithExtendedValidationData(CadesExtendedForm.CompleteReferences)
            .PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task CompleteAsync_RsaPss_UsesTheParametersOfTheSigningRequest()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithSignatureAlgorithm(Oids.RsaPss)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .WithOperationId("op-pss")
            .PrepareAsync();

        ExternalSigningRequest request = prepared.ToSigningRequest();
        request.PayloadKind.ShouldBe(ExternalSigningPayloadKind.CmsSignedAttributes);
        request.SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
        request.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA384);
        request.RsaPssParameters.ShouldNotBeNull().HashAlgorithm.ShouldBe(HashAlgorithmName.SHA384);
        request.OperationId.ShouldBe("op-pss");
        prepared.DigestAlgorithm.ShouldBe("SHA384");

        byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, s_key).CompleteAsync(RemoteKey.Sign(_rsa, request));

        new CadesSignatureValidator().Validate(cms, _data, [_rsa]).IsValid.ShouldBeTrue();
        CmsParser.Parse(cms).SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
    }

    // ── What is signed is fixed in phase one ──────────────────────────────

    [Fact]
    public async Task PrepareAsync_SignedAttributeOptions_AreInTheCompletedSignature()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var signingTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600);
        byte[] policyDocument = "a signature policy document"u8.ToArray();
        var policy = new SignaturePolicyReference("2.16.76.1.7.1.1.2.3", Oids.Sha256, SHA256.HashData(policyDocument), "https://example.com/policy.der");

        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithSigningTime(signingTime)
            .WithCommitmentType(CommitmentType.ProofOfApproval)
            .WithSignaturePolicy(policy)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument("1.2.3.4.5.1", policyDocument))
            .WithSignerRole("Approver")
            .WithMimeType("application/pdf")
            .WithSignerLocation(new CadesSignerLocation { CountryName = "PE", LocalityName = "Lima" })
            .WithContentHints(new CadesContentHints { Description = "contract" })
            .PrepareAsync();

        byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        CmsSignedData parsed = CmsParser.Parse(cms);
        parsed.SigningTime.ShouldBe(signingTime);
        parsed.CommitmentTypeOid.ShouldNotBeNull();
        parsed.SignaturePolicyOid.ShouldBe(policy.Oid);
        CadesSignedAttributes attributes = CadesSignedAttributes.Read(parsed.SignedAttrs);
        attributes.ClaimedRoles.ShouldBe(["Approver"]);
        attributes.MimeType.ShouldBe("application/pdf");
        attributes.SignerLocation.ShouldNotBeNull().LocalityName.ShouldBe("Lima");
        attributes.ContentHints.ShouldNotBeNull().Description.ShouldBe("contract");
        var store = CadesSignaturePolicyStore.Read(parsed).ShouldNotBeNull();
        store.Document.ToArray().ShouldBe(policyDocument);
        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_rsa]);
        report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
    }

    [Fact]
    public async Task PrepareAsync_ContentTimestamp_IsRequestedInPhaseOneAndSigned()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);

        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithContentTimestamp(new TimestampOptions(new Uri(TsaUrl), Http))
            .PrepareAsync();

        _tsaAuthorizations.Count.ShouldBe(1);
        byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));
        _tsaAuthorizations.Count.ShouldBe(1);
        new CadesSignatureValidator().Validate(cms, _data, [_rsa]).HasValidContentTimestamp.ShouldBe(true);
    }

    [Fact]
    public async Task PhaseOneMethods_OnAResumedBuilder_Throw()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();
        CadesDeferredSignerBuilder resumed = CadesDeferredSigner.Resume(prepared.SessionData, s_key);

        Should.Throw<InvalidOperationException>(() => resumed.WithCertificate(publicCertificate));
        Should.Throw<InvalidOperationException>(() => resumed.WithSigningTime(DateTimeOffset.UtcNow));
        Should.Throw<InvalidOperationException>(() => resumed.WithCommitmentType(CommitmentType.ProofOfOrigin));
        Should.Throw<InvalidOperationException>(() => resumed.WithContentType(CadesContentType.Enveloped));
        Should.Throw<InvalidOperationException>(() => resumed.WithLevel(AdesBaselineProfile.Basic()));
        Should.Throw<InvalidOperationException>(() => resumed.WithSessionIntegrityKey(s_key));
        await Should.ThrowAsync<InvalidOperationException>(() => resumed.PrepareAsync());
        resumed.SignerCertificate.ShouldBeNull();
    }

    [Fact]
    public async Task CompleteAsync_OnABuilderThatWasNotResumed_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredSignerBuilder builder = CadesDeferredSigner.Document(_data).WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key);

        await Should.ThrowAsync<InvalidOperationException>(() => builder.CompleteAsync([1, 2, 3]));
        Should.Throw<InvalidOperationException>(() => builder.WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl))));
    }

    // ── The session ───────────────────────────────────────────────────────

    [Fact]
    public async Task Resume_TamperedSession_IsRefused()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();

        // Turn the detached signature into an attached one without touching the HMAC.
        string json = Encoding.UTF8.GetString(prepared.SessionData);
        byte[] tampered = Encoding.UTF8.GetBytes(json.Replace("\"session\":{", "\"session\":{\"Attached\":true,", StringComparison.Ordinal));

        tampered.ShouldNotBe(prepared.SessionData);
        Should.Throw<CryptographicException>(() => CadesDeferredSigner.Resume(tampered, s_key));
    }

    [Fact]
    public async Task Resume_AnotherKeyOrAnotherFormat_IsRefused()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();

        Should.Throw<CryptographicException>(() => CadesDeferredSigner.Resume(prepared.SessionData, RandomNumberGenerator.GetBytes(32)));
        Should.Throw<ArgumentException>(() => CadesDeferredSigner.Resume(prepared.SessionData, new byte[16]));
        Should.Throw<ArgumentException>(() => CadesDeferredSigner.Resume("{\"format\":\"XAdES\",\"version\":1}"u8.ToArray(), s_key));
        Should.Throw<ArgumentException>(() => CadesDeferredSigner.Resume("not a session"u8.ToArray(), s_key));
    }

    [Fact]
    public async Task SessionData_OptionalFieldsAtTheirDefault_AreNotWritten()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();

        string json = Encoding.UTF8.GetString(prepared.SessionData);
        foreach (string optional in new[] { "Attached", "ExtraCertificatesDer", "TimestampEndpoint", "ArchiveTimestampEndpoint", "RevocationPreference", "ClockSkewSeconds", "ExtendedForm", "PolicyStoreAttribute", "OperationId" })
        {
            json.ShouldNotContain($"\"{optional}\"");
        }
    }

    [Fact]
    public async Task Resume_SessionOfAnotherVersion_StillCompletes()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).WithOperationId("op-1").PrepareAsync();

        // A later version wrote a field this one does not know; an earlier one did not write OperationId.
        byte[] session = RemoteKey.RewriteSession(prepared.SessionData, s_key, s =>
        {
            s["FieldOfALaterVersion"] = "value";
            s.Remove("OperationId").ShouldBeTrue();
        });

        byte[] cms = await CadesDeferredSigner.Resume(session, s_key).CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        new CadesSignatureValidator().Validate(cms, _data, [_rsa]).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task SessionData_LongTermValidationSettings_AreRestored()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var validation = new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst, ClockSkewTolerance = TimeSpan.FromSeconds(42) };
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithLevel(AdesBaselineProfile.Archive(new TimestampOptions(new Uri(TsaUrl)), validation, new ArchiveTimestampOptions(new Uri("http://198.51.100.1/archive-tsa"))))
            .PrepareAsync();

        CadesDeferredSession session = CadesDeferredSession.Read(prepared.SessionData, s_key);

        session.RequestedLevel.ShouldBe(AdesBaselineLevel.Archive);
        session.TimestampEndpoint.ShouldBe(TsaUrl);
        session.ArchiveTimestampEndpoint.ShouldBe("http://198.51.100.1/archive-tsa");
        AdesBaselineProfile restored = CadesSignerBuilder.ForDeferredCompletion(session).Profile;
        restored.LongTermValidation.ShouldNotBeNull().RevocationPreference.ShouldBe(RevocationPreference.CrlFirst);
        restored.LongTermValidation.ClockSkewTolerance.ShouldBe(TimeSpan.FromSeconds(42));
        restored.ArchiveTimestamp.ShouldNotBeNull().Endpoint.ShouldBe(new Uri("http://198.51.100.1/archive-tsa"));
    }

    // ── The signature ─────────────────────────────────────────────────────

    [Fact]
    public async Task CompleteAsync_SignatureOfAnotherKey_IsRefusedAndAudited()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        using X509Certificate2 other = TestCertificateFactory.CreateSelfSignedCert("CN=Another key");
        var audit = new RecordingAuditSink();
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).WithOperationId("op-wrong-key").PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(() => CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithAuditSink(audit)
            .CompleteAsync(RemoteKey.Sign(other, prepared.ToSigningRequest())));

        ex.Reason.ShouldBe(SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Signed.ShouldBeFalse();
        refused.Reason.ShouldBe(SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        refused.OperationId.ShouldBe("op-wrong-key");
    }

    [Fact]
    public async Task CompleteAsync_EmptyOrNullSignature_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();
        CadesDeferredSignerBuilder resumed = CadesDeferredSigner.Resume(prepared.SessionData, s_key);

        await Should.ThrowAsync<ArgumentException>(() => resumed.CompleteAsync([]));
        await Should.ThrowAsync<ArgumentNullException>(() => resumed.CompleteAsync(null!));
    }

    // ── Signing policy and audit ──────────────────────────────────────────

    [Fact]
    public async Task PrepareAsync_PolicyRefusal_IsAuditedAndNothingIsHandedOut()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        using var revoked = new HttpClient(new MockHttpHandler(request => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(request.RequestUri!.ToString() == LeafCrlUrl ? _pki.BuildRevokedLeafCrl() : _pki.BuildIntermediateCrl()),
        })));
        var audit = new RecordingAuditSink();

        var ex = await Should.ThrowAsync<SigningException>(() => CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithRevocation)
            .WithHttpClientProvider(new SingleClientProvider(revoked))
            .WithAuditSink(audit)
            .WithOperationId("op-revoked")
            .PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Format.ShouldBe("CAdES");
        refused.Signed.ShouldBeFalse();
        refused.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        refused.OperationId.ShouldBe("op-revoked");
        refused.CertificateSubject.ShouldBe(_pki.Leaf.Subject);
        refused.PolicyName.ShouldBe(TestPolicies.SigningWithRevocation.Name);
    }

    [Fact]
    public async Task PrepareAsync_TrustAnchorRequired_AcceptsOnlyAChainToAGivenAnchor()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        CadesDeferredSignerBuilder builder = CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate, [_pki.IntermediateCa])
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithTrustAnchor);

        await Should.ThrowAsync<SigningException>(() => builder.PrepareAsync());
        CadesDeferredPrepareResult prepared = await builder.WithTrustAnchors(new InMemoryTrustAnchors(_pki.RootCa)).PrepareAsync();

        prepared.DataToSign.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task CompleteAsync_Success_IsAuditedWithTheOperationIdOfPhaseOne()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var prepareAudit = new RecordingAuditSink();
        var completeAudit = new RecordingAuditSink();
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithAuditSink(prepareAudit)
            .WithOperationId("op-42")
            .PrepareAsync();

        byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithAuditSink(completeAudit)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        // Preparing signs nothing: only the completion is a signature.
        prepareAudit.Events.ShouldBeEmpty();
        SignatureAuditEvent signed = completeAudit.Events.ShouldHaveSingleItem();
        signed.Signed.ShouldBeTrue();
        signed.OperationId.ShouldBe("op-42");
        signed.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        signed.CertificateSha256.ShouldBe(Convert.ToHexString(_rsa.GetCertHash(HashAlgorithmName.SHA256)));
        signed.InputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(_data)));
        signed.OutputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(cms)));
    }

    [Fact]
    public async Task WithOperationId_OnTheResumedBuilder_ReplacesTheOneOfTheSession()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var audit = new RecordingAuditSink();
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).WithOperationId("phase-one").PrepareAsync();

        await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithAuditSink(audit)
            .WithOperationId("phase-two")
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        audit.Events.ShouldHaveSingleItem().OperationId.ShouldBe("phase-two");
    }

    // ── What the session cannot store ─────────────────────────────────────

    [Fact]
    public async Task WithTimestampOptions_OnTheResumedBuilder_SendsTheCredentialsToTheTsa()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)) { Authorization = new AuthenticationHeaderValue("Bearer", "secret") }))
            .PrepareAsync();

        Encoding.UTF8.GetString(prepared.SessionData).ShouldNotContain("secret");
        CadesSigningResult result = await CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl), Http) { Authorization = new AuthenticationHeaderValue("Bearer", "secret") })
            .CompleteWithDetailsAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        result.HasSignatureTimestamp.ShouldBeTrue();
        _tsaAuthorizations.ShouldHaveSingleItem().ShouldNotBeNull().Parameter.ShouldBe("secret");
    }

    [Fact]
    public async Task WithTimestampOptions_AnotherEndpointOrASessionWithoutTimestamp_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        CadesDeferredSignerBuilder builder = CadesDeferredSigner.Document(_data).WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key);
        CadesDeferredPrepareResult timestamped = await builder
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)))).PrepareAsync();
        CadesDeferredPrepareResult basic = await builder.PrepareAsync();

        Should.Throw<ArgumentException>(() => CadesDeferredSigner.Resume(timestamped.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri("http://198.51.100.9/other-tsa"))));
        Should.Throw<InvalidOperationException>(() => CadesDeferredSigner.Resume(basic.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl))));
    }

    [Fact]
    public async Task CompleteAsync_ProfileThatMayReturnALowerLevel_NeedsTheDetailedResult()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        using HttpClient failing = MockHttpHandler.Failing();
        CadesDeferredPrepareResult prepared = await CadesDeferredSigner.Document(_data)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)), SigningLevelFailureBehavior.ReturnLowerLevel))
            .PrepareAsync();
        byte[] signature = RemoteKey.Sign(_rsa, prepared.ToSigningRequest());
        CadesDeferredSignerBuilder resumed = CadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(failing));

        var ex = await Should.ThrowAsync<SigningException>(() => resumed.CompleteAsync(signature));
        CadesSigningResult result = await resumed.CompleteWithDetailsAsync(signature);

        ex.Reason.ShouldBe(SigningErrorReason.DowngradeRequiresDetailedResult);
        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);
    }

    // ── What phase one needs ──────────────────────────────────────────────

    [Fact]
    public async Task PrepareAsync_WithoutCertificateOrSessionKey_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);

        var noCertificate = await Should.ThrowAsync<SigningException>(() =>
            CadesDeferredSigner.Document(_data).WithSessionIntegrityKey(s_key).PrepareAsync());
        var noKey = await Should.ThrowAsync<SigningException>(() =>
            CadesDeferredSigner.Document(_data).WithCertificate(publicCertificate).PrepareAsync());

        noCertificate.Reason.ShouldBe(SigningErrorReason.CredentialMissing);
        noKey.Reason.ShouldBe(SigningErrorReason.LevelDependenciesMissing);
        Should.Throw<ArgumentException>(() => CadesDeferredSigner.Document(_data).WithSessionIntegrityKey(new byte[31]));
    }

    [Fact]
    public async Task PrepareAsync_ExpiredCertificate_IsRefused()
    {
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Expired", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 expired = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(-1));
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(expired);

        var ex = await Should.ThrowAsync<SigningException>(() =>
            CadesDeferredSigner.Document(_data).WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
    }
}
