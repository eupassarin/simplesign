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
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// Two-phase XAdES signing: the server prepares with the public certificate, another machine signs the
/// canonical SignedInfo, and a builder resumed from the stored session completes the signature.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesDeferredSignerTests : IDisposable
{
    private const string TsaUrl = "http://198.51.100.1/tsa";
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private const string DataUri = "document.xml";
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);

    private readonly byte[] _xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><order><id>42</id><item>two phases</item></order>"u8.ToArray();
    private readonly X509Certificate2 _rsa = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Deferred RSA, O=Tests");
    private readonly X509Certificate2 _ecdsa = TestCertificateFactory.CreateEcdsaCert(subject: "CN=XAdES Deferred ECDSA, O=Tests");
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly List<AuthenticationHeaderValue?> _tsaAuthorizations = [];
    private readonly HttpClient _http;

    public XadesDeferredSignerTests()
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

    private XadesDeferredSignerBuilder Prepare(X509Certificate2 publicCertificate, XadesForm form = XadesForm.Enveloped)
    {
        XadesDeferredSignerBuilder builder = XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate)
            .WithSessionIntegrityKey(s_key)
            .WithForm(form);
        return form == XadesForm.Detached ? builder.WithDataUri(DataUri) : builder;
    }

    private XadesValidationResult Validate(byte[] signed, XadesForm form, params X509Certificate2[] anchors) =>
        new XadesSignatureValidator().Validate(signed, anchors, form == XadesForm.Detached ? _xml : null);

    /// <summary>The r || s form of a P-256 ECDSA signature given as a DER SEQUENCE.</summary>
    private static byte[] P1363(byte[] der)
    {
        var sequence = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER).ReadSequence();
        byte[] value = new byte[64];
        foreach (int end in new[] { 32, 64 })
        {
            ReadOnlySpan<byte> integer = sequence.ReadIntegerBytes().Span.TrimStart((byte)0);
            integer.CopyTo(value.AsSpan(end - integer.Length));
        }

        return value;
    }

    // ── Round trip, every form and level ──────────────────────────────────

    [Theory]
    [InlineData(XadesForm.Enveloped, false)]
    [InlineData(XadesForm.Enveloped, true)]
    [InlineData(XadesForm.Enveloping, false)]
    [InlineData(XadesForm.Enveloping, true)]
    [InlineData(XadesForm.Detached, false)]
    [InlineData(XadesForm.Detached, true)]
    public async Task CompleteAsync_BasicLevel_ValidatesForEachFormAndKey(XadesForm form, bool ecdsa)
    {
        X509Certificate2 signer = Signer(ecdsa);
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(signer);

        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate, form).PrepareAsync();
        byte[] signature = RemoteKey.Sign(signer, prepared.ToSigningRequest());

        // Another process: only the session bytes and the key cross over.
        byte[] signed = await XadesDeferredSigner.Resume([.. prepared.SessionData], s_key).CompleteAsync(signature);

        XadesValidationResult validation = Validate(signed, form, signer);
        validation.Errors.ShouldBeEmpty();
        validation.IsValid.ShouldBeTrue();
        // RSA goes in as it came; ECDSA arrives as a DER SEQUENCE and is written as r || s.
        string signatureValue = Convert.ToBase64String(ecdsa ? P1363(signature) : signature);
        Encoding.UTF8.GetString(signed).ShouldContain(signatureValue);
        if (form == XadesForm.Detached)
        {
            Encoding.UTF8.GetString(signed).ShouldNotContain("two phases");
            new XadesSignatureValidator().Validate(signed, [signer], "<other/>"u8.ToArray()).IsValid.ShouldBeFalse();
        }
    }

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Enveloping)]
    [InlineData(XadesForm.Detached)]
    public async Task CompleteWithDetailsAsync_TimestampedLevel_EmbedsTheSignatureTimestamp(XadesForm form)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate, form)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .PrepareAsync();

        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.HasSignatureTimestamp.ShouldBeTrue();
        XadesValidationResult validation = Validate(result.SignedArtifact, form, _rsa);
        validation.IsValid.ShouldBeTrue(string.Join("; ", validation.Errors));
        validation.HasValidSignatureTimeStamp.ShouldBe(true);
    }

    [Theory]
    [InlineData(XadesForm.Enveloped, false)]
    [InlineData(XadesForm.Enveloped, true)]
    [InlineData(XadesForm.Enveloping, true)]
    [InlineData(XadesForm.Detached, true)]
    public async Task CompleteWithDetailsAsync_LongTermAndArchiveLevels_AreFinishedInPhaseTwo(XadesForm form, bool archive)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        var tsa = new TimestampOptions(new Uri(TsaUrl));
        var validation = new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst };
        XadesDeferredSignerBuilder builder = XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithForm(form)
            .WithLevel(archive ? AdesBaselineProfile.Archive(tsa, validation) : AdesBaselineProfile.LongTerm(tsa, validation));
        XadesDeferredPrepareResult prepared = await (form == XadesForm.Detached ? builder.WithDataUri(DataUri) : builder).PrepareAsync();

        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        result.AchievedLevel.ShouldBe(archive ? AdesBaselineLevel.Archive : AdesBaselineLevel.LongTerm);
        result.HasLongTermValidationMaterial.ShouldBeTrue();
        result.HasArchiveTimestamp.ShouldBe(archive);
        XadesValidationResult validated = Validate(result.SignedArtifact, form, _pki.IntermediateCa, _pki.RootCa);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.IsIntegrityValid.ShouldBeTrue();
        validated.IsLtvDataValid.ShouldBe(true);
        if (archive)
        {
            validated.HasValidArchiveTimeStamp.ShouldBe(true);
        }
    }

    [Fact]
    public async Task CompleteWithDetailsAsync_ExtendedForm_TravelsInTheSession()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        XadesDeferredPrepareResult prepared = await XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .WithExtendedValidationData(XadesExtendedForm.CompleteReferences)
            .PrepareAsync();

        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        XadesValidationResult validated = Validate(result.SignedArtifact, XadesForm.Enveloped, _pki.IntermediateCa, _pki.RootCa);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.HasValidSigAndRefsTimeStamp.ShouldBe(true, string.Join("; ", validated.Warnings));
        validated.HasValidCompleteReferences.ShouldBe(true, string.Join("; ", validated.Warnings));
    }

    [Fact]
    public async Task PrepareAsync_ExtendedFormWithoutTimestamp_IsRefusedBeforeAnythingIsSigned()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);

        var ex = await Should.ThrowAsync<SigningException>(() => Prepare(publicCertificate)
            .WithExtendedValidationData(XadesExtendedForm.CompleteReferences)
            .PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task CompleteAsync_RsaPss_UsesTheParametersOfTheSigningRequest()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate)
            .WithSignatureAlgorithm(Oids.RsaPss)
            .WithOperationId("op-pss")
            .PrepareAsync();

        ExternalSigningRequest request = prepared.ToSigningRequest();
        request.PayloadKind.ShouldBe(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
        request.SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
        request.RsaPssParameters.ShouldNotBeNull();
        request.OperationId.ShouldBe("op-pss");

        byte[] signed = await XadesDeferredSigner.Resume(prepared.SessionData, s_key).CompleteAsync(RemoteKey.Sign(_rsa, request));

        Validate(signed, XadesForm.Enveloped, _rsa).IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task CompleteAsync_DocumentThatIsAlreadySigned_AddsTheSecondSignature()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_ecdsa);
        byte[] once = await XadesSigner.Document(_xml).WithCertificate(_rsa).SignAsync();

        XadesDeferredPrepareResult prepared = await XadesDeferredSigner.Document(once)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).PrepareAsync();
        byte[] twice = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .CompleteAsync(RemoteKey.Sign(_ecdsa, prepared.ToSigningRequest()));

        var results = new XadesSignatureValidator().ValidateAll(twice, [_rsa, _ecdsa]);
        results.Count.ShouldBe(2);
        results.ShouldAllBe(r => r.IsValid);
    }

    // ── What is signed is fixed in phase one ──────────────────────────────

    [Theory]
    [InlineData(XadesCanonicalization.Exclusive)]
    [InlineData(XadesCanonicalization.Inclusive)]
    public async Task PrepareAsync_SignedPropertyOptions_AreInTheCompletedSignature(XadesCanonicalization canonicalization)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var signingTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600);
        byte[] policyDocument = "a signature policy document"u8.ToArray();
        var policy = new SignaturePolicyReference("2.16.76.1.7.1.6.2.3", Oids.Sha256, SHA256.HashData(policyDocument), "https://example.com/policy.xml");

        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate)
            .WithCanonicalization(canonicalization)
            .WithSigningTime(signingTime)
            .WithCommitmentType(CommitmentType.ProofOfApproval)
            .WithSignaturePolicy(policy)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument("1.2.3.4.5.1", policyDocument))
            .WithSignerRoles(["Approver", "Manager"])
            .WithSignatureProductionPlace(new SignatureProductionPlace { City = "Lima", CountryName = "PE" })
            .WithDataObjectFormat(new DataObjectFormat { MimeType = "application/xml" })
            .PrepareAsync();

        byte[] signed = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        XadesValidationResult validation = Validate(signed, XadesForm.Enveloped, _rsa);
        validation.IsValid.ShouldBeTrue(string.Join("; ", validation.Errors));
        validation.SigningTime.ShouldBe(signingTime);
        validation.ClaimedRoles.ShouldBe(["Approver", "Manager"]);
        validation.SignaturePolicy.ShouldNotBeNull().Oid.ShouldBe(policy.Oid);
        validation.SignaturePolicyStore.ShouldNotBeNull().Document.ToArray().ShouldBe(policyDocument);
        string text = Encoding.UTF8.GetString(signed);
        text.ShouldContain("CommitmentTypeIndication");
        text.ShouldContain(">Lima<");
        text.ShouldContain("application/xml");
    }

    [Fact]
    public async Task PrepareAsync_DataObjectsTimestamp_IsRequestedInPhaseOneAndSigned()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);

        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate)
            .WithDataObjectsTimestamp(new TimestampOptions(new Uri(TsaUrl), Http))
            .PrepareAsync();

        _tsaAuthorizations.Count.ShouldBe(1);
        byte[] signed = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));
        _tsaAuthorizations.Count.ShouldBe(1);
        Validate(signed, XadesForm.Enveloped, _rsa).HasValidDataObjectsTimeStamp.ShouldBe(true);
    }

    [Fact]
    public async Task CompleteWithDetailsAsync_AdditionalDataObjects_AreReadBackFromTheSession()
    {
        byte[] terms = "Terms and conditions\n"u8.ToArray();
        byte[] attachment = [0x25, 0x50, 0x44, 0x46, 0x00, 0xFF, 0x10, 0x80];
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        var tsa = new TimestampOptions(new Uri(TsaUrl));
        XadesDeferredPrepareResult prepared = await XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithForm(XadesForm.Detached)
            .WithDataUri(DataUri)
            .WithAdditionalDataObject(XadesDataObject.External("terms.txt", terms, "text/plain"))
            .WithAdditionalDataObject(XadesDataObject.Embedded(attachment, "application/pdf"))
            .WithLevel(AdesBaselineProfile.Archive(tsa, new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst }))
            .PrepareAsync();

        // The archive timestamp of phase two digests the detached document and the external object again.
        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Archive);
        var external = new Dictionary<string, byte[]> { [DataUri] = _xml, ["terms.txt"] = terms };
        XadesValidationResult validated = new XadesSignatureValidator().Validate(result.SignedArtifact, [_pki.IntermediateCa, _pki.RootCa], external);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.IsIntegrityValid.ShouldBeTrue();
        validated.HasValidArchiveTimeStamp.ShouldBe(true);
        external["terms.txt"] = "other terms"u8.ToArray();
        new XadesSignatureValidator().Validate(result.SignedArtifact, [_pki.IntermediateCa, _pki.RootCa], external).IsIntegrityValid.ShouldBeFalse();
    }

    [Fact]
    public async Task PhaseOneMethods_OnAResumedBuilder_Throw()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).PrepareAsync();
        XadesDeferredSignerBuilder resumed = XadesDeferredSigner.Resume(prepared.SessionData, s_key);

        Should.Throw<InvalidOperationException>(() => resumed.WithCertificate(publicCertificate));
        Should.Throw<InvalidOperationException>(() => resumed.WithSigningTime(DateTimeOffset.UtcNow));
        Should.Throw<InvalidOperationException>(() => resumed.WithForm(XadesForm.Enveloping));
        Should.Throw<InvalidOperationException>(() => resumed.WithSignerRole("Approver"));
        Should.Throw<InvalidOperationException>(() => resumed.WithLevel(AdesBaselineProfile.Basic()));
        Should.Throw<InvalidOperationException>(() => resumed.WithSessionIntegrityKey(s_key));
        await Should.ThrowAsync<InvalidOperationException>(() => resumed.PrepareAsync());
        resumed.SignerCertificate.ShouldBeNull();
    }

    [Fact]
    public async Task CompleteAsync_OnABuilderThatWasNotResumed_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredSignerBuilder builder = Prepare(publicCertificate);

        await Should.ThrowAsync<InvalidOperationException>(() => builder.CompleteAsync([1, 2, 3]));
        Should.Throw<InvalidOperationException>(() => builder.WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl))));
    }

    // ── The session ───────────────────────────────────────────────────────

    [Fact]
    public async Task Resume_TamperedSession_IsRefused()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).PrepareAsync();

        // Ask for another signature Id without touching the HMAC.
        string json = Encoding.UTF8.GetString(prepared.SessionData);
        byte[] tampered = Encoding.UTF8.GetBytes(json.Replace("\"SignatureId\":\"", "\"SignatureId\":\"x", StringComparison.Ordinal));

        tampered.ShouldNotBe(prepared.SessionData);
        Should.Throw<CryptographicException>(() => XadesDeferredSigner.Resume(tampered, s_key));
    }

    [Fact]
    public async Task Resume_AnotherKeyOrAnotherFormat_IsRefused()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).PrepareAsync();

        Should.Throw<CryptographicException>(() => XadesDeferredSigner.Resume(prepared.SessionData, RandomNumberGenerator.GetBytes(32)));
        Should.Throw<ArgumentException>(() => XadesDeferredSigner.Resume(prepared.SessionData, new byte[16]));
        Should.Throw<ArgumentException>(() => XadesDeferredSigner.Resume("{\"format\":\"CAdES\",\"version\":1}"u8.ToArray(), s_key));
        Should.Throw<ArgumentException>(() => XadesDeferredSigner.Resume("not a session"u8.ToArray(), s_key));
    }

    [Fact]
    public async Task SessionData_OptionalFieldsAtTheirDefault_AreNotWritten()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).PrepareAsync();

        string json = Encoding.UTF8.GetString(prepared.SessionData);
        foreach (string optional in new[] { "DetachedContent", "ExternalDataObjects", "ExtraCertificatesDer", "TimestampEndpoint", "ArchiveTimestampEndpoint", "RevocationPreference", "ClockSkewSeconds", "ExtendedForm", "OperationId" })
        {
            json.ShouldNotContain($"\"{optional}\"");
        }
    }

    [Fact]
    public async Task Resume_SessionOfAnotherVersion_StillCompletes()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).WithOperationId("op-1").PrepareAsync();

        // A later version wrote a field this one does not know; an earlier one did not write OperationId.
        byte[] session = RemoteKey.RewriteSession(prepared.SessionData, s_key, s =>
        {
            s["FieldOfALaterVersion"] = "value";
            s.Remove("OperationId").ShouldBeTrue();
        });

        byte[] signed = await XadesDeferredSigner.Resume(session, s_key).CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        Validate(signed, XadesForm.Enveloped, _rsa).IsValid.ShouldBeTrue();
    }

    // ── The signature ─────────────────────────────────────────────────────

    [Fact]
    public async Task CompleteAsync_SignatureOfAnotherKey_IsRefusedAndAudited()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        using X509Certificate2 other = TestCertificateFactory.CreateSelfSignedCert("CN=Another key");
        var audit = new RecordingAuditSink();
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).WithOperationId("op-wrong-key").PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(() => XadesDeferredSigner.Resume(prepared.SessionData, s_key)
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
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).PrepareAsync();
        XadesDeferredSignerBuilder resumed = XadesDeferredSigner.Resume(prepared.SessionData, s_key);

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

        var ex = await Should.ThrowAsync<SigningException>(() => XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithRevocation)
            .WithHttpClientProvider(new SingleClientProvider(revoked))
            .WithAuditSink(audit)
            .WithOperationId("op-revoked")
            .PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Format.ShouldBe("XAdES");
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
        XadesDeferredSignerBuilder builder = XadesDeferredSigner.Document(_xml)
            .WithCertificate(publicCertificate, [_pki.IntermediateCa])
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithTrustAnchor);

        await Should.ThrowAsync<SigningException>(() => builder.PrepareAsync());
        XadesDeferredPrepareResult prepared = await builder.WithTrustAnchors(new InMemoryTrustAnchors(_pki.RootCa)).PrepareAsync();

        prepared.DataToSign.ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Detached)]
    public async Task CompleteAsync_Success_IsAuditedWithTheOperationIdOfPhaseOne(XadesForm form)
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var prepareAudit = new RecordingAuditSink();
        var completeAudit = new RecordingAuditSink();
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate, form)
            .WithAuditSink(prepareAudit)
            .WithOperationId("op-42")
            .PrepareAsync();

        byte[] signed = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithAuditSink(completeAudit)
            .CompleteAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        // Preparing signs nothing: only the completion is a signature.
        prepareAudit.Events.ShouldBeEmpty();
        SignatureAuditEvent signedEvent = completeAudit.Events.ShouldHaveSingleItem();
        signedEvent.Signed.ShouldBeTrue();
        signedEvent.OperationId.ShouldBe("op-42");
        signedEvent.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        signedEvent.CertificateSha256.ShouldBe(Convert.ToHexString(_rsa.GetCertHash(HashAlgorithmName.SHA256)));
        signedEvent.InputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(_xml)));
        signedEvent.OutputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(signed)));
    }

    [Fact]
    public async Task WithOperationId_OnTheResumedBuilder_ReplacesTheOneOfTheSession()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        var audit = new RecordingAuditSink();
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate).WithOperationId("phase-one").PrepareAsync();

        await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
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
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)) { Authorization = new AuthenticationHeaderValue("Bearer", "secret") }))
            .PrepareAsync();

        Encoding.UTF8.GetString(prepared.SessionData).ShouldNotContain("secret");
        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl), Http) { Authorization = new AuthenticationHeaderValue("Bearer", "secret") })
            .CompleteWithDetailsAsync(RemoteKey.Sign(_rsa, prepared.ToSigningRequest()));

        result.HasSignatureTimestamp.ShouldBeTrue();
        _tsaAuthorizations.ShouldHaveSingleItem().ShouldNotBeNull().Parameter.ShouldBe("secret");
    }

    [Fact]
    public async Task WithTimestampOptions_AnotherEndpointOrASessionWithoutTimestamp_Throws()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        XadesDeferredPrepareResult timestamped = await Prepare(publicCertificate)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)))).PrepareAsync();
        XadesDeferredPrepareResult basic = await Prepare(publicCertificate).PrepareAsync();

        Should.Throw<ArgumentException>(() => XadesDeferredSigner.Resume(timestamped.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri("http://198.51.100.9/other-tsa"))));
        Should.Throw<InvalidOperationException>(() => XadesDeferredSigner.Resume(basic.SessionData, s_key)
            .WithTimestampOptions(new TimestampOptions(new Uri(TsaUrl))));
    }

    [Fact]
    public async Task CompleteAsync_ProfileThatMayReturnALowerLevel_NeedsTheDetailedResult()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_rsa);
        using HttpClient failing = MockHttpHandler.Failing();
        XadesDeferredPrepareResult prepared = await Prepare(publicCertificate)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)), SigningLevelFailureBehavior.ReturnLowerLevel))
            .PrepareAsync();
        byte[] signature = RemoteKey.Sign(_rsa, prepared.ToSigningRequest());
        XadesDeferredSignerBuilder resumed = XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(failing));

        var ex = await Should.ThrowAsync<SigningException>(() => resumed.CompleteAsync(signature));
        XadesSigningResult result = await resumed.CompleteWithDetailsAsync(signature);

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
            XadesDeferredSigner.Document(_xml).WithSessionIntegrityKey(s_key).PrepareAsync());
        var noKey = await Should.ThrowAsync<SigningException>(() =>
            XadesDeferredSigner.Document(_xml).WithCertificate(publicCertificate).PrepareAsync());

        noCertificate.Reason.ShouldBe(SigningErrorReason.CredentialMissing);
        noKey.Reason.ShouldBe(SigningErrorReason.LevelDependenciesMissing);
        Should.Throw<ArgumentException>(() => XadesDeferredSigner.Document(_xml).WithSessionIntegrityKey(new byte[31]));
    }
}
