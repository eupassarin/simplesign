using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>The signature-policy-store unsigned attribute (ETSI EN 319 122-1 §5.2.10).</summary>
[Trait("Category", "Unit")]
public sealed class CadesSignaturePolicyStoreTests : IDisposable
{
    private const string PolicyOid = "2.16.76.1.7.1.1.2.3";
    private const string SpecificationOid = "1.2.3.4.5.1";
    private static readonly byte[] s_policyDocument = "a signature policy document"u8.ToArray();
    private static readonly SignaturePolicyReference s_policy =
        new(PolicyOid, Oids.Sha256, SHA256.HashData(s_policyDocument), "https://example.com/policy.der");

    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _data = "content"u8.ToArray();

    public void Dispose() => _cert.Dispose();

    [Fact]
    public void Encode_DocumentWithOidSpecification_IsOidThenOctetString()
    {
        var attribute = CadesSignaturePolicyStore.Encode(SignaturePolicyStore.FromDocument("1.2.3", new byte[] { 0xAA }));

        // SEQUENCE { OID 1.2.3, OCTET STRING AA }
        attribute.Oid.ShouldBe("0.4.0.19122.1.3");
        attribute.DerValue.ShouldBe([0x30, 0x07, 0x06, 0x02, 0x2A, 0x03, 0x04, 0x01, 0xAA]);
    }

    [Fact]
    public void Encode_LocalUriWithUriSpecification_IsTwoIa5Strings()
    {
        var attribute = CadesSignaturePolicyStore.Encode(SignaturePolicyStore.FromLocalUri("urn:a", "file:b"));

        // SEQUENCE { IA5String "urn:a", IA5String "file:b" }
        attribute.DerValue.ShouldBe(
        [
            0x30, 0x0F,
            0x16, 0x05, 0x75, 0x72, 0x6E, 0x3A, 0x61,
            0x16, 0x06, 0x66, 0x69, 0x6C, 0x65, 0x3A, 0x62,
        ]);
    }

    [Fact]
    public async Task SignAsync_WithPolicyStore_AddsTheUnsignedAttributeAndValidates()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignaturePolicy(s_policy)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(SpecificationOid, s_policyDocument))
            .SignAsync();

        var signer = CmsParser.Parse(cms);
        signer.UnsignedAttributes.ShouldNotBeNull().ContainsKey(Oids.SignaturePolicyStore).ShouldBeTrue();
        var store = CadesSignaturePolicyStore.Read(signer).ShouldNotBeNull();
        store.Specification.ShouldBe(SpecificationOid);
        store.Document.ToArray().ShouldBe(s_policyDocument);
        store.MatchesHash(CmsAttribute.ReadSignaturePolicy(signer.SignedAttrs).ShouldNotBeNull()).ShouldBeTrue();
        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]);
        report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
    }

    [Fact]
    public async Task SignAsync_PolicyStoreAtTimestampedLevel_KeepsTheStoreAsItWasWritten()
    {
        // The store is added before the signature timestamp; embedding the timestamp rewrites the
        // unsigned attributes and must keep the ones already there octet for octet.
        using var tsaHttp = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes)),
            };
            response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var tsa = new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SimpleSign.Core.Http.SingleClientProvider(tsaHttp));
        var policyStore = SignaturePolicyStore.FromDocument(SpecificationOid, s_policyDocument);

        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignaturePolicy(s_policy)
            .WithSignaturePolicyStore(policyStore)
            .WithLevel(AdesBaselineProfile.Timestamped(tsa))
            .SignAsync();

        var signer = CmsParser.Parse(cms);
        signer.SignatureTimestampToken.ShouldNotBeNull();
        signer.UnsignedAttributes![Oids.SignaturePolicyStore].ShouldHaveSingleItem().ShouldBe(CadesSignaturePolicyStore.Encode(policyStore).DerValue);
        CadesSignaturePolicyStore.Read(signer).ShouldNotBeNull().Document.ToArray().ShouldBe(s_policyDocument);
    }

    [Fact]
    public async Task SignAsync_WithLocalUriStore_RoundTrips()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignaturePolicy(s_policy)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromLocalUri("https://example.com/policy-syntax", "file:///policies/pa.der"))
            .SignAsync();

        var store = CadesSignaturePolicyStore.Read(CmsParser.Parse(cms)).ShouldNotBeNull();
        store.Specification.ShouldBe("https://example.com/policy-syntax");
        store.SpecificationIsOid.ShouldBeFalse();
        store.LocalUri.ShouldBe("file:///policies/pa.der");
        store.Document.IsEmpty.ShouldBeTrue();
    }

    [Fact]
    public async Task SignAsync_PolicyStoreWithoutPolicy_Throws()
    {
        var builder = CadesSigner.Document(_data).WithCertificate(_cert)
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(SpecificationOid, s_policyDocument));

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Message.ShouldContain("policy");
    }

    [Fact]
    public async Task SignAsync_PolicyStoreWithPolicyThatHasNoHash_Throws()
    {
        // The hash in the signed policy identifier is what protects the unsigned store (§6.3).
        var builder = CadesSigner.Document(_data).WithCertificate(_cert)
            .WithSignaturePolicy(PolicyOid, "https://example.com/policy.der")
            .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(SpecificationOid, s_policyDocument));

        await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact]
    public async Task Read_SignerWithoutStore_ReturnsNull()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        CadesSignaturePolicyStore.Read(CmsParser.Parse(cms)).ShouldBeNull();
    }

    [Fact]
    public async Task Read_MalformedStore_ReturnsNull()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();
        byte[] broken = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Create(Oids.SignaturePolicyStore, [0x02, 0x01, 0x05])]);

        CadesSignaturePolicyStore.Read(CmsParser.Parse(broken)).ShouldBeNull();
    }

    [Fact]
    public void WithSignaturePolicyStore_Null_Throws() =>
        Should.Throw<ArgumentNullException>(() => CadesSigner.Document(_data).WithSignaturePolicyStore(null!));

    private static readonly SimpleSign.Core.Policies.ValidationPolicy s_requirePolicyDocument = SimpleSign.Core.Policies.ValidationPolicy.Default
        .With("SignatureConstraints/AcceptablePolicies", new SimpleSign.Core.Policies.PolicyConstraint(SimpleSign.Core.Policies.ConstraintLevel.Ignore))
        .With("SignatureConstraints/PolicyAvailable", new SimpleSign.Core.Policies.PolicyConstraint(SimpleSign.Core.Policies.ConstraintLevel.Fail));

    [Fact]
    public async Task Validate_PolicyDocumentNotCarriedNorFound_SignaturePolicyNotAvailable()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).WithSignaturePolicy(s_policy).SignAsync();

        var result = new SimpleSign.CAdES.CadesSignatureValidator(new SimpleSign.Core.Validation.ValidationOptions
        {
            CheckRevocation = false,
            Policy = s_requirePolicyDocument,
        }).Validate(cms, _data, [_cert]);

        result.Indication.ShouldBe(SimpleSign.Core.Validation.SignatureIndication.Indeterminate);
        result.SubIndication.ShouldBe(SimpleSign.Core.Validation.SignatureSubIndication.SignaturePolicyNotAvailable);
    }

    [Fact]
    public async Task Validate_PolicyDocumentFromTheProvider_IsAvailable()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).WithSignaturePolicy(s_policy).SignAsync();

        var result = new SimpleSign.CAdES.CadesSignatureValidator(new SimpleSign.Core.Validation.ValidationOptions
        {
            CheckRevocation = false,
            Policy = s_requirePolicyDocument,
            SignaturePolicyDocuments = new Documents(),
        }).Validate(cms, _data, [_cert]);

        result.SubIndication.ShouldNotBe(SimpleSign.Core.Validation.SignatureSubIndication.SignaturePolicyNotAvailable);
        result.Constraints.ShouldContain(c => c.Id.EndsWith("/PolicyAvailable", StringComparison.Ordinal)
            && c.Status == SimpleSign.Core.Validation.ConstraintStatus.Passed);
    }

    private sealed class Documents : SimpleSign.Core.Policies.ISignaturePolicyDocumentProvider
    {
        public byte[]? Find(string policyOid) => policyOid == PolicyOid ? s_policyDocument : null;
    }
}
