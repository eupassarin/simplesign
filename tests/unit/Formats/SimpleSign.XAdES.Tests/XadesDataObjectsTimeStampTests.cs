using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>The AllDataObjectsTimeStamp signed property (ETSI EN 319 132-1 §5.2.8.1): written by the builder, checked by the validator.</summary>
[Trait("Category", "Unit")]
public sealed class XadesDataObjectsTimeStampTests : IDisposable
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><p:order xmlns:p=\"urn:example:order\" xmlns:unused=\"urn:example:unused\"><p:item>1</p:item></p:order>");
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Data Timestamp, O=Tests");

    private readonly HttpClient _tsaHttp = new(new MockHttpHandler(async request =>
    {
        byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes)),
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
        return response;
    }));

    public void Dispose() => _tsaHttp.Dispose();

    private TimestampOptions Tsa => new(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_tsaHttp));

    [Theory]
    [InlineData(XadesForm.Enveloped, XadesCanonicalization.Exclusive)]
    [InlineData(XadesForm.Enveloped, XadesCanonicalization.Inclusive)]
    [InlineData(XadesForm.Enveloping, XadesCanonicalization.Exclusive)]
    [InlineData(XadesForm.Enveloping, XadesCanonicalization.Inclusive)]
    [InlineData(XadesForm.Detached, XadesCanonicalization.Exclusive)]
    [InlineData(XadesForm.Detached, XadesCanonicalization.Inclusive)]
    public async Task SignAsync_WithDataObjectsTimestamp_StampsWhatTheDataReferenceDigests(XadesForm form, XadesCanonicalization canonicalization)
    {
        byte[] signed = await Builder(form).WithCanonicalization(canonicalization).WithDataObjectsTimestamp(Tsa).SignAsync();

        var (signature, ns) = Signature(signed);
        var timestamp = signature.SelectSingleNode(".//xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp", ns).ShouldBeOfType<XmlElement>();
        timestamp.ChildNodes.OfType<XmlElement>().Select(e => e.LocalName).ShouldBe(["CanonicalizationMethod", "EncapsulatedTimeStamp"]);
        byte[] token = Convert.FromBase64String(timestamp.SelectSingleNode("xades:EncapsulatedTimeStamp", ns)!.InnerText);

        // The token's imprint is the SHA-256 of the timestamped octets, and so is the DigestValue of
        // the only reference besides SignedProperties: they must be the same value.
        var dataReference = signature.SelectSingleNode("ds:SignedInfo/ds:Reference[not(@Type)]", ns).ShouldBeOfType<XmlElement>();
        byte[] referenceDigest = Convert.FromBase64String(dataReference.SelectSingleNode("ds:DigestValue", ns)!.InnerText);
        var verification = TimestampToken.VerifyHash(token, referenceDigest, HashAlgorithmName.SHA256);
        verification.IsImprintValid.ShouldBeTrue();
        verification.IsIntegrityValid.ShouldBeTrue();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert], form == XadesForm.Detached ? s_xml : null);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidDataObjectsTimeStamp.ShouldBe(true);
        // The mock TSA stamps every token with this fixed time.
        result.DataObjectsTimeStampTime.ShouldBe(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
        // A B-B signature: the data objects timestamp is not the signature timestamp.
        result.HasValidSignatureTimeStamp.ShouldBeNull();
    }

    [Fact]
    public async Task SignAsync_WithFormatAndCommitment_PutsTheTimestampLastInSignedDataObjectProperties()
    {
        byte[] signed = await Builder(XadesForm.Enveloped)
            .WithDataObjectFormat(new DataObjectFormat { ObjectReference = "", MimeType = "text/xml" })
            .WithCommitmentType(CommitmentType.ProofOfOrigin)
            .WithDataObjectsTimestamp(Tsa)
            .SignAsync();

        var (signature, ns) = Signature(signed);
        signature.SelectSingleNode(".//xades:SignedDataObjectProperties", ns)!.ChildNodes.OfType<XmlElement>().Select(e => e.LocalName)
            .ShouldBe(["DataObjectFormat", "CommitmentTypeIndication", "AllDataObjectsTimeStamp"]);
    }

    [Fact]
    public async Task SignAsync_ExternalSignerWithDataObjectsTimestamp_Validates()
    {
        byte[] signed = await XadesSigner.Document(s_xml)
            .WithExternalSigner(s_cert, new DelegatingExternalSigner(data =>
            {
                using var rsa = s_cert.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .WithForm(XadesForm.Enveloping)
            .WithDataObjectsTimestamp(Tsa)
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidDataObjectsTimeStamp.ShouldBe(true);
    }

    [Fact]
    public void Validate_TokenOverOtherData_IsReportedAsNotCoveringTheDataObjects()
    {
        // A correctly signed signature whose timestamp was taken over something else.
        byte[] strayToken = TimestampTestResponseBuilder.CreateTokenForData("something else"u8, HashAlgorithmName.SHA256);
        byte[] signed = XadesSignatureBuilder.BuildSignature(
            s_xml, s_cert, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, extraCertificates: null, commitmentType: null,
            signaturePolicy: null, XadesSigningCertificateForm.V2, "1.2.840.113549.1.1.11", XadesForm.Enveloped,
            signerRoles: null, dataObjectFormat: null, productionPlace: null,
            new XadesDataObjectsTimeStamp(strayToken, DataObjectId: null), additionalReferences: null, NullLogger.Instance);

        var result = new XadesSignatureValidator().Validate(signed, [s_cert]);

        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidDataObjectsTimeStamp.ShouldBe(false);
        result.DataObjectsTimeStampTime.ShouldBeNull();
        result.Errors.ShouldContain(e => e.Contains("AllDataObjectsTimeStamp", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_PolicyAsksForTheContentTimestamp_ReportsItAndItsImprint()
    {
        byte[] strayToken = TimestampTestResponseBuilder.CreateTokenForData("something else"u8, HashAlgorithmName.SHA256);
        byte[] signed = XadesSignatureBuilder.BuildSignature(
            s_xml, s_cert, HashAlgorithmName.SHA256, DateTimeOffset.UtcNow, extraCertificates: null, commitmentType: null,
            signaturePolicy: null, XadesSigningCertificateForm.V2, "1.2.840.113549.1.1.11", XadesForm.Enveloped,
            signerRoles: null, dataObjectFormat: null, productionPlace: null,
            new XadesDataObjectsTimeStamp(strayToken, DataObjectId: null), additionalReferences: null, NullLogger.Instance);
        var policy = SimpleSign.Core.Policies.ValidationPolicy.Default
            .With("SignatureConstraints/SignedAttributes/ContentTimeStamp", new SimpleSign.Core.Policies.PolicyConstraint(SimpleSign.Core.Policies.ConstraintLevel.Fail))
            .With("SignatureConstraints/SignedAttributes/ContentTimeStampMessageImprint", new SimpleSign.Core.Policies.PolicyConstraint(SimpleSign.Core.Policies.ConstraintLevel.Fail));

        var result = new XadesSignatureValidator(new SimpleSign.Core.Validation.ValidationOptions { Policy = policy, CheckRevocation = false })
            .Validate(signed, [s_cert]);

        result.Constraints.ShouldContain(c => c.Id == "SignatureConstraints/SignedAttributes/ContentTimeStamp" && c.Status == SimpleSign.Core.Validation.ConstraintStatus.Passed);
        result.Constraints.ShouldContain(c => c.Id == "SignatureConstraints/SignedAttributes/ContentTimeStampMessageImprint"
            && c.Status == SimpleSign.Core.Validation.ConstraintStatus.Failed);
    }

    [Fact]
    public async Task Validate_SignatureWithoutTheProperty_ReportsNull()
    {
        byte[] signed = await Builder(XadesForm.Enveloped).SignAsync();

        new XadesSignatureValidator().Validate(signed, [s_cert]).HasValidDataObjectsTimeStamp.ShouldBeNull();
    }

    [Fact]
    public async Task SignAsync_TsaDoesNotAnswer_Throws()
    {
        using var failing = MockHttpHandler.Failing();
        var builder = Builder(XadesForm.Enveloped)
            .WithDataObjectsTimestamp(new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(failing)));

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Reason.ShouldBe(SigningErrorReason.NetworkFailure);
        exception.Message.ShouldContain("Data objects timestamp");
    }

    [Fact]
    public void WithDataObjectsTimestamp_Null_Throws() =>
        Should.Throw<ArgumentNullException>(() => XadesSigner.Document(s_xml).WithDataObjectsTimestamp(null!));

    private static XadesSignerBuilder Builder(XadesForm form)
    {
        var builder = XadesSigner.Document(s_xml).WithCertificate(s_cert).WithForm(form);
        return form == XadesForm.Detached ? builder.WithDataUri("order.xml") : builder;
    }

    private static (XmlElement Signature, XmlNamespaceManager Ns) Signature(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using var stream = new MemoryStream(signed);
        doc.Load(stream);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesNs);
        return ((XmlElement)doc.SelectSingleNode("//ds:Signature", ns)!, ns);
    }
}
