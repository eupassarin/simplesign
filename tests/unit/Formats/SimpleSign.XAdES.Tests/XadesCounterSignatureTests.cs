using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// Enveloped countersignatures (ETSI EN 319 132-1 §5.2.7): built by <see cref="XadesSigner.CounterSign"/>
/// and validated under the signature they sign.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesCounterSignatureTests : IDisposable
{
    private const string XadesNs = "http://uri.etsi.org/01903/v1.3.2#";
    private const string CountersignedType = "http://uri.etsi.org/01903#CountersignedSignature";
    private const string CounterSignaturePath =
        "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CounterSignature/ds:Signature";

    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><p:order xmlns:p=\"urn:example:order\" xmlns:unused=\"urn:example:unused\"><p:item>1</p:item></p:order>");
    private static readonly X509Certificate2 s_signer = TestCertificateFactory.CreateSelfSignedCert("CN=Signer, O=Tests");
    private static readonly X509Certificate2 s_witness = TestCertificateFactory.CreateSelfSignedCert("CN=Witness, O=Tests");
    private static readonly X509Certificate2[] s_trusted = [s_signer, s_witness];

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

    private AdesBaselineProfile Timestamped => AdesBaselineProfile.Timestamped(
        new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_tsaHttp)));

    [Theory]
    [InlineData(XadesCanonicalization.Exclusive)]
    [InlineData(XadesCanonicalization.Inclusive)]
    public async Task CounterSign_SignsTheSignatureValueOfTheSignatureItIsEmbeddedIn(XadesCanonicalization canonicalization)
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();

        byte[] countersigned = await XadesSigner.CounterSign(signed)
            .WithCertificate(s_witness)
            .WithCanonicalization(canonicalization)
            .WithSignerRole("Testemunha")
            .SignAsync();

        var (signature, ns) = OnlySignature(countersigned);
        var counter = signature.SelectSingleNode(CounterSignaturePath, ns).ShouldBeOfType<XmlElement>();
        var signatureValue = signature.SelectSingleNode("ds:SignatureValue", ns).ShouldBeOfType<XmlElement>();
        var reference = counter.SelectSingleNode("ds:SignedInfo/ds:Reference[1]", ns).ShouldBeOfType<XmlElement>();
        reference.GetAttribute("Type").ShouldBe(CountersignedType);
        reference.GetAttribute("URI").ShouldBe("#" + signatureValue.GetAttribute("Id"));

        // The digest is over the complete ds:SignatureValue element, canonicalized where it stands.
        Transform transform = canonicalization == XadesCanonicalization.Inclusive ? new XmlDsigC14NTransform() : new XmlDsigExcC14NTransform();
        transform.LoadInput(signatureValue.SelectNodes("descendant-or-self::node() | descendant-or-self::*/@* | descendant-or-self::*/namespace::*")!);
        using var canonical = new MemoryStream();
        ((Stream)transform.GetOutput(typeof(Stream))).CopyTo(canonical);
        Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText).ShouldBe(SHA256.HashData(canonical.ToArray()));
        counter.SelectSingleNode(".//xades:ClaimedRole", ns)!.InnerText.ShouldBe("Testemunha");
    }

    [Fact]
    public async Task Validate_CountersignedDocument_ReportsTheCounterSignatureUnderTheSignature()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        byte[] countersigned = await XadesSigner.CounterSign(signed).WithCertificate(s_witness).SignAsync();
        var validator = new XadesSignatureValidator();

        var result = validator.Validate(countersigned, s_trusted);

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.SignerCertificate!.Thumbprint.ShouldBe(s_signer.Thumbprint);
        var counter = result.CounterSignatures.ShouldHaveSingleItem();
        counter.IsValid.ShouldBeTrue(string.Join("; ", counter.Errors));
        counter.SignerCertificate!.Thumbprint.ShouldBe(s_witness.Thumbprint);
        counter.CounterSignatures.ShouldBeEmpty();
        // The countersignature is not a second signature of the document.
        validator.ValidateAll(countersigned, s_trusted).ShouldHaveSingleItem();
    }

    [Fact]
    public async Task CounterSign_TimestampedSignature_LeavesItsTimestampValid()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).WithLevel(Timestamped).SignAsync();

        byte[] countersigned = await XadesSigner.CounterSign(signed).WithCertificate(s_witness).WithLevel(Timestamped).SignAsync();

        var result = new XadesSignatureValidator().Validate(countersigned, s_trusted);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidSignatureTimeStamp.ShouldBe(true);
        var counter = result.CounterSignatures.ShouldHaveSingleItem();
        counter.IsValid.ShouldBeTrue(string.Join("; ", counter.Errors));
        counter.HasValidSignatureTimeStamp.ShouldBe(true);
        counter.DetectedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    [Fact]
    public async Task CounterSign_ExternalSigner_Validates()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).WithForm(XadesForm.Enveloping).SignAsync();

        byte[] countersigned = await XadesSigner.CounterSign(signed)
            .WithExternalSigner(s_witness, new DelegatingExternalSigner(data =>
            {
                using var rsa = s_witness.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }))
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(countersigned, s_trusted);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.CounterSignatures.ShouldHaveSingleItem().IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task CounterSign_TwoCounterSignatures_AreBothUnderTheSignature()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        byte[] once = await XadesSigner.CounterSign(signed).WithCertificate(s_witness).SignAsync();

        byte[] twice = await XadesSigner.CounterSign(once).WithCertificate(s_signer).SignAsync();

        var result = new XadesSignatureValidator().Validate(twice, s_trusted);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.CounterSignatures.Count.ShouldBe(2);
        result.CounterSignatures.ShouldAllBe(c => c.IsValid);
    }

    [Fact]
    public async Task CounterSign_DocumentWithTwoSignatures_NeedsTheIdOfTheOneToCountersign()
    {
        byte[] first = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        byte[] both = await XadesSigner.Document(first).WithCertificate(s_witness).SignAsync();
        var validator = new XadesSignatureValidator();
        string secondId = validator.ValidateAll(both, s_trusted)[1].SignatureId!;

        await Should.ThrowAsync<SigningException>(() => XadesSigner.CounterSign(both).WithCertificate(s_witness).SignAsync());
        byte[] countersigned = await XadesSigner.CounterSign(both, secondId).WithCertificate(s_signer).SignAsync();

        var results = validator.ValidateAll(countersigned, s_trusted);
        results.Count.ShouldBe(2);
        results.ShouldAllBe(r => r.IsValid);
        results[0].CounterSignatures.ShouldBeEmpty();
        results[1].CounterSignatures.ShouldHaveSingleItem().IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_CounterSignatureMovedToAnotherSignature_IsInvalid()
    {
        byte[] first = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        byte[] both = await XadesSigner.Document(first).WithCertificate(s_witness).SignAsync();
        var validator = new XadesSignatureValidator();
        var ids = validator.ValidateAll(both, s_trusted).Select(r => r.SignatureId!).ToArray();
        byte[] countersigned = await XadesSigner.CounterSign(both, ids[0]).WithCertificate(s_witness).SignAsync();

        // Move the whole UnsignedProperties (with the countersignature) from the first signature to the second.
        var doc = new XmlDocument { PreserveWhitespace = true };
        using (var stream = new MemoryStream(countersigned))
        {
            doc.Load(stream);
        }

        var ns = Namespaces(doc);
        var unsignedProperties = doc.SelectSingleNode($"//ds:Signature[@Id='{ids[0]}']/ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", ns)!;
        var otherQualifying = doc.SelectSingleNode($"//ds:Signature[@Id='{ids[1]}']/ds:Object/xades:QualifyingProperties", ns)!;
        otherQualifying.AppendChild(unsignedProperties);
        using var moved = new MemoryStream();
        doc.Save(moved);

        var results = validator.ValidateAll(moved.ToArray(), s_trusted);

        // The countersignature still verifies as XMLDSig, but it does not sign the value of the signature it now sits in.
        var counter = results[1].CounterSignatures.ShouldHaveSingleItem();
        counter.IsValid.ShouldBeFalse();
        counter.Errors.ShouldContain(e => e.Contains("ds:SignatureValue", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CounterSign_SignatureValueWithoutId_ReceivesOne()
    {
        // A signature as older versions wrote it: no Id on ds:SignatureValue (the element is not signed, so it stays valid).
        byte[] signed = RemoveSignatureValueId(await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync());

        byte[] countersigned = await XadesSigner.CounterSign(signed).WithCertificate(s_witness).SignAsync();

        var result = new XadesSignatureValidator().Validate(countersigned, s_trusted);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.CounterSignatures.ShouldHaveSingleItem().IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task CounterSign_TimestampedSignatureValueWithoutId_Throws()
    {
        // Adding the Id would change the element the existing signature timestamp covers.
        byte[] signed = RemoveSignatureValueId(await XadesSigner.Document(s_xml).WithCertificate(s_signer).WithLevel(Timestamped).SignAsync());

        var exception = await Should.ThrowAsync<SigningException>(() => XadesSigner.CounterSign(signed).WithCertificate(s_witness).SignAsync());

        exception.Message.ShouldContain("time-stamps");
    }

    [Fact]
    public async Task CounterSign_ACounterSignature_Throws()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        byte[] countersigned = await XadesSigner.CounterSign(signed).WithCertificate(s_witness).SignAsync();
        string counterId = new XadesSignatureValidator().Validate(countersigned, s_trusted).CounterSignatures[0].SignatureId!;

        var exception = await Should.ThrowAsync<SigningException>(() => XadesSigner.CounterSign(countersigned, counterId).WithCertificate(s_signer).SignAsync());

        exception.Message.ShouldContain("cannot be countersigned");
    }

    [Fact]
    public async Task CounterSign_LevelAboveTimestamped_Throws()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();
        var tsa = new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_tsaHttp));
        var builder = XadesSigner.CounterSign(signed).WithCertificate(s_witness)
            .WithLevel(AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions()));

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task CounterSign_DocumentWithoutSignature_Throws() =>
        await Should.ThrowAsync<SigningException>(() => XadesSigner.CounterSign(s_xml).WithCertificate(s_witness).SignAsync());

    [Fact]
    public void CounterSign_Null_Throws() =>
        Should.Throw<ArgumentNullException>(() => XadesSigner.CounterSign(null!));

    [Fact]
    public async Task SignAsync_NewSignature_HasAnIdOnSignatureValue()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_signer).SignAsync();

        var (signature, ns) = OnlySignature(signed);
        ((XmlElement)signature.SelectSingleNode("ds:SignatureValue", ns)!).GetAttribute("Id")
            .ShouldBe(signature.GetAttribute("Id") + "-SignatureValue");
    }

    private static byte[] RemoveSignatureValueId(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using (var stream = new MemoryStream(signed))
        {
            doc.Load(stream);
        }

        ((XmlElement)doc.SelectSingleNode("//ds:SignatureValue", Namespaces(doc))!).RemoveAttribute("Id");
        using var output = new MemoryStream();
        doc.Save(output);
        return output.ToArray();
    }

    private static (XmlElement Signature, XmlNamespaceManager Ns) OnlySignature(byte[] signed)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        using var stream = new MemoryStream(signed);
        doc.Load(stream);
        var ns = Namespaces(doc);
        return ((XmlElement)doc.SelectSingleNode("//ds:Signature[not(parent::xades:CounterSignature)]", ns)!, ns);
    }

    private static XmlNamespaceManager Namespaces(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesNs);
        return ns;
    }
}
