using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using SimpleSign.XAdES.Constants;
using Shouldly;
using Xunit;

namespace SimpleSign.XAdES.Tests;

public sealed class XadesSignatureValidatorTests
{
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Val Test, O=Tests");

    private static readonly RSA s_tsaKey = RSA.Create(2048);
    private static readonly X509Certificate2 s_tsaCert = CreateTsaCert(s_tsaKey);

    private const string XmlTemplate = "<?xml version=\"1.0\"?><doc><id>123</id><content>test</content></doc>";

    private static readonly byte[] s_xmlBytes = System.Text.Encoding.UTF8.GetBytes(XmlTemplate);

    private static X509Certificate2 CreateTsaCert(RSA key)
    {
        var req = new CertificateRequest("CN=Test TSA, O=Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadCertificate(cert.RawData);
    }

    [Fact]
    public async Task Validate_EnvelopedSignature_ReturnsValid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors)
            + " | Warnings: " + string.Join("; ", result.Warnings);
        result.IsValid.ShouldBeTrue(diag);
        result.IsSignatureValid.ShouldBeTrue(diag);
        result.IsIntegrityValid.ShouldBeTrue(diag);
        result.DetectedLevel.ShouldBe(XadesLevel.Basic);
    }

    [Fact]
    public async Task Validate_DetachedSignature_ReturnsValid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .WithForm(XadesForm.Detached)
            .WithDataUri("doc.xml")
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, originalData: s_xmlBytes, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors)
            + " | Warnings: " + string.Join("; ", result.Warnings);
        result.IsValid.ShouldBeTrue(diag);
        result.Errors.ShouldBeEmpty();
    }

    [Fact]
    public async Task Validate_EnvelopingSignature_ReturnsValid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .WithForm(XadesForm.Enveloping)
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors)
            + " | Warnings: " + string.Join("; ", result.Warnings);
        result.IsValid.ShouldBeTrue(diag);
        result.Errors.ShouldBeEmpty();
    }

    [Fact]
    public async Task Validate_TamperedXml_ReturnsInvalid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        string signedText = System.Text.Encoding.UTF8.GetString(signed);
        signedText = signedText.Replace("<id>123</id>", "<id>999</id>");
        byte[] tamperedXml = System.Text.Encoding.UTF8.GetBytes(signedText);

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(tamperedXml, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors);
        result.IsSignatureValid.ShouldBeFalse(diag);
    }

    [Fact]
    public async Task Validate_DigestMismatch_ReturnsInvalid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        string signedText = System.Text.Encoding.UTF8.GetString(signed);
        signedText = signedText.Replace("<content>test</content>", "<content>tampered</content>");
        byte[] tamperedXml = System.Text.Encoding.UTF8.GetBytes(signedText);

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(tamperedXml, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors);
        result.IsIntegrityValid.ShouldBeFalse(diag);
    }

    [Fact]
    public async Task Validate_TrustedChain_ReturnsValid()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors);
        result.IsCertificateChainValid.ShouldBeTrue(diag);
    }

    [Fact]
    public async Task Validate_UntrustedChain_ReturnsInvalid()
    {
        var otherCert = TestCertificateFactory.CreateSelfSignedCert("CN=Wrong Anchor, O=Tests");

        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, trustAnchors: [otherCert]);

        var diag = "Errors: " + string.Join("; ", result.Errors);
        result.IsCertificateChainValid.ShouldBeFalse(diag);
    }

    [Fact]
    public void Validate_EmptyXml_ReturnsError()
    {
        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate([]);

        result.IsValid.ShouldBeFalse();
        result.Errors.ShouldNotBeEmpty();
        result.IsSignatureValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_DetectedLevel_Basic()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .WithLevel(XadesLevel.Basic)
            .SignAsync();

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        result.DetectedLevel.ShouldBe(XadesLevel.Basic);
    }

    [Fact]
    public async Task Validate_DetectedLevel_Timestamped()
    {
        byte[] signed = await XadesSigner.Document(s_xmlBytes)
            .WithCertificate(s_cert)
            .SignAsync();

        byte[] tsXml = EmbedSyntheticTimestamp(signed);

        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false });
        var result = validator.Validate(tsXml, trustAnchors: [s_cert]);

        var diag = "Errors: " + string.Join("; ", result.Errors)
            + " | Warnings: " + string.Join("; ", result.Warnings);
        result.DetectedLevel.ShouldBe(XadesLevel.Timestamped, diag);
        result.HasValidSignatureTimeStamp.ShouldBe(true, diag);
    }

    private static byte[] EmbedSyntheticTimestamp(byte[] signedXml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        if (doc.SelectSingleNode("//ds:Signature/ds:SignatureValue", ns) is not XmlElement sigValueEl)
        {
            throw new InvalidOperationException("No SignatureValue found.");
        }

        byte[] sigValueBytes = Convert.FromBase64String(sigValueEl.InnerText.Trim());
        byte[] preImageHash = SHA256.HashData(sigValueBytes);

        byte[] tokenBytes = BuildSyntheticTsaToken(s_tsaKey, s_tsaCert, preImageHash);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        if (signature.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is not XmlElement qp)
        {
            throw new InvalidOperationException("QualifyingProperties not found.");
        }

        var usp = EnsureTestUnsignedSignatureProperties(doc, qp, ns);

        var tsElement = doc.CreateElement("SignatureTimeStamp", XadesUris.XadesNamespace);
        tsElement.SetAttribute("Id", "TS-" + Guid.NewGuid().ToString("N")[..8]);
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encElement.InnerText = Convert.ToBase64String(tokenBytes);
        tsElement.AppendChild(encElement);
        usp.AppendChild(tsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    private static XmlElement EnsureTestUnsignedSignatureProperties(
        XmlDocument doc,
        XmlElement qp,
        XmlNamespaceManager ns)
    {
        if (qp.SelectSingleNode("xades:UnsignedProperties", ns) is not XmlElement up)
        {
            up = doc.CreateElement("UnsignedProperties", XadesUris.XadesNamespace);
            qp.AppendChild(up);
        }

        if (up.SelectSingleNode("xades:UnsignedSignatureProperties", ns) is not XmlElement usp)
        {
            usp = doc.CreateElement("UnsignedSignatureProperties", XadesUris.XadesNamespace);
            up.AppendChild(usp);
        }

        return usp;
    }

    private static byte[] BuildSyntheticTsaToken(RSA signerKey, X509Certificate2 signerCert, byte[] preImageHash)
    {
        byte[] tstInfoBytes;
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                w.WriteInteger(1);
                w.WriteObjectIdentifier("1.2.3.4");
                using (w.PushSequence())
                {
                    using (w.PushSequence())
                    { w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                    w.WriteOctetString(preImageHash);
                }
                w.WriteInteger(1234567890);
                w.WriteGeneralizedTime(DateTimeOffset.UtcNow);
            }
            tstInfoBytes = w.Encode();
        }

        byte[] signedAttrsBytes;
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSetOf())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                    using (w.PushSetOf())
                    { w.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4"); }
                }
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.4");
                    using (w.PushSetOf())
                    { w.WriteOctetString(SHA256.HashData(tstInfoBytes)); }
                }
            }
            signedAttrsBytes = w.Encode();
        }

        byte[] attrsForSigning = (byte[])signedAttrsBytes.Clone();
        attrsForSigning[0] = 0x31;
        byte[] signature = signerKey.SignData(attrsForSigning, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var cmsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (cmsWriter.PushSequence())
        {
            cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.7.2");
            using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (cmsWriter.PushSequence())
                {
                    cmsWriter.WriteInteger(3);
                    using (cmsWriter.PushSetOf())
                    {
                        using (cmsWriter.PushSequence())
                        { cmsWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                    }
                    using (cmsWriter.PushSequence())
                    {
                        cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.9.16.1.4");
                        using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                        { cmsWriter.WriteOctetString(tstInfoBytes); }
                    }
                    using (cmsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    { cmsWriter.WriteEncodedValue(signerCert.RawData); }
                    using (cmsWriter.PushSetOf())
                    {
                        using (cmsWriter.PushSequence())
                        {
                            cmsWriter.WriteInteger(1);
                            using (cmsWriter.PushSequence())
                            {
                                cmsWriter.WriteEncodedValue(signerCert.IssuerName.RawData);
                                cmsWriter.WriteIntegerUnsigned(signerCert.SerialNumberBytes.Span);
                            }
                            using (cmsWriter.PushSequence())
                            { cmsWriter.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); }
                            byte[] signedAttrsCopy = (byte[])signedAttrsBytes.Clone();
                            signedAttrsCopy[0] = 0xA0;
                            cmsWriter.WriteEncodedValue(signedAttrsCopy);
                            using (cmsWriter.PushSequence())
                            {
                                cmsWriter.WriteObjectIdentifier("1.2.840.113549.1.1.11");
                                cmsWriter.WriteNull();
                            }
                            cmsWriter.WriteOctetString(signature);
                        }
                    }
                }
            }
        }
        return cmsWriter.Encode();
    }
}
