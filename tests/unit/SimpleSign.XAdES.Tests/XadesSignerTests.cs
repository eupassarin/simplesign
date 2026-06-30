using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

public sealed class XadesSignerTests
{
    private static readonly X509Certificate2 s_cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Test, O=Tests");

    private static readonly X509Certificate2 s_ecdsaCert = TestCertificateFactory.CreateEcdsaCert(ECCurve.NamedCurves.nistP256, "CN=ECDSA XAdES Test, O=Tests");
    private static readonly X509Certificate2 s_rsaPssCert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA256, 2048, "CN=RSA-PSS XAdES Test, O=Tests");

    private static readonly RSA s_tsaKey = RSA.Create(2048);
    private static readonly X509Certificate2 s_tsaCert = CreateTsaCert(s_tsaKey);

    private static readonly X509Certificate2 s_certNoKey = CreateCertWithoutPrivateKey();

    private static X509Certificate2 CreateCertWithoutPrivateKey()
    {
        using RSA key = RSA.Create(2048);
        var req = new CertificateRequest("CN=No Key, O=Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadCertificate(cert.RawData);
    }

    private static X509Certificate2 CreateTsaCert(RSA key)
    {
        var req = new CertificateRequest("CN=Test TSA, O=Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadCertificate(cert.RawData);
    }

    [Fact]
    public async Task SignAsync_BasicEnveloped_ReturnsValidSignature()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><id>123</id><content>test</content></doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        signed.ShouldNotBeNull();
        signed.Length.ShouldBeGreaterThan(xmlBytes.Length);

        string signedText = System.Text.Encoding.UTF8.GetString(signed);
        signedText.ShouldContain("<Signature");
        signedText.ShouldContain("QualifyingProperties");
        signedText.ShouldContain("SignedProperties");
        signedText.ShouldContain("SigningCertificateV2");
        signedText.ShouldContain("SigningTime");
    }

    [Fact]
    public async Task SignAsync_WithXadesSignerBuilder_ProducesValidResult()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><data>test</data></root>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithLevel(XadesLevel.Basic)
            .SignWithDetailsAsync();

        result.SignedXml.ShouldNotBeNull();
        result.TimestampApplied.ShouldBeFalse();
        result.LtvDataEmbedded.ShouldBeFalse();
        result.ArchiveTimestampApplied.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAsync_WithHashAlgorithm_ChangesDigestMethod()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>hash test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithHashAlgorithm(System.Security.Cryptography.HashAlgorithmName.SHA512)
            .SignAsync();

        string signedText = System.Text.Encoding.UTF8.GetString(signed);
        signedText.ShouldContain("sha512");
    }

    [Fact]
    public async Task SignAsync_WithExternalSigner_ReturnsValidSignature()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>external</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithExternalSigner(s_cert,
                async data =>
                {
                    using var rsa = s_cert.GetRSAPrivateKey()!;
                    return await Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                },
                "1.2.840.113549.1.1.11")
            .SignAsync();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        Assert.True(result.IsValid, diag);
        Assert.NotNull(result.SignerCertificate);
        Assert.Equal(s_cert.Thumbprint, result.SignerCertificate.Thumbprint);
    }

    [Fact]
    public async Task SignAsync_HashAlgorithmNotSupported_ThrowsException()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>bad hash</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        var ex = await Should.ThrowAsync<NotSupportedException>(async () =>
        {
            await XadesSigner.Document(xmlBytes)
                .WithCertificate(s_cert)
                .WithHashAlgorithm(System.Security.Cryptography.HashAlgorithmName.MD5)
                .SignAsync();
        });
    }

    [Fact]
    public async Task SignAsync_WithAllOptions_ProducesFullResult()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>all options</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithHashAlgorithm(System.Security.Cryptography.HashAlgorithmName.SHA384)
            .WithLevel(XadesLevel.Basic)
            .WithForm(XadesForm.Enveloped)
            .WithSigningTime(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero))
            .WithCommitmentType(global::SimpleSign.Core.Signing.CommitmentType.ProofOfOrigin)
            .WithSignaturePolicy("1.2.3.4.5", "https://example.com/policy")
            .SignWithDetailsAsync();

        result.SignedXml.ShouldNotBeNull();
        string signedText = System.Text.Encoding.UTF8.GetString(result.SignedXml);
        signedText.ShouldContain("1.2.840.113549.1.9.16.6.1");
        signedText.ShouldContain("2026-06-15T12:00:00Z");
    }

    [Fact]
    public async Task SignAsync_WithSignerRolesAndDataObjectFormat_IncludesElements()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>roles test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        var result = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithSignerRoles(["Manager", "Approver"])
            .WithDataObjectFormat(new DataObjectFormat
            {
                ObjectReference = "",
                MimeType = "text/xml"
            })
            .SignWithDetailsAsync();

        result.SignedXml.ShouldNotBeNull();
        string signedText = System.Text.Encoding.UTF8.GetString(result.SignedXml);
        signedText.ShouldContain("SignerRole");
        signedText.ShouldContain("ClaimedRoles");
        signedText.ShouldContain("ClaimedRole");
        signedText.ShouldContain("Manager");
        signedText.ShouldContain("Approver");
        signedText.ShouldContain("DataObjectFormat");
        signedText.ShouldContain("MimeType");
        signedText.ShouldContain("text/xml");
    }

    [Fact]
    public async Task SignThenValidate_RoundTrip_ReturnsIsValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>roundtrip</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        var signedStr = System.Text.Encoding.UTF8.GetString(signed);
        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        var details = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings) +
                       $" | IsSignatureValid={result.IsSignatureValid}" +
                       $" | IsIntegrityValid={result.IsIntegrityValid}" +
                       $" | IsCertificateChainValid={result.IsCertificateChainValid}" +
                       $" | SignerCert={result.SignerCertificate?.Thumbprint}" +
                       " | XML=" + signedStr.Substring(0, Math.Min(signedStr.Length, 500));
        Assert.True(result.IsValid, details);
        Assert.NotNull(result.SignerCertificate);
        Assert.Equal(s_cert.Thumbprint, result.SignerCertificate.Thumbprint);
    }

    [Fact]
    public void Validate_NullInput_Throws()
    {
        var validator = new XadesSignatureValidator();
        Should.Throw<ArgumentNullException>(() => validator.Validate(null!));
    }

    [Fact]
    public void Validate_NoSignature_ReturnsErrors()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>no sig</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(xmlBytes);

        result.IsValid.ShouldBeFalse();
        result.Errors.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Validate_SignatureTimeStampValid_ReturnsTrue()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>timestamp test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Extract signature value and embed a synthetic timestamp token
        byte[] tsXml = EmbedSyntheticTimestamp(signed);

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(tsXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidSignatureTimeStamp.ShouldBe(true, diag);
    }

    [Fact]
    public async Task Validate_SignatureTimeStampHashMismatch_ReturnsFalse()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>bad ts</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Create a token with a DIFFERENT signature value hash
        byte[] tsXml = EmbedSyntheticTimestamp(signed, tamperHash: true);

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(tsXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidSignatureTimeStamp.ShouldBe(false, diag);
    }

    [Fact]
    public async Task Validate_NoSignatureTimeStamp_ReturnsNull()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>no ts</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithLevel(XadesLevel.Basic)
            .SignAsync();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        string diag = "Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidSignatureTimeStamp.ShouldBeNull(diag);
    }

    [Fact]
    public async Task Validate_SignatureTimeStampMalformedToken_ReturnsFalse()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>malformed ts</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Use XML manipulation to embed a SignatureTimeStamp with garbage token
        byte[] tsXml = EmbedMalformedTimestamp(signed);

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(tsXml, trustAnchors: [s_cert]);

        string diag = "Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidSignatureTimeStamp.ShouldBe(false, diag);
    }

    [Fact]
    public async Task Validate_LtvDataPresent_ReturnsValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>ltv test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Add CertificateValues with the signer cert and RevocationValues with
        // a dummy but structurally valid OCSP response
        var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signed));
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not System.Xml.XmlElement sigEl)
        {
            Assert.Fail("No Signature element found");
            return;
        }

        // Find or create QualifyingProperties inside Object
        if (sigEl.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is not System.Xml.XmlElement qp)
        {
            Assert.Fail("No QualifyingProperties found");
            return;
        }

        var usp = EnsureTestUnsignedSignatureProperties(doc, qp, ns);

        // Add CertificateValues with the signer cert
        var cv = doc.CreateElement("CertificateValues", XadesUris.XadesNamespace);
        cv.SetAttribute("Id", "CV-test");
        var ec = doc.CreateElement("EncapsulatedX509Certificate", XadesUris.XadesNamespace);
        ec.InnerText = Convert.ToBase64String(s_cert.RawData);
        cv.AppendChild(ec);
        usp.AppendChild(cv);

        // Add RevocationValues with a dummy OCSP response (minimal SEQUENCE)
        var rv = doc.CreateElement("RevocationValues", XadesUris.XadesNamespace);
        rv.SetAttribute("Id", "RV-test");
        var ocspVals = doc.CreateElement("OCSPValues", XadesUris.XadesNamespace);
        var ocspEnc = doc.CreateElement("EncapsulatedOCSPValue", XadesUris.XadesNamespace);
        // Craft a minimal OCSP response: just a SEQUENCE with nothing inside
        byte[] minimalOcsp = [0x30, 0x00]; // DER SEQUENCE (empty)
        ocspEnc.InnerText = Convert.ToBase64String(minimalOcsp);
        ocspVals.AppendChild(ocspEnc);
        rv.AppendChild(ocspVals);
        usp.AppendChild(rv);

        using var ms = new MemoryStream();
        doc.Save(ms);
        byte[] ltvXml = ms.ToArray();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(ltvXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.IsLtvDataValid.ShouldBe(true, diag);
        result.DetectedLevel.ShouldBe(XadesLevel.LongTerm);
    }

    private static byte[] EmbedMalformedTimestamp(byte[] signedXml)
    {
        var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("xades", XadesUris.XadesNamespace);

        if (doc.SelectSingleNode("//ds:Signature", ns) is not System.Xml.XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        // Find QualifyingProperties inside ds:Object
        if (signature.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is not System.Xml.XmlElement qp)
        {
            throw new InvalidOperationException("QualifyingProperties not found.");
        }

        var usp = EnsureTestUnsignedSignatureProperties(doc, qp, ns);

        // Add a SignatureTimeStamp with garbage content ("AAAA" is invalid base64 token)
        var tsElement = doc.CreateElement("SignatureTimeStamp", XadesUris.XadesNamespace);
        tsElement.SetAttribute("Id", "TS-malformed");
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encElement.InnerText = "AAAA"; // well-formed base64 but not a valid DER/BER CMS token
        tsElement.AppendChild(encElement);
        usp.AppendChild(tsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    private static byte[] EmbedSyntheticTimestamp(byte[] signedXml, bool tamperHash = false)
    {
        // Parse the signed XML to extract the SignatureValue
        var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.AddNamespace("xades", "http://uri.etsi.org/01903/v1.3.2#");

        if (doc.SelectSingleNode("//ds:Signature/ds:SignatureValue", ns) is not System.Xml.XmlElement sigValueEl)
        {
            throw new InvalidOperationException("No SignatureValue found.");
        }

        byte[] sigValueBytes = Convert.FromBase64String(sigValueEl.InnerText.Trim());
        byte[] preImageHash = SHA256.HashData(tamperHash ? "wrong-data"u8 : sigValueBytes);

        // Build a synthetic RFC 3161 timestamp token
        byte[] tokenBytes = BuildSyntheticTsaToken(s_tsaKey, s_tsaCert, preImageHash);

        // Embed the token into UnsignedProperties (like XadesSignatureBuilder.EmbedSignatureTimeStamp)
        if (doc.SelectSingleNode("//ds:Signature", ns) is not System.Xml.XmlElement signature)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        // Find or create QualifyingProperties inside ds:Object
        if (signature.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) is not System.Xml.XmlElement qp)
        {
            // Create QualifyingProperties directly on signature for B-B (no Object yet)
            qp = doc.CreateElement("QualifyingProperties", XadesUris.XadesNamespace);
            qp.SetAttribute("Target", "#" + signature.GetAttribute("Id"));
            // Check if there's an Object element to nest inside
            var obj = signature.SelectSingleNode("ds:Object", ns);
            if (obj is not null)
            {
                obj.AppendChild(qp);
            }
            else
            {
                signature.AppendChild(qp);
            }
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

    private static byte[] BuildSyntheticTsaToken(RSA signerKey, X509Certificate2 signerCert, byte[] preImageHash)
    {
        // Build TSTInfo
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

        // Build signedAttrs
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

        // Sign the attributes
        byte[] attrsForSigning = (byte[])signedAttrsBytes.Clone();
        attrsForSigning[0] = 0x31;
        byte[] signature = signerKey.SignData(attrsForSigning, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Build CMS SignedData token
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

    [Fact]
    public async Task SignThenValidate_BasicTimestamped_ReturnsValidTimestamp()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>b-t test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Embed a synthetic RFC 3161 timestamp token (B-T)
        byte[] tsXml = EmbedSyntheticTimestamp(signed);

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(tsXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidSignatureTimeStamp.ShouldBe(true, diag);
        result.DetectedLevel.ShouldBe(XadesLevel.Timestamped);
    }

    [Fact]
    public async Task SignThenValidate_LongTerm_ReturnsLtvValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>b-lt test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Inject synthetic LTV data (CertificateValues + RevocationValues)
        byte[] ltvXml = await Task.Run(() =>
        {
            var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
            doc.Load(new MemoryStream(signed));
            var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            ns.AddNamespace("xades", XadesUris.XadesNamespace);

            var sigEl = doc.SelectSingleNode("//ds:Signature", ns) as System.Xml.XmlElement;
            if (sigEl is null)
            {
                throw new InvalidOperationException("No Signature element");
            }

            var qp = sigEl.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) as System.Xml.XmlElement;
            if (qp is null)
            {
                throw new InvalidOperationException("No QualifyingProperties");
            }

            var usp = EnsureTestUnsignedSignatureProperties(doc, qp, ns);

            // CertificateValues
            var cv = doc.CreateElement("CertificateValues", XadesUris.XadesNamespace);
            var ec = doc.CreateElement("EncapsulatedX509Certificate", XadesUris.XadesNamespace);
            ec.InnerText = Convert.ToBase64String(s_cert.RawData);
            cv.AppendChild(ec);
            usp.AppendChild(cv);

            // RevocationValues with minimal OCSP
            var rv = doc.CreateElement("RevocationValues", XadesUris.XadesNamespace);
            var ocspVals = doc.CreateElement("OCSPValues", XadesUris.XadesNamespace);
            var o = doc.CreateElement("EncapsulatedOCSPValue", XadesUris.XadesNamespace);
            o.InnerText = Convert.ToBase64String([0x30, 0x00]); // empty DER SEQUENCE
            ocspVals.AppendChild(o);
            rv.AppendChild(ocspVals);
            usp.AppendChild(rv);

            using var ms = new MemoryStream();
            doc.Save(ms);
            return ms.ToArray();
        });

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(ltvXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.IsLtvDataValid.ShouldBe(true, diag);
        result.DetectedLevel.ShouldBe(XadesLevel.LongTerm);
    }

    [Fact]
    public async Task SignThenValidate_ArchiveLevel_ReturnsValidArchiveTimeStamp()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>b-lta test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.SignAsync(xmlBytes, s_cert);

        // Inject LTV data first (same as LongTerm test)
        byte[] ltvXml;
        {
            var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
            doc.Load(new MemoryStream(signed));
            var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            ns.AddNamespace("xades", XadesUris.XadesNamespace);

            var sigEl = doc.SelectSingleNode("//ds:Signature", ns) as System.Xml.XmlElement;
            if (sigEl is null)
            {
                throw new InvalidOperationException("No Signature element");
            }

            var qp = sigEl.SelectSingleNode("ds:Object/xades:QualifyingProperties", ns) as System.Xml.XmlElement;
            if (qp is null)
            {
                throw new InvalidOperationException("No QualifyingProperties");
            }

            var usp = EnsureTestUnsignedSignatureProperties(doc, qp, ns);

            var cv = doc.CreateElement("CertificateValues", XadesUris.XadesNamespace);
            var ec = doc.CreateElement("EncapsulatedX509Certificate", XadesUris.XadesNamespace);
            ec.InnerText = Convert.ToBase64String(s_cert.RawData);
            cv.AppendChild(ec);
            usp.AppendChild(cv);

            var rv = doc.CreateElement("RevocationValues", XadesUris.XadesNamespace);
            var ocspVals = doc.CreateElement("OCSPValues", XadesUris.XadesNamespace);
            var o = doc.CreateElement("EncapsulatedOCSPValue", XadesUris.XadesNamespace);
            o.InnerText = Convert.ToBase64String([0x30, 0x00]);
            ocspVals.AppendChild(o);
            rv.AppendChild(ocspVals);
            usp.AppendChild(rv);

            using var ms = new MemoryStream();
            doc.Save(ms);
            ltvXml = ms.ToArray();
        }

        // Extract SignatureValue for the archive timestamp messageImprint
        var parseDoc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        parseDoc.Load(new MemoryStream(ltvXml));
        var parseNs = new System.Xml.XmlNamespaceManager(parseDoc.NameTable);
        parseNs.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        parseNs.AddNamespace("xades", XadesUris.XadesNamespace);
        parseNs.AddNamespace("xades141", XadesUris.Xades141Namespace);

        var sigValEl = parseDoc.SelectSingleNode("//ds:Signature/ds:SignatureValue", parseNs) as System.Xml.XmlElement;
        if (sigValEl is null)
        {
            throw new InvalidOperationException("No SignatureValue");
        }

        byte[] sigValueBytes = Convert.FromBase64String(sigValEl.InnerText.Trim());
        byte[] preImageHash = SHA256.HashData(sigValueBytes);

        // Build synthetic archive timestamp token
        byte[] archiveToken = BuildSyntheticTsaToken(s_tsaKey, s_tsaCert, preImageHash);

        // Embed archive timestamp using xades141 namespace
        var sigEl2 = parseDoc.SelectSingleNode("//ds:Signature", parseNs) as System.Xml.XmlElement;
        if (sigEl2 is null)
        {
            throw new InvalidOperationException("No Signature element");
        }

        var qp2 = sigEl2.SelectSingleNode("ds:Object/xades:QualifyingProperties", parseNs) as System.Xml.XmlElement;
        if (qp2 is null)
        {
            throw new InvalidOperationException("No QualifyingProperties");
        }

        var usp2 = EnsureTestUnsignedSignatureProperties(parseDoc, qp2, parseNs);

        var ats = parseDoc.CreateElement("ArchiveTimeStamp", XadesUris.Xades141Namespace);
        ats.SetAttribute("Id", "ATS-test");
        var encAts = parseDoc.CreateElement("EncapsulatedTimeStamp", XadesUris.Xades141Namespace);
        encAts.InnerText = Convert.ToBase64String(archiveToken);
        ats.AppendChild(encAts);
        usp2.AppendChild(ats);

        using var ms2 = new MemoryStream();
        parseDoc.Save(ms2);
        byte[] ltaXml = ms2.ToArray();

        // Validate
        var validator = new XadesSignatureValidator();
        var result = validator.Validate(ltaXml, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        result.HasValidArchiveTimeStamp.ShouldBe(true, diag);
        result.DetectedLevel.ShouldBe(XadesLevel.Archive);
    }

    [Fact]
    public async Task SignWithDetailsAsync_ReturnsCorrectLevelFlags()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>flags test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        // B-B
        var bbResult = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .WithLevel(XadesLevel.Basic)
            .SignWithDetailsAsync();

        bbResult.TimestampApplied.ShouldBeFalse();
        bbResult.LtvDataEmbedded.ShouldBeFalse();
        bbResult.ArchiveTimestampApplied.ShouldBeFalse();

        // Basic (no explicit level)
        var defaultResult = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_cert)
            .SignWithDetailsAsync();

        defaultResult.TimestampApplied.ShouldBeFalse();
        defaultResult.LtvDataEmbedded.ShouldBeFalse();
        defaultResult.ArchiveTimestampApplied.ShouldBeFalse();
    }

    [Fact]
    public async Task SignThenValidate_EcdsaSha256_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>ecdsa test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_ecdsaCert)
            .SignAsync();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_ecdsaCert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        Assert.True(result.IsValid, diag);
        Assert.NotNull(result.SignerCertificate);
        Assert.Equal(s_ecdsaCert.Thumbprint, result.SignerCertificate.Thumbprint);
    }

    [Fact]
    public async Task SignThenValidate_RsaPssSha256_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>rsa-pss test</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithCertificate(s_rsaPssCert)
            .SignAsync();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_rsaPssCert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        Assert.True(result.IsValid, diag);
        Assert.NotNull(result.SignerCertificate);
        Assert.Equal(s_rsaPssCert.Thumbprint, result.SignerCertificate.Thumbprint);
    }

    [Fact]
    public async Task SignThenValidate_ExternalSigner_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>external</doc>";
        byte[] xmlBytes = System.Text.Encoding.UTF8.GetBytes(xml);

        byte[] signed = await XadesSigner.Document(xmlBytes)
            .WithExternalSigner(s_cert,
                async data =>
                {
                    using var rsa = s_cert.GetRSAPrivateKey()!;
                    return await Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                },
                "1.2.840.113549.1.1.11")
            .SignAsync();

        var validator = new XadesSignatureValidator();
        var result = validator.Validate(signed, trustAnchors: [s_cert]);

        string diag = "Errors: " + string.Join("; ", result.Errors) +
                       " | Warnings: " + string.Join("; ", result.Warnings);
        Assert.True(result.IsValid, diag);
        Assert.NotNull(result.SignerCertificate);
        Assert.Equal(s_cert.Thumbprint, result.SignerCertificate.Thumbprint);
    }

    // ===== Batch 1: Error path / argument validation tests =====

    [Fact]
    public void XadesSigner_Document_NullData_Throws() =>
        Should.Throw<ArgumentNullException>(() => XadesSigner.Document(null!));

    [Fact]
    public async Task XadesSigner_SignAsync_NullData_Throws() =>
        await Should.ThrowAsync<ArgumentNullException>(() => XadesSigner.SignAsync(null!, s_cert));

    [Fact]
    public async Task XadesSigner_SignAsync_NullCert_Throws()
    {
        byte[] data = "test"u8.ToArray();
        await Should.ThrowAsync<ArgumentNullException>(() => XadesSigner.SignAsync(data, null!));
    }

    [Fact]
    public async Task XadesSigner_SignAsync_CertWithoutPrivateKey_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>no key</doc>";
        await Should.ThrowAsync<ArgumentException>(() =>
            XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_certNoKey));
    }

    [Fact]
    public async Task Builder_WithFormDetached_ThrowsNotSupported()
    {
        string xml = "<?xml version=\"1.0\"?><doc>detached</doc>";
        await Should.ThrowAsync<NotSupportedException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithCertificate(s_cert)
                .WithForm(XadesForm.Detached)
                .SignAsync());
    }

    [Fact]
    public async Task Builder_WithFormEnveloping_ThrowsNotSupported()
    {
        string xml = "<?xml version=\"1.0\"?><doc>enveloping</doc>";
        await Should.ThrowAsync<NotSupportedException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithCertificate(s_cert)
                .WithForm(XadesForm.Enveloping)
                .SignAsync());
    }

    [Fact]
    public async Task Builder_SignWithDetails_NoCertificate_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>no cert</doc>";
        await Should.ThrowAsync<InvalidOperationException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml)).SignAsync());
    }

    [Fact]
    public async Task Builder_WithExternalSigner_NullCallback_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>null cb</doc>";
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithExternalSigner(s_cert, null!, "1.2.840.113549.1.1.11"));
    }

    [Fact]
    public void Builder_WithExternalSigner_EmptyOid_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>empty oid</doc>";
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithExternalSigner(s_cert, async d => d, ""));
    }

    [Fact]
    public async Task Builder_ExternalSigner_ReturnsNull_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>null sig</doc>";
        await Should.ThrowAsync<InvalidOperationException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithExternalSigner(s_cert, _ => Task.FromResult<byte[]>(null!), "1.2.840.113549.1.1.11")
                .SignAsync());
    }

    [Fact]
    public void Builder_WithTimestamp_NullUrl_Throws()
    {
        string xml = "<?xml version=\"1.0\"?><doc>ts null</doc>";
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml)).WithTimestamp(null!));
    }

    [Fact]
    public void Builder_WithTimestamp_EmptyUrl_Throws()
    {
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document([]).WithTimestamp(""));
    }

    [Fact]
    public void Builder_WithSignerRoles_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithSignerRoles(null!));
    }

    [Fact]
    public void Builder_WithSignerRole_Null_Throws()
    {
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document([]).WithSignerRole(null!));
    }

    [Fact]
    public void Builder_WithSignerRole_Empty_Throws()
    {
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document([]).WithSignerRole(""));
    }

    [Fact]
    public void Builder_WithDataObjectFormat_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithDataObjectFormat(null!));
    }

    [Fact]
    public void Builder_WithLogger_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithLogger(null!));
    }

    [Fact]
    public void Builder_WithHttpClient_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithHttpClient(null!));
    }

    [Fact]
    public void Builder_WithRevocationHttpClient_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithRevocationHttpClient(null!));
    }

    [Fact]
    public void Builder_WithSignaturePolicy_NullOid_Throws()
    {
        Should.Throw<ArgumentException>(() =>
            XadesSigner.Document([]).WithSignaturePolicy(null!));
    }

    [Fact]
    public void Builder_WithCertificate_Null_Throws()
    {
        Should.Throw<ArgumentNullException>(() =>
            XadesSigner.Document([]).WithCertificate(null!));
    }

    // ===== Batch 3: Algorithm variant tests =====

    [Fact]
    public async Task SignThenValidate_EcdsaSha384_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\"?><doc>ecdsa384</doc>";
        byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(s_ecdsaCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [s_ecdsaCert]);
        Assert.True(result.IsValid, "Errors: " + string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignThenValidate_EcdsaSha512_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\"?><doc>ecdsa512</doc>";
        byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(s_ecdsaCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [s_ecdsaCert]);
        Assert.True(result.IsValid, "Errors: " + string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignThenValidate_RsaPssSha384_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\"?><doc>pss384</doc>";
        byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(s_rsaPssCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA384)
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [s_rsaPssCert]);
        Assert.True(result.IsValid, "Errors: " + string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignThenValidate_RsaPssSha512_RoundTripValid()
    {
        string xml = "<?xml version=\"1.0\"?><doc>pss512</doc>";
        byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(s_rsaPssCert)
            .WithHashAlgorithm(HashAlgorithmName.SHA512)
            .SignAsync();

        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [s_rsaPssCert]);
        Assert.True(result.IsValid, "Errors: " + string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task SignAsync_WithAllCommitmentTypes_IncludeCorrectOids()
    {
        string xml = "<?xml version=\"1.0\"?><doc>commitments</doc>";
        var types = new (CommitmentType Type, string Oid)[]
        {
            (CommitmentType.ProofOfOrigin, Oids.ProofOfOrigin),
            (CommitmentType.ProofOfReceipt, Oids.ProofOfReceipt),
            (CommitmentType.ProofOfDelivery, Oids.ProofOfDelivery),
            (CommitmentType.ProofOfSender, Oids.ProofOfSender),
            (CommitmentType.ProofOfApproval, Oids.ProofOfApproval),
            (CommitmentType.ProofOfCreation, Oids.ProofOfCreation),
        };

        foreach (var (type, oid) in types)
        {
            byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
                .WithCertificate(s_cert)
                .WithCommitmentType(type)
                .SignAsync();

            string text = System.Text.Encoding.UTF8.GetString(signed);
            Assert.Contains(oid, text);
        }
    }

    [Fact]
    public async Task SignAsync_WithExtraCertificates_IncludesInKeyInfo()
    {
        using RSA extraKey = RSA.Create(2048);
        var extraCert = TestCertificateFactory.CreateSelfSignedCert("CN=Extra Cert, O=Tests");
        string xml = "<?xml version=\"1.0\"?><doc>extra certs</doc>";

        byte[] signed = await XadesSigner.Document(System.Text.Encoding.UTF8.GetBytes(xml))
            .WithCertificate(s_cert, [extraCert])
            .SignAsync();

        string text = System.Text.Encoding.UTF8.GetString(signed);
        text.ShouldContain(Convert.ToBase64String(extraCert.RawData));
    }

    // ===== Batch 4: Validation edge cases =====

    [Fact]
    public async Task Validate_DigestMismatch_ReturnsFalse()
    {
        string xml = "<?xml version=\"1.0\"?><doc>original</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        // Tamper the document content (not the signature) so reference digest won't match
        string text = System.Text.Encoding.UTF8.GetString(signed);
        text = text.Replace(">original<", ">tampered<");
        byte[] tampered = System.Text.Encoding.UTF8.GetBytes(text);

        var result = new XadesSignatureValidator().Validate(tampered, trustAnchors: [s_cert]);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_SignatureValueMissing_ReturnsFalse()
    {
        string xml = "<?xml version=\"1.0\"?><doc>no sigval</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        // Remove SignatureValue element
        string text = System.Text.Encoding.UTF8.GetString(signed);
        var doc = new System.Xml.XmlDocument();
        doc.LoadXml(text);
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        var sigVal = doc.SelectSingleNode("//ds:Signature/ds:SignatureValue", ns);
        sigVal?.ParentNode?.RemoveChild(sigVal);

        using var ms = new MemoryStream();
        doc.Save(ms);
        var result = new XadesSignatureValidator().Validate(ms.ToArray(), trustAnchors: [s_cert]);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_SignedInfoMissingSignatureMethod_ReturnsFalse()
    {
        string xml = "<?xml version=\"1.0\"?><doc>no sigmethod</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        string text = System.Text.Encoding.UTF8.GetString(signed);
        var doc = new System.Xml.XmlDocument();
        doc.LoadXml(text);
        var ns = new System.Xml.XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        var sigMethod = doc.SelectSingleNode("//ds:Signature/ds:SignedInfo/ds:SignatureMethod", ns);
        sigMethod?.ParentNode?.RemoveChild(sigMethod);

        using var ms = new MemoryStream();
        doc.Save(ms);
        var result = new XadesSignatureValidator().Validate(ms.ToArray(), trustAnchors: [s_cert]);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_WrongTrustAnchor_ChainFails()
    {
        using RSA otherKey = RSA.Create(2048);
        var otherCert = TestCertificateFactory.CreateSelfSignedCert("CN=Other, O=Tests");
        string xml = "<?xml version=\"1.0\"?><doc>wrong anchor</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        var result = new XadesSignatureValidator().Validate(signed, trustAnchors: [otherCert]);
        Assert.False(result.IsCertificateChainValid);
    }

    [Fact]
    public async Task Validate_QualifyingPropertiesTargetMismatch_Warns()
    {
        string xml = "<?xml version=\"1.0\"?><doc>qp mismatch</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        string text = System.Text.Encoding.UTF8.GetString(signed);
        text = text.Replace("Target=\"#", "Target=\"#wrong-");

        var result = new XadesSignatureValidator().Validate(System.Text.Encoding.UTF8.GetBytes(text), trustAnchors: [s_cert]);
        Assert.Contains(result.Warnings, w => w.Contains("Target") && w.Contains("does not match"));
    }

    [Fact]
    public async Task Validate_SignedPropertiesReferenceTypeMissing_Warns()
    {
        string xml = "<?xml version=\"1.0\"?><doc>missing type</doc>";
        byte[] signed = await XadesSigner.SignAsync(System.Text.Encoding.UTF8.GetBytes(xml), s_cert);

        string text = System.Text.Encoding.UTF8.GetString(signed);
        text = text.Replace("Type=\"http://uri.etsi.org/01903#SignedProperties\"", "");

        var result = new XadesSignatureValidator().Validate(System.Text.Encoding.UTF8.GetBytes(text), trustAnchors: [s_cert]);
        Assert.Contains(result.Warnings, w => w.Contains("Type") && w.Contains("SignedProperties"));
    }

    [Fact]
    public void Validate_NoXadesSignedProperties_Warns()
    {
        // Plain XMLDSig without any XAdES properties
        string xml = "<?xml version=\"1.0\"?><doc><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>dGVzdA==</DigestValue></Reference></SignedInfo><SignatureValue>dGVzdA==</SignatureValue></Signature></doc>";

        var result = new XadesSignatureValidator().Validate(System.Text.Encoding.UTF8.GetBytes(xml));
        Assert.Contains(result.Warnings, w => w.Contains("no XAdES") || w.Contains("SignedProperties"));
        Assert.False(result.IsValid);
    }

    private static System.Xml.XmlElement EnsureTestUnsignedSignatureProperties(
        System.Xml.XmlDocument doc,
        System.Xml.XmlElement qp,
        System.Xml.XmlNamespaceManager ns)
    {
        if (qp.SelectSingleNode("xades:UnsignedProperties", ns) is not System.Xml.XmlElement up)
        {
            up = doc.CreateElement("UnsignedProperties", XadesUris.XadesNamespace);
            qp.AppendChild(up);
        }

        if (up.SelectSingleNode("xades:UnsignedSignatureProperties", ns) is not System.Xml.XmlElement usp)
        {
            usp = doc.CreateElement("UnsignedSignatureProperties", XadesUris.XadesNamespace);
            up.AppendChild(usp);
        }

        return usp;
    }
}
