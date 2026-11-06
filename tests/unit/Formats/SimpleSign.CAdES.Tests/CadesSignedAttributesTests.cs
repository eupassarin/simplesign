using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>
/// The optional signed attributes of ETSI EN 319 122-1 §5.2.4 to §5.2.6: how they are encoded and
/// how they are read back from a signature.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CadesSignedAttributesTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _data = "signed attributes"u8.ToArray();

    public void Dispose() => _cert.Dispose();

    [Fact]
    public void EncodeSignerLocation_CountryOnly_UsesAnExplicitContextTag()
    {
        var attribute = CadesSignedAttributes.EncodeSignerLocation(new CadesSignerLocation { CountryName = "BR" });

        // SEQUENCE { [0] EXPLICIT { UTF8String "BR" } }
        attribute.Oid.ShouldBe("1.2.840.113549.1.9.16.2.17");
        attribute.DerValue.ShouldBe([0x30, 0x06, 0xA0, 0x04, 0x0C, 0x02, 0x42, 0x52]);
    }

    [Fact]
    public void EncodeSignerLocation_PostalAddress_IsASequenceInsideTag2()
    {
        var attribute = CadesSignedAttributes.EncodeSignerLocation(new CadesSignerLocation { PostalAddress = ["A", "B"] });

        // SEQUENCE { [2] EXPLICIT { SEQUENCE { UTF8String "A", UTF8String "B" } } }
        attribute.DerValue.ShouldBe([0x30, 0x0A, 0xA2, 0x08, 0x30, 0x06, 0x0C, 0x01, 0x41, 0x0C, 0x01, 0x42]);
    }

    [Fact]
    public void EncodeMimeType_IsAUtf8StringUnderTheEtsiOid()
    {
        var attribute = CadesSignedAttributes.EncodeMimeType("a/b");

        attribute.Oid.ShouldBe("0.4.0.1733.2.1");
        attribute.DerValue.ShouldBe([0x0C, 0x03, 0x61, 0x2F, 0x62]);
    }

    [Fact]
    public void EncodeContentHints_WithoutDescription_HoldsOnlyTheContentType()
    {
        var attribute = CadesSignedAttributes.EncodeContentHints(new CadesContentHints());

        // SEQUENCE { OID id-data }
        attribute.Oid.ShouldBe("1.2.840.113549.1.9.16.2.4");
        attribute.DerValue.ShouldBe([0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]);
    }

    [Fact]
    public void EncodeClaimedRoles_WritesOneRoleAttributePerRoleInClaimedAttributes()
    {
        var attribute = CadesSignedAttributes.EncodeClaimedRoles(["A"]);

        // SEQUENCE { [0] EXPLICIT { SEQUENCE OF { SEQUENCE { OID id-at-role, SET { UTF8String "A" } } } } }
        attribute.Oid.ShouldBe("0.4.0.19122.1.1");
        attribute.DerValue.ShouldBe(
        [
            0x30, 0x10, 0xA0, 0x0E, 0x30, 0x0C, 0x30, 0x0A,
            0x06, 0x03, 0x55, 0x04, 0x48, 0x31, 0x03, 0x0C, 0x01, 0x41,
        ]);
    }

    [Fact]
    public void EncodeSignerAttributes_AttributeCertificate_GoesInCertifiedAttributesUnderTag0()
    {
        byte[] attributeCertificate = [0x30, 0x03, 0x04, 0x01, 0xAA];

        var attribute = CadesSignedAttributes.EncodeSignerAttributes([], [attributeCertificate], []);

        // SEQUENCE { [1] EXPLICIT { SEQUENCE OF { [0] EXPLICIT { AttributeCertificate } } } }
        attribute.DerValue.ShouldBe([0x30, 0x0B, 0xA1, 0x09, 0x30, 0x07, 0xA0, 0x05, 0x30, 0x03, 0x04, 0x01, 0xAA]);
    }

    [Fact]
    public async Task SignAsync_AttributeCertificatesAndSignedAssertions_AreSignedAndReadBack()
    {
        byte[] attributeCertificate = [0x30, 0x03, 0x04, 0x01, 0xAA]; // stands for an attribute certificate: any single DER SEQUENCE is embedded as given
        byte[] saml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"u8.ToArray();

        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignerRole("Diretor")
            .WithAttributeCertificates([attributeCertificate])
            .WithSignedAssertions([CadesSignedAssertion.Saml(saml)])
            .SignAsync();

        var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);
        attributes.ClaimedRoles.ShouldBe(["Diretor"]);
        attributes.AttributeCertificates.ShouldHaveSingleItem().ToArray().ShouldBe(attributeCertificate);
        var assertion = attributes.SignedAssertions.ShouldHaveSingleItem();
        assertion.Oid.ShouldBe("0.4.0.19122.3.0");
        assertion.SamlAssertion().ShouldBe(saml);
        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]);
        report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
    }

    [Fact]
    public async Task SignAsync_OnlyAttributeCertificates_WritesNoClaimedAttributes()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert)
            .WithAttributeCertificates([new byte[] { 0x30, 0x03, 0x04, 0x01, 0xAA }]).SignAsync();

        var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);
        attributes.ClaimedRoles.ShouldBeEmpty();
        attributes.AttributeCertificates.ShouldHaveSingleItem();
        attributes.SignedAssertions.ShouldBeEmpty();
    }

    [Fact]
    public void WithAttributeCertificates_NotASingleDerSequence_Throws()
    {
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithAttributeCertificates([new byte[] { 0x04, 0x01, 0x00 }]));
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithAttributeCertificates([new byte[] { 0x30, 0x00, 0x00 }]));
    }

    [Fact]
    public void WithSignedAssertions_AssertionWithoutOid_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithSignedAssertions([new CadesSignedAssertion(" ", ReadOnlyMemory<byte>.Empty)]));

    [Fact]
    public void SamlAssertion_OtherKindOfAssertion_ReturnsNull() =>
        new CadesSignedAssertion("1.2.3", new byte[] { 0x04, 0x01, 0x78 }).SamlAssertion().ShouldBeNull();

    [Fact]
    public void Saml_EmptyAssertion_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSignedAssertion.Saml([]));

    [Fact]
    public async Task Read_SignatureWithEveryAttribute_ReturnsWhatWasSigned()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignerLocation(new CadesSignerLocation
            {
                CountryName = "BR",
                LocalityName = "São Paulo",
                PostalAddress = ["Av. Paulista, 1000", "Bela Vista"],
            })
            .WithContentHints(new CadesContentHints { Description = "Contrato de prestação de serviços" })
            .WithMimeType("application/pdf")
            .WithSignerRoles(["Diretor", "Procurador"])
            .SignAsync();

        var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);

        attributes.SignerLocation.ShouldNotBeNull();
        attributes.SignerLocation.CountryName.ShouldBe("BR");
        attributes.SignerLocation.LocalityName.ShouldBe("São Paulo");
        attributes.SignerLocation.PostalAddress.ShouldBe(["Av. Paulista, 1000", "Bela Vista"]);
        attributes.ContentHints.ShouldNotBeNull();
        attributes.ContentHints.Description.ShouldBe("Contrato de prestação de serviços");
        attributes.ContentHints.ContentTypeOid.ShouldBe(Oids.Data);
        attributes.MimeType.ShouldBe("application/pdf");
        attributes.ClaimedRoles.ShouldBe(["Diretor", "Procurador"]);
    }

    [Fact]
    public async Task Read_SignatureWithoutTheAttributes_ReturnsEmpty()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);

        attributes.SignerLocation.ShouldBeNull();
        attributes.ContentHints.ShouldBeNull();
        attributes.MimeType.ShouldBeNull();
        attributes.ClaimedRoles.ShouldBeEmpty();
    }

    [Fact]
    public void Read_RoleWrittenAsX509RoleSyntax_ReturnsTheRoleName()
    {
        // RoleSyntax ::= SEQUENCE { roleAuthority [0] GeneralNames OPTIONAL, roleName [1] GeneralName }
        var role = new AsnWriter(AsnEncodingRules.DER);
        using (role.PushSequence())
        using (role.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)))
        {
            role.WriteCharacterString(UniversalTagNumber.IA5String, "urn:role:director", new Asn1Tag(TagClass.ContextSpecific, 6));
        }

        var signerAttributes = new AsnWriter(AsnEncodingRules.DER);
        using (signerAttributes.PushSequence())
        using (signerAttributes.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
        using (signerAttributes.PushSequence())
        using (signerAttributes.PushSequence())
        {
            signerAttributes.WriteObjectIdentifier(Oids.RoleAttribute);
            using (signerAttributes.PushSetOf())
            {
                signerAttributes.WriteEncodedValue(role.Encode());
            }
        }

        var attributes = CadesSignedAttributes.Read(SignedAttributes((Oids.SignerAttributesV2, signerAttributes.Encode())));

        attributes.ClaimedRoles.ShouldBe(["urn:role:director"]);
    }

    [Fact]
    public void Read_LocationInPrintableString_IsDecoded()
    {
        var location = new AsnWriter(AsnEncodingRules.DER);
        using (location.PushSequence())
        using (location.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)))
        {
            location.WriteCharacterString(UniversalTagNumber.PrintableString, "Lisboa");
        }

        var attributes = CadesSignedAttributes.Read(SignedAttributes((Oids.SignerLocation, location.Encode())));

        attributes.SignerLocation.ShouldNotBeNull();
        attributes.SignerLocation.LocalityName.ShouldBe("Lisboa");
        attributes.SignerLocation.CountryName.ShouldBeNull();
        attributes.SignerLocation.PostalAddress.ShouldBeEmpty();
    }

    [Fact]
    public void Read_OneMalformedAttribute_StillReadsTheOthers()
    {
        byte[] notASequence = [0x02, 0x01, 0x05]; // an INTEGER where SignerLocation is expected
        var mimeType = CadesSignedAttributes.EncodeMimeType("text/plain");

        var attributes = CadesSignedAttributes.Read(SignedAttributes(
            (Oids.SignerLocation, notASequence), (mimeType.Oid, mimeType.DerValue)));

        attributes.SignerLocation.ShouldBeNull();
        attributes.MimeType.ShouldBe("text/plain");
    }

    [Fact]
    public void Read_NotASetOfAttributes_ReturnsEmpty()
    {
        var attributes = CadesSignedAttributes.Read([0x05, 0x00]);

        attributes.SignerLocation.ShouldBeNull();
        attributes.MimeType.ShouldBeNull();
        attributes.ClaimedRoles.ShouldBeEmpty();
    }

    [Fact]
    public async Task SignAsync_WithEveryAttribute_StillValidates()
    {
        byte[] cms = await CadesSigner.Document(_data)
            .WithCertificate(_cert)
            .WithSignerLocation(new CadesSignerLocation { CountryName = "BR" })
            .WithContentHints(new CadesContentHints { Description = "texto" })
            .WithMimeType("text/plain")
            .WithSignerRole("Diretor")
            .SignAsync();

        var report = new CadesSignatureValidator().ValidateAll(cms, _data, [_cert]);

        report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
    }

    [Fact]
    public void WithSignerLocation_NoField_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithSignerLocation(new CadesSignerLocation()));

    [Fact]
    public void WithSignerLocation_SevenPostalLines_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithSignerLocation(
            new CadesSignerLocation { PostalAddress = ["1", "2", "3", "4", "5", "6", "7"] }));

    [Fact]
    public void WithSignerLocation_EmptyPostalLine_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithSignerLocation(
            new CadesSignerLocation { PostalAddress = ["Rua A", " "] }));

    [Fact]
    public void WithContentHints_EmptyDescription_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithContentHints(new CadesContentHints { Description = "" }));

    [Fact]
    public void WithMimeType_Blank_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithMimeType(" "));

    [Fact]
    public async Task WithSignerRoles_OnlyBlankRoles_WritesNoAttribute()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).WithSignerRoles(["", "  "]).SignAsync();

        // An empty signer-attributes-v2 shall not be created (§5.2.6.1).
        HasSignedAttribute(cms, Oids.SignerAttributesV2).ShouldBeFalse();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SignAsync_CounterSignatureDescribingTheContent_Throws(bool mimeType)
    {
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();
        var builder = CadesSigner.CounterSign(signed).WithCertificate(_cert);
        builder = mimeType ? builder.WithMimeType("text/plain") : builder.WithContentHints(new CadesContentHints());

        var exception = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());

        exception.Message.ShouldContain("countersignature");
    }

    [Fact]
    public async Task SignAsync_CounterSignatureWithLocationAndRoles_IsAllowed()
    {
        byte[] signed = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        byte[] countersigned = await CadesSigner.CounterSign(signed)
            .WithCertificate(_cert)
            .WithSignerLocation(new CadesSignerLocation { LocalityName = "Recife" })
            .WithSignerRole("Testemunha")
            .SignAsync();

        var counter = CmsParser.Parse(countersigned).CounterSignatures.ShouldHaveSingleItem();
        var attributes = CadesSignedAttributes.Read(counter.SignedAttrs);
        attributes.SignerLocation!.LocalityName.ShouldBe("Recife");
        attributes.ClaimedRoles.ShouldBe(["Testemunha"]);
    }

    private static bool HasSignedAttribute(byte[] cms, string oid)
    {
        var set = new AsnReader(CmsParser.Parse(cms).SignedAttrs!, AsnEncodingRules.BER).ReadSetOf();
        while (set.HasData)
        {
            if (set.ReadSequence().ReadObjectIdentifier() == oid)
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] SignedAttributes(params (string Oid, byte[] Value)[] attributes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            foreach (var (oid, value) in attributes)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    using (writer.PushSetOf())
                    {
                        writer.WriteEncodedValue(value);
                    }
                }
            }
        }

        return writer.Encode();
    }
}
