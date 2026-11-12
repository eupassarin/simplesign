using Shouldly;
using SimpleSign.Sandbox.Pki;

namespace SimpleSign.Sandbox.Tests;

[Trait("Category", "Unit")]
public sealed class SandboxSubjectTests
{
    [Fact]
    public void Parse_DnWithSerialNumber_KeepsEveryAttributeInOrder()
    {
        var subject = SandboxSubject.Parse("CN=Juan Pérez, serialNumber=PNOPE-12345678, OU=Firma, O=Empresa SAC, C=PE");

        // Encoding order: least specific first.
        Encoded(subject).ShouldBe([("2.5.4.6", "PE"), ("2.5.4.10", "Empresa SAC"), ("2.5.4.11", "Firma"), ("2.5.4.5", "PNOPE-12345678"), ("2.5.4.3", "Juan Pérez")]);
    }

    [Fact]
    public void Parse_QuotedAndEscapedCommas_KeepsThemInTheValue() =>
        Encoded(SandboxSubject.Parse("CN=\"Pérez, Juan\", O=Empresa\\, SAC")).ShouldBe([("2.5.4.10", "Empresa, SAC"), ("2.5.4.3", "Pérez, Juan")]);

    [Fact]
    public void Build_Attributes_SameAsTheDnString() =>
        SandboxSubject.Build([new("CN", "Ana"), new("O", "Org"), new("C", "PE")]).RawData
            .ShouldBe(SandboxSubject.Parse("CN=Ana, O=Org, C=PE").RawData);

    [Fact]
    public void Parse_MultiValuedRdn_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Parse("CN=Ana+serialNumber=1"));

    [Fact]
    public void Build_SerialNumber_IsPrintableString()
    {
        var subject = SandboxSubject.Build([new("CN", "Ana"), new("serialNumber", "IDCPE-12345678")]);

        // PrintableString (0x13) for serialNumber, UTF8String (0x0C) for CN.
        byte[] der = subject.RawData;
        int at = Array.IndexOf(der, (byte)'I');
        der[at - 2].ShouldBe((byte)0x13);
    }

    [Theory]
    [InlineData("E", "a@b.c")]
    [InlineData("DC", "example")]
    public void Build_AttributeNotAccepted_Throws(string type, string value) =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([new("CN", "Ana"), new(type, value)]));

    [Fact]
    public void Build_WithoutCn_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([new("O", "Org")])).Message.ShouldContain("CN");

    [Fact]
    public void Build_ValueTooLong_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([new("CN", new string('a', SandboxSubject.MaxValueLength + 1))]));

    [Theory]
    [InlineData("pe")]
    [InlineData("PER")]
    public void Build_BadCountry_Throws(string country) =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([new("CN", "Ana"), new("C", country)]));

    [Fact]
    public void Build_SerialNumberNotPrintable_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([new("CN", "Ana"), new("serialNumber", "Ñ-1")]));

    [Fact]
    public void Build_TooManyAttributes_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Build([.. Enumerable.Range(0, SandboxSubject.MaxAttributes + 1).Select(i => new SubjectAttribute("OU", $"u{i}"))]));

    [Fact]
    public void Parse_EmailAttribute_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Parse("CN=Ana, E=ana@example.com"));

    [Fact]
    public void Parse_Garbage_Throws() =>
        Should.Throw<ArgumentException>(() => SandboxSubject.Parse("this is not a DN"));

    private static List<(string?, string?)> Encoded(System.Security.Cryptography.X509Certificates.X500DistinguishedName name) =>
        [.. name.EnumerateRelativeDistinguishedNames(reversed: false).Select(r => (r.GetSingleElementType().Value, r.GetSingleElementValue()))];
}
