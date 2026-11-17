using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Adobe.Aatl.Tests;

/// <summary>The publisher and the certification authorities, made once for the class: generating their RSA keys is most of the time.</summary>
public sealed class AatlFixture : IDisposable
{
    public const string HardwarePolicy = "1.3.6.1.4.1.99999.1.1";
    public const string SoftwarePolicy = "1.3.6.1.4.1.99999.1.2";

    internal AatlListBuilder Lists { get; } = new();

    /// <summary>An authority the list trusts for every certificate.</summary>
    internal PolicyCa Open { get; } = new("Open CA");

    /// <summary>An authority the list trusts only for the hardware policy.</summary>
    internal PolicyCa Restricted { get; } = new("Restricted CA");

    /// <summary>An authority the list took out (ImportAction 3).</summary>
    internal PolicyCa Removed { get; } = new("Removed CA");

    /// <summary>An authority the list names without making it a trusted root.</summary>
    internal PolicyCa NotARoot { get; } = new("Listed CA");

    /// <summary>An authority the list does not have.</summary>
    internal PolicyCa Unknown { get; } = new("Unknown CA");

    internal IReadOnlyList<TestIdentity> Identities =>
    [
        new(Open.Root),
        new(Restricted.Root, Action: 2, Root: true, HardwarePolicy, "1.3.6.1.4.1.99999.1.9"),
        new(Removed.Root, Action: 3),
        new(NotARoot.Root, Action: 1, Root: false),
    ];

    public void Dispose()
    {
        Lists.Dispose();
        Open.Dispose();
        Restricted.Dispose();
        Removed.Dispose();
        NotARoot.Dispose();
        Unknown.Dispose();
    }
}

[Trait("Category", "Unit")]
public sealed class AatlListTests(AatlFixture fixture) : IClassFixture<AatlFixture>
{
    [Fact]
    public async Task LoadAsync_SignedList_ReadsTheIdentitiesAndTheirTrust()
    {
        var signedAt = new DateTimeOffset(2026, 11, 12, 13, 42, 17, TimeSpan.Zero);
        byte[] pdf = await fixture.Lists.ListAsync(fixture.Identities, signedAt);

        var list = await AatlList.LoadAsync(pdf, fixture.Lists.Options);

        list.Identities.Count.ShouldBe(4);
        list.SignedAt.ShouldBe(signedAt);
        list.Sha256.ShouldBe(Convert.ToHexString(SHA256.HashData(pdf)).ToLowerInvariant());
        list.RegionCode.ShouldBe("AATL");
        list.DisplayName.ShouldContain("2026-11-12");
        list.GetTrustAnchors().Select(c => c.Thumbprint).ShouldBe([fixture.Open.Root.Thumbprint, fixture.Restricted.Root.Thumbprint], ignoreOrder: true);
        list.GetIntermediateCertificates().ShouldBeEmpty();

        var restricted = list.Find(fixture.Restricted.Root).ShouldNotBeNull();
        restricted.ImportAction.ShouldBe(2);
        restricted.IsAnchor.ShouldBeTrue();
        restricted.CertificatePolicies.ShouldBe([AatlFixture.HardwarePolicy, "1.3.6.1.4.1.99999.1.9"]);
        restricted.PolicyDescription.ShouldBe("Hardware");
        restricted.Source.ShouldBe("AATL");
        restricted.IsTrustedForCertifiedDocuments.ShouldBeTrue();

        list.Find(fixture.Open.Root).ShouldNotBeNull().HasPolicyRestrictions.ShouldBeFalse();
        list.Find(fixture.Removed.Root).ShouldNotBeNull().IsAnchor.ShouldBeFalse();
        list.Find(fixture.NotARoot.Root).ShouldNotBeNull().IsAnchor.ShouldBeFalse();
        list.Find(fixture.Unknown.Root).ShouldBeNull();
    }

    [Fact]
    public async Task LoadAsync_SignedUnderAnotherRoot_IsRefused()
    {
        using var forger = new AatlListBuilder();
        byte[] pdf = await forger.ListAsync(fixture.Identities);

        var ex = await Should.ThrowAsync<CryptographicException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.Message.ShouldContain("not signed by its publisher");
    }

    [Fact]
    public async Task LoadAsync_TamperedAfterSigning_IsRefused()
    {
        byte[] pdf = await fixture.Lists.ListAsync(fixture.Identities);
        int target = Encoding.Latin1.GetString(pdf).IndexOf("/Type /Catalog", StringComparison.Ordinal);
        pdf[target + 1] = (byte)'X';

        await Should.ThrowAsync<CryptographicException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));
    }

    [Fact]
    public async Task LoadAsync_ContentAfterTheSignature_IsRefused()
    {
        byte[] pdf = [.. await fixture.Lists.ListAsync(fixture.Identities), .. "\n% appended"u8];

        var ex = await Should.ThrowAsync<CryptographicException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.Message.ShouldContain("does not cover the whole file");
    }

    [Fact]
    public async Task LoadAsync_ObjectsHiddenInTheSignaturesOwnContents_AreNotRead()
    {
        // The /Contents of a signature is the one part of the file its ByteRange leaves out. A forger who cannot touch
        // the signed bytes can still write there: here, after the signature's hex, a later "revision" of the embedded
        // file with an authority of the forger's own.
        byte[] pdf = await fixture.Lists.ListAsync(fixture.Identities);
        string text = Encoding.Latin1.GetString(pdf);
        string forged = AatlListBuilder.Xml([new TestIdentity(fixture.Unknown.Root)]);
        string injected = $">\n6 0 obj\n<< /Type /EmbeddedFile /Length {Encoding.ASCII.GetByteCount(forged)} >>\nstream\n{forged}\nendstream\nendobj\n<";
        int contents = text.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
        int end = text.IndexOf('>', contents);
        int padding = text.LastIndexOf("0000", end, StringComparison.Ordinal);
        padding.ShouldBeGreaterThan(contents);
        int start = end - injected.Length;
        text.AsSpan(start, injected.Length).ToString().Trim('0').ShouldBeEmpty("the injection must fit in the padding of the placeholder");
        Encoding.Latin1.GetBytes(injected).CopyTo(pdf, start);

        var ex = await Record.ExceptionAsync(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.ShouldBeOfType<CryptographicException>("a list with anything but the signature in /Contents must be refused");
    }

    [Theory]
    [InlineData("<3082abCD00>", true)]
    [InlineData("<>", true)]
    [InlineData("<3082>\n6 0 obj\nendobj\n<00>", false)]
    [InlineData("<30 82>", false)]
    [InlineData("<3082", false)]
    [InlineData("(3082)", false)]
    public void HoldsOnlyTheSignature_TheBytesTheSignatureLeavesOut_MustBeItsHexadecimalAlone(string contents, bool expected)
    {
        // "before" + contents + "after", with a ByteRange that leaves out the contents.
        byte[] pdf = Encoding.ASCII.GetBytes("before" + contents + "after");
        var range = new SimpleSign.PAdES.Pdf.PdfByteRange { Offset1 = 0, Length1 = 6, Offset2 = 6 + contents.Length, Length2 = 5 };

        AatlList.HoldsOnlyTheSignature(pdf, range).ShouldBe(expected);
    }

    [Fact]
    public async Task LoadAsync_NotSigned_IsRefused()
    {
        byte[] pdf = TestPdfFactory.CreatePdfWithAttachments((AatlList.SettingsFileName, Encoding.UTF8.GetBytes(AatlListBuilder.Xml(fixture.Identities))));

        var ex = await Should.ThrowAsync<CryptographicException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.Message.ShouldContain("not signed");
    }

    [Fact]
    public async Task LoadAsync_NotAPdf_IsRefused() =>
        await Should.ThrowAsync<Exception>(() => AatlList.LoadAsync("not a pdf"u8.ToArray(), fixture.Lists.Options));

    [Fact]
    public async Task LoadAsync_SignedPdfWithoutTheSettingsFile_IsRefused()
    {
        byte[] pdf = await fixture.Lists.SignAsync(TestPdfFactory.CreatePdfWithAttachments(("other.xml", "<x/>"u8.ToArray())));

        var ex = await Should.ThrowAsync<InvalidDataException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.Message.ShouldContain(AatlList.SettingsFileName);
    }

    [Theory]
    [InlineData("<SecuritySettings><TrustedIdentities>", "not well-formed")]
    [InlineData("<SecuritySettings/>", "TrustedIdentities")]
    [InlineData("<SecuritySettings><TrustedIdentities><Identity><Certificate>AAAA</Certificate></Identity></TrustedIdentities></SecuritySettings>", "identity 1")]
    [InlineData("<!DOCTYPE x [<!ENTITY e \"x\">]><SecuritySettings><TrustedIdentities/></SecuritySettings>", "not well-formed")]
    public async Task LoadAsync_SettingsThatCannotBeRead_IsRefused(string xml, string expected)
    {
        byte[] pdf = await fixture.Lists.SignAsync(TestPdfFactory.CreatePdfWithAttachments((AatlList.SettingsFileName, Encoding.UTF8.GetBytes(xml))));

        var ex = await Should.ThrowAsync<InvalidDataException>(() => AatlList.LoadAsync(pdf, fixture.Lists.Options));

        ex.Message.ShouldContain(expected);
    }

    [Fact]
    public async Task LoadAsync_IdentityWithoutAnAction_GivesNoTrust()
    {
        string xml = AatlListBuilder.Xml([new TestIdentity(fixture.Open.Root)]).Replace("<ImportAction>1</ImportAction>", "", StringComparison.Ordinal);
        byte[] pdf = await fixture.Lists.SignAsync(TestPdfFactory.CreatePdfWithAttachments((AatlList.SettingsFileName, Encoding.UTF8.GetBytes(xml))));

        var list = await AatlList.LoadAsync(pdf, fixture.Lists.Options);

        list.Identities.ShouldHaveSingleItem().IsRemoved.ShouldBeTrue();
        list.GetTrustAnchors().ShouldBeEmpty();
    }

    [Fact]
    public async Task WhyRefused_RestrictedAnchor_AsksThePoliciesOfTheSignerCertificate()
    {
        var list = await LoadAsync();
        using var hardware = fixture.Restricted.Issue("Hardware signer", AatlFixture.SoftwarePolicy, AatlFixture.HardwarePolicy);
        using var software = fixture.Restricted.Issue("Software signer", AatlFixture.SoftwarePolicy);
        using var none = fixture.Restricted.Issue("No policy signer");

        list.WhyRefused(fixture.Restricted.Root, [hardware, fixture.Restricted.Root]).ShouldBeNull();
        list.WhyRefused(fixture.Restricted.Root, [software, fixture.Restricted.Root]).ShouldNotBeNull().ShouldContain(AatlFixture.HardwarePolicy);
        list.WhyRefused(fixture.Restricted.Root, [none, fixture.Restricted.Root]).ShouldNotBeNull().ShouldContain("Restricted CA");
        list.WhyRefused(fixture.Open.Root, [none, fixture.Open.Root]).ShouldBeNull();
    }

    [Fact]
    public void CertificatePoliciesOf_ReadsTheExtension()
    {
        using var signer = fixture.Open.Issue("Two policies", AatlFixture.HardwarePolicy, AatlFixture.SoftwarePolicy);

        AatlList.CertificatePoliciesOf(signer).ShouldBe([AatlFixture.HardwarePolicy, AatlFixture.SoftwarePolicy]);
        AatlList.CertificatePoliciesOf(fixture.Open.Root).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("open", true)]
    [InlineData("restricted-hardware", true)]
    [InlineData("restricted-software", false)]
    [InlineData("removed", false)]
    [InlineData("not-a-root", false)]
    [InlineData("unknown", false)]
    public async Task Validate_UnderTheProfile_TrustsWhatAcrobatWould(string signer, bool trusted)
    {
        var profile = AatlProfile.Create(new AatlExtension(await LoadAsync()));
        var (ca, policies) = Signer(signer);
        using var certificate = ca.Issue("Signer", policies);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(certificate, [ca.Root]).SignAsync();

        using var stream = new MemoryStream(signed);
        var result = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, Profile = profile }).ValidateAsync(stream))
            .ShouldHaveSingleItem();

        result.IsCertificateChainValid.ShouldBe(trusted, string.Join("; ", result.Errors));
        if (signer == "restricted-software")
        {
            result.Errors.ShouldContain(e => e.Contains("Adobe Approved Trust List", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Profile_HasTheDefaultPoliciesAndDoesNotTrustTheSystemRoots()
    {
        var extension = new AatlExtension(await LoadAsync());

        var profile = AatlProfile.Create(extension);

        profile.Name.ShouldBe("aatl");
        profile.TrustSystemRoots.ShouldBeFalse();
        profile.CanSign.ShouldBeTrue();
        profile.SignatureQualifiers.ShouldBeEmpty();
        profile.ChainValidationProviders.ShouldBeEmpty();
        profile.ConstrainedTrustAnchors.ShouldHaveSingleItem();
        extension.Source.ShouldBeNull();
        extension.List.GetTrustAnchors().Count.ShouldBe(2);
        AatlExtension.ListSigners.ShouldHaveSingleItem().Subject.ShouldContain("Adobe Root CA G2");
    }

    [Fact]
    public async Task Profile_WithTrustFromAProfileThatTrustsTheAuthorityPlainly_AcceptsTheSoftwareCertificate()
    {
        var aatl = AatlProfile.Create(new AatlExtension(await LoadAsync()));
        var other = new TrustProfile("other", "Other", null, SimpleSign.Core.Policies.ValidationPolicy.Default, [new InMemoryTrustAnchors(fixture.Restricted.Root)], []);
        using var certificate = fixture.Restricted.Issue("Software signer", AatlFixture.SoftwarePolicy);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(certificate, [fixture.Restricted.Root]).SignAsync();

        using var stream = new MemoryStream(signed);
        var result = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, Profile = aatl.WithTrustFrom(other) }).ValidateAsync(stream))
            .ShouldHaveSingleItem();

        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task Sign_UnderTheProfileWithACertificateThePoliciesExclude_IsRefused()
    {
        var profile = AatlProfile.Create(new AatlExtension(await LoadAsync()));
        using var software = fixture.Restricted.Issue("Software signer", AatlFixture.SoftwarePolicy);

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(software, [fixture.Restricted.Root])
            .WithProfile(profile)
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [Fact]
    public async Task Sign_UnderTheProfileWithACertificateTheListAccepts_Signs()
    {
        var profile = AatlProfile.Create(new AatlExtension(await LoadAsync()));
        using var hardware = fixture.Restricted.Issue("Hardware signer", AatlFixture.HardwarePolicy);

        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(hardware, [fixture.Restricted.Root])
            .WithProfile(profile)
            .SignAsync();

        signed.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Validate_SignatureAsAcrobatMakesIt_IsNotIndeterminateForItsMissingCertificateReference()
    {
        var profile = AatlProfile.Create(new AatlExtension(await LoadAsync()));
        using var certificate = fixture.Open.Issue("Acrobat user");
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate, [fixture.Open.Root])
            .WithSubFilter(SimpleSign.PAdES.Signing.PdfSignatureSubFilter.AdbePkcs7Detached)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var underProfile = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, Profile = profile }).ValidateAsync(stream))
            .ShouldHaveSingleItem();

        underProfile.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", underProfile.Errors));
        underProfile.SubIndication.ShouldNotBe(SignatureSubIndication.NoSigningCertificateFound);
    }

    private (PolicyCa Ca, string[] Policies) Signer(string name) => name switch
    {
        "open" => (fixture.Open, []),
        "restricted-hardware" => (fixture.Restricted, [AatlFixture.HardwarePolicy]),
        "restricted-software" => (fixture.Restricted, [AatlFixture.SoftwarePolicy]),
        "removed" => (fixture.Removed, []),
        "not-a-root" => (fixture.NotARoot, []),
        _ => (fixture.Unknown, []),
    };

    private async Task<AatlList> LoadAsync() =>
        await AatlList.LoadAsync(await fixture.Lists.ListAsync(fixture.Identities), fixture.Lists.Options);
}
