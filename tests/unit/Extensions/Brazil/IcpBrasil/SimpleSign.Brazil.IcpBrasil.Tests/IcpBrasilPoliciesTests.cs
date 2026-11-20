using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

[Trait("Category", "Unit")]
public sealed class IcpBrasilPoliciesTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Theory]
    [InlineData("SigningCertificate/ProspectiveCertificateChain")]
    [InlineData("SigningCertificate/NotRevoked")]
    [InlineData("SigningCertificate/RevocationDataAvailable")]
    [InlineData("CACertificate/NotRevoked")]
    [InlineData("CACertificate/RevocationDataAvailable")]
    [InlineData("CACertificate/Cryptographic")]
    [InlineData("Timestamp/ProspectiveCertificateChain")]
    [InlineData("Timestamp/NotRevoked")]
    public void Signing_Constraint_IsFail(string path) =>
        IcpBrasilPolicies.Signing.Find(path).ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public async Task Signing_RootNotAmongTheAnchors_IsRefused()
    {
        using var other = new SyntheticPki();

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithSigningPolicy(IcpBrasilPolicies.Signing)
            .WithTrustAnchors(new InMemoryTrustAnchors(other.RootCa))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [Fact]
    public void Validation_SigningCertificateKeyUsage_FailsWithoutDigitalSignatureOrNonRepudiation()
    {
        var keyUsage = IcpBrasilPolicies.Validation.Find("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage").ShouldNotBeNull();

        keyUsage.Level.ShouldBe(ConstraintLevel.Fail);
        keyUsage.Ids.ShouldBe(["digitalSignature", "nonRepudiation"], ignoreOrder: true);
    }

    [Theory]
    [InlineData("SignatureConstraints/SignedAttributes/SigningCertificatePresent")]
    [InlineData("SignatureConstraints/SignedAttributes/CertDigestPresent")]
    public void Validation_SigningCertificateAttributeMissing_OnlyWarns(string path) =>
        IcpBrasilPolicies.Validation.Find(path).ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Warn);

    [Fact]
    public void Validation_SigningCertificateReference_MustStillMatch() =>
        IcpBrasilPolicies.Validation.Find("SignatureConstraints/SignedAttributes/CertDigestMatch").ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public void Validation_PolicyRules_IsFail() =>
        IcpBrasilPolicies.Validation.Find("SignatureConstraints/PolicyRules").ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public async Task Validation_ConformantAdRb_IsValid()
    {
        using var pki = TestPki.Create(leafExpired: false);
        byte[] signed = await SignAdRb(pki);

        var result = await Validate(pki, signed);

        result.Indication.ShouldBe(SignatureIndication.Valid, Report(result));
        result.ChainValidationMetadata!["BR.SignaturePolicyStatus"].ShouldBe("Valid");
        result.Constraints.ShouldContain(c => c.Id == PolicyRules && c.Status == ConstraintStatus.Passed);
    }

    [Fact]
    public async Task Validation_AdRbWithoutSigningCertificateAttribute_IsNotValid()
    {
        using var pki = TestPki.Create(leafExpired: false);
        byte[] signed = WithoutSigningCertificateV2(await SignAdRb(pki), pki);

        var result = await Validate(pki, signed);

        // DOC-ICP-15.03 mandates signing-certificate-v2: the policy the signature declares is broken. Not a chain
        // failure: the chain is still trusted.
        result.Indication.ShouldBe(SignatureIndication.Indeterminate, Report(result));
        result.SubIndication.ShouldBe(SignatureSubIndication.SigConstraintsFailure);
        result.ChainValidationMetadata!["BR.SignaturePolicyStatus"].ShouldBe("Invalid");
        result.Constraints.ShouldContain(c => c.Id == PolicyRules && c.Status == ConstraintStatus.Failed
            && c.Message.Contains(SigningCertificateV2, StringComparison.Ordinal));
        result.Warnings.ShouldNotContain(w => w.Contains("Signature policy:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validation_NoSignaturePolicy_PolicyRulesDoesNotApply()
    {
        using var pki = TestPki.Create(leafExpired: false);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(pki.Leaf, [pki.Ac, pki.Root])
            .SignAsync();

        var result = await Validate(pki, signed);

        result.Indication.ShouldBe(SignatureIndication.Valid, Report(result));
        result.ChainValidationMetadata!.ContainsKey("BR.SignaturePolicyStatus").ShouldBeFalse();
        result.Constraints.ShouldNotContain(c => c.Id == PolicyRules);
    }

    private const string PolicyRules = "SignatureConstraints/PolicyRules";
    private const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";

    private static Task<byte[]> SignAdRb(TestPki pki) =>
        PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(pki.Leaf, [pki.Ac, pki.Root])
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
            .SignAsync();

    private static async Task<SignatureValidationResult> Validate(TestPki pki, byte[] signed)
    {
        var icp = IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { AdditionalRoots = [pki.Root] });
        var validator = new PdfSignatureValidator(new ValidationOptions { Profile = icp, CheckRevocation = false });
        await using var stream = new MemoryStream(signed, writable: false);
        return (await validator.ValidateAsync(stream)).Single();
    }

    private static string Report(SignatureValidationResult result) =>
        $"{result.Indication}/{result.SubIndication}: " + string.Join("; ", result.Constraints
            .Where(c => c.Status == ConstraintStatus.Failed).Select(c => $"{c.Id}: {c.Message}"));

    /// <summary>
    /// The same PDF, its CMS made again with the signed attributes of the original but the ESS signing-certificate-v2:
    /// what Adobe Reader or Gov.br would write, yet still declaring the ICP-Brasil policy.
    /// </summary>
    private static byte[] WithoutSigningCertificateV2(byte[] pdf, TestPki pki)
    {
        string text = Encoding.Latin1.GetString(pdf);
        var range = Regex.Match(text, @"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]");
        int[] r = [.. Enumerable.Range(1, 4).Select(i => int.Parse(range.Groups[i].Value, CultureInfo.InvariantCulture))];
        byte[] content = [.. pdf.AsSpan(r[0], r[1]), .. pdf.AsSpan(r[2], r[3])];
        int hexStart = r[0] + r[1] + 1;
        int hexLength = r[2] - 1 - hexStart;
        byte[] contents = Convert.FromHexString(text.AsSpan(hexStart, hexLength));
        AsnDecoder.ReadEncodedValue(contents, AsnEncodingRules.BER, out _, out _, out int cmsLength);

        var original = new SignedCms();
        original.Decode(contents.AsSpan(0, cmsLength));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, pki.Leaf)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signer.Certificates.Add(pki.Ac);
        foreach (var attribute in original.SignerInfos[0].SignedAttributes)
        {
            if (attribute.Oid.Value is "1.2.840.113549.1.9.3" or "1.2.840.113549.1.9.4" or SigningCertificateV2)
            {
                continue;
            }

            signer.SignedAttributes.Add(new AsnEncodedData(attribute.Oid, attribute.Values[0].RawData));
        }

        var cms = new SignedCms(new ContentInfo(content), detached: true);
        cms.ComputeSignature(signer);
        string hex = Convert.ToHexString(cms.Encode());
        hex.Length.ShouldBeLessThanOrEqualTo(hexLength);
        byte[] result = [.. pdf];
        Encoding.Latin1.GetBytes(hex.PadRight(hexLength, '0')).CopyTo(result, hexStart);
        return result;
    }

    [Fact]
    public void Policies_ToJson_RoundTrip()
    {
        SigningPolicy.FromJson(IcpBrasilPolicies.Signing.ToJson()).Name.ShouldBe("ICP-Brasil");
        ValidationPolicy.FromJson(IcpBrasilPolicies.Validation.ToJson()).Name.ShouldBe("ICP-Brasil");
    }

    [Fact]
    public void Profile_Create_CarriesThePoliciesTheRootsAndTheChainValidation()
    {
        var profile = IcpBrasilProfile.Create();

        profile.Name.ShouldBe("icp-brasil");
        profile.SigningPolicy.ShouldBeSameAs(IcpBrasilPolicies.Signing);
        profile.ValidationPolicy.ShouldBeSameAs(IcpBrasilPolicies.Validation);
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
        profile.ChainValidationProviders.ShouldNotBeEmpty();
    }
}
