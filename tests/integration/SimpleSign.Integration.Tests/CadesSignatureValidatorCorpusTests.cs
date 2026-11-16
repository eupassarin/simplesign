using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Integration.Tests.Helpers;
using Xunit;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// <see cref="CadesSignatureValidator"/> on CAdES vectors from the EU DSS test resources, offline.
/// See <c>Fixtures/README.md</c> and <c>Fixtures/ades/manifest.json</c> for their origin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CadesSignatureValidatorCorpusTests
{
    [Fact(DisplayName = "EU DSS CAdES-B-T: the signature timestamp verifies against the signature value")]
    public void Validate_EuDssCadesBT_SignatureTimestampValid()
    {
        var result = Validate("cades/cades-bt.p7m", "cades/cades-bt.content");

        result.IsIntegrityValid.ShouldBeTrue(Describe(result));
        result.IsSignatureValid.ShouldBeTrue(Describe(result));
        result.HasValidTimestamp.ShouldBe(true, Describe(result));
        result.HasValidArchiveTimestamp.ShouldBeNull(Describe(result));
    }

    [Fact(DisplayName = "EU DSS CAdES-B-LT: the certificate and revocation material is valid")]
    public void Validate_EuDssCadesBLT_LtvDataValid()
    {
        var result = Validate("cades/cades-blt-ltv.p7s", content: []);

        result.IsLtvDataValid.ShouldBe(true, Describe(result));
    }

    [Fact(DisplayName = "EU DSS CAdES-B-LTA: the ATSHashIndexV3 archive timestamp verifies")]
    public void Validate_EuDssCadesBLTA_ArchiveTimestampValid()
    {
        var result = Validate("cades/cades-blta.p7m", "cades/cades-blta.content");

        result.HasValidArchiveTimestamp.ShouldBe(true, Describe(result));
    }

    [Fact(DisplayName = "EU DSS CAdES-B-LTA with a modified ATSHashIndexV3: the archive timestamp is rejected")]
    public void Validate_EuDssCadesBLTAModifiedHashIndex_ArchiveTimestampInvalid()
    {
        var result = Validate("cades/cades-blta-modified-ats.p7m", "cades/cades-blta-modified-ats.content");

        result.HasValidArchiveTimestamp.ShouldBe(false, Describe(result));
        result.IsValid.ShouldBeFalse(Describe(result));
    }

    private static CadesValidationResult Validate(string signature, string content) =>
        Validate(signature, EtsiCorpus.ReadAdes(content));

    private static CadesValidationResult Validate(string signature, byte[] content) =>
        new CadesSignatureValidator(EtsiCorpus.OfflineOptions).Validate(EtsiCorpus.ReadAdes(signature), content);

    private static string Describe(CadesValidationResult result) =>
        $"Errors: {string.Join(" | ", result.Errors)}; warnings: {string.Join(" | ", result.Warnings)}";
}
