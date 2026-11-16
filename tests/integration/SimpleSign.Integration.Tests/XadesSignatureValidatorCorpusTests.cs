using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Integration.Tests.Helpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// <see cref="XadesSignatureValidator"/> on XAdES vectors from the EU DSS test resources, offline.
/// See <c>Fixtures/README.md</c> and <c>Fixtures/ades/manifest.json</c> for their origin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class XadesSignatureValidatorCorpusTests
{
    [Fact(DisplayName = "EU DSS enveloped XAdES-B-T: the signature and its timestamp verify")]
    public void Validate_EuDssXadesBT_SignatureTimestampValid()
    {
        var result = Validate("xades/xades-bt-enveloped.xml");

        result.IsSignatureValid.ShouldBeTrue(Describe(result));
        result.HasValidSignatureTimeStamp.ShouldBe(true, Describe(result));
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    /// <summary>
    /// TimeStampValidationData covers the TSA only: it must not be taken as the signature's B-LT material.
    /// </summary>
    [Fact(DisplayName = "EU DSS XAdES-B-T with TimeStampValidationData: not claimed as signature-level LTV")]
    public void Validate_EuDssXadesBTWithTimestampValidationData_NoSignatureLevelLtv()
    {
        var result = Validate("xades/xades-blt-enveloped.xml");

        result.HasValidSignatureTimeStamp.ShouldBe(true, Describe(result));
        result.IsLtvDataValid.ShouldBeNull(Describe(result));
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    [Fact(DisplayName = "EU DSS enveloped XAdES-B-LTA: the archive timestamp verifies")]
    public void Validate_EuDssXadesBLTA_ArchiveTimestampValid()
    {
        var result = Validate("xades/xades-blta-enveloped.xml");

        result.HasValidSignatureTimeStamp.ShouldBe(true, Describe(result));
        result.HasValidArchiveTimeStamp.ShouldBe(true, Describe(result));
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Archive);
    }

    [Fact(DisplayName = "EU DSS detached XAdES-B-LTA: verifies with the original document")]
    public void Validate_EuDssDetachedXadesBLTAWithOriginal_ArchiveTimestampValid()
    {
        var result = Validate("xades/xades-blta-detached.xml", EtsiCorpus.ReadAdes("xades/xades-detached-content.xml"));

        result.HasValidSignatureTimeStamp.ShouldBe(true, Describe(result));
        result.HasValidArchiveTimeStamp.ShouldBe(true, Describe(result));
    }

    [Fact(DisplayName = "EU DSS detached XAdES-B-LTA: a changed original document is rejected")]
    public void Validate_EuDssDetachedXadesBLTAWithAlteredOriginal_Invalid()
    {
        var altered = EtsiCorpus.ReadAdes("xades/xades-detached-content.xml");
        altered[^1] ^= 0x01;

        var result = Validate("xades/xades-blta-detached.xml", altered);

        result.IsSignatureValid.ShouldBeFalse(Describe(result));
        result.HasValidArchiveTimeStamp.ShouldBe(false, Describe(result));
    }

    [Fact(DisplayName = "EU DSS XAdES-B-LTA with a copied archive timestamp: the archive timestamp is rejected")]
    public void Validate_EuDssXadesBLTACopiedArchiveTimestamp_ArchiveTimestampInvalid()
    {
        var result = Validate("xades/xades-blta-copied-ats.xml");

        result.HasValidArchiveTimeStamp.ShouldBe(false, Describe(result));
        result.IsValid.ShouldBeFalse(Describe(result));
    }

    private static XadesValidationResult Validate(string signature, byte[]? originalData = null) =>
        new XadesSignatureValidator(EtsiCorpus.OfflineOptions).Validate(EtsiCorpus.ReadAdes(signature), originalData: originalData);

    private static string Describe(XadesValidationResult result) =>
        $"Errors: {string.Join(" | ", result.Errors)}; warnings: {string.Join(" | ", result.Warnings)}";
}
