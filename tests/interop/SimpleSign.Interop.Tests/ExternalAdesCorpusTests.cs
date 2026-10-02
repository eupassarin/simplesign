using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// Regression tests for CAdES and XAdES documents produced outside SimpleSign.
/// The resources are fixed EU DSS corpus artifacts; they never require network access.
/// </summary>
[Trait("Category", "Interop")]
[Trait("Category", "EtsiCorpus")]
public sealed class ExternalAdesCorpusTests
{
    private const string ResourcePrefix = "SimpleSign.Interop.Tests.corpus.";
    private static readonly ValidationOptions OfflineValidation = new()
    {
        CheckRevocation = false,
        TrustSystemRoots = false,
    };

    /// <summary>Every versioned artifact must match the EU DSS provenance manifest.</summary>
    [Fact]
    public void CorpusResources_MatchRecordedSha256()
    {
        using JsonDocument manifest = LoadManifest();
        foreach (JsonElement vector in manifest.RootElement.GetProperty("vectors").EnumerateArray())
        {
            AssertResourceHash(vector.GetProperty("resource").GetString()!, vector.GetProperty("sha256").GetString()!);

            if (vector.TryGetProperty("contentResource", out JsonElement contentResource))
            {
                AssertResourceHash(contentResource.GetString()!, vector.GetProperty("contentSha256").GetString()!);
            }
        }
    }

    /// <summary>EU DSS CAdES-B-T has a signature timestamp that verifies against the signature value.</summary>
    [Fact]
    public void CadesBT_ExternalVector_ValidatesSignatureTimestamp()
    {
        CadesValidationResult result = ValidateCades("cades/cades-bt.p7m", "cades/cades-bt.content");

        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue(Describe(result));
        result.HasValidTimestamp.ShouldBe(true);
        result.HasValidArchiveTimestamp.ShouldBeNull();
    }

    /// <summary>EU DSS CAdES-B-LT exposes valid certificate and revocation material.</summary>
    [Fact]
    public void CadesBLT_ExternalVector_ValidatesLongTermMaterial()
    {
        CadesValidationResult result = ValidateCades("cades/cades-blt-ltv.p7s", []);

        result.IsLtvDataValid.ShouldBe(true, Describe(result));
    }

    /// <summary>An external CAdES-B-LTA vector validates its ETSI ATSHashIndexV3 archive timestamp.</summary>
    [Fact]
    public void CadesBLTA_ExternalVector_ValidatesArchiveTimestamp()
    {
        CadesValidationResult result = ValidateCades("cades/cades-blta.p7m", "cades/cades-blta.content");

        result.HasValidArchiveTimestamp.ShouldBe(true, Describe(result));
    }

    /// <summary>An external CAdES vector with a modified ATSHashIndexV3 must not be accepted.</summary>
    [Fact]
    public void CadesBLTA_ModifiedHashIndex_RejectsArchiveTimestamp()
    {
        CadesValidationResult result = ValidateCades(
            "cades/cades-blta-modified-ats.p7m", "cades/cades-blta-modified-ats.content");

        result.HasValidArchiveTimestamp.ShouldBe(false);
    }

    /// <summary>EU DSS enveloped XAdES-B-T retains a verifiable signature timestamp.</summary>
    [Fact]
    public void XadesBT_ExternalVector_ValidatesSignatureTimestamp()
    {
        XadesValidationResult result = ValidateXades("xades/xades-bt-enveloped.xml");

        result.IsSignatureValid.ShouldBeTrue(Describe(result));
        result.HasValidSignatureTimeStamp.ShouldBe(true);
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    /// <summary>
    /// EU DSS XAdES-B-T with TimeStampValidationData must retain its signature timestamp without
    /// being misclassified as signature-level B-LT validation material.
    /// </summary>
    [Fact]
    public void XadesBT_WithTimestampValidationData_DoesNotClaimSignatureLevelLtv()
    {
        XadesValidationResult result = ValidateXades("xades/xades-blt-enveloped.xml");

        result.HasValidSignatureTimeStamp.ShouldBe(true);
        result.IsLtvDataValid.ShouldBeNull();
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
    }

    /// <summary>An external XAdES-B-LTA vector validates its ETSI archive timestamp preimage.</summary>
    [Fact]
    public void XadesBLTA_ExternalVector_ValidatesArchiveTimestamp()
    {
        XadesValidationResult result = ValidateXades("xades/xades-blta-enveloped.xml");

        result.HasValidSignatureTimeStamp.ShouldBe(true);
        result.HasValidArchiveTimeStamp.ShouldBe(true, Describe(result));
        result.DetectedLevel.ShouldBe(AdesBaselineLevel.Archive);
    }

    /// <summary>Detached XAdES-B-LTA requires and verifies the external signed document.</summary>
    [Fact]
    public void XadesBLTA_DetachedExternalVector_RequiresCorrectOriginalData()
    {
        byte[] signature = LoadResource("xades/xades-blta-detached.xml");
        byte[] original = LoadResource("xades/xades-detached-content.xml");
        var validator = new XadesSignatureValidator(OfflineValidation);

        XadesValidationResult result = validator.Validate(signature, originalData: original);

        result.HasValidSignatureTimeStamp.ShouldBe(true);
        result.HasValidArchiveTimeStamp.ShouldBe(true, Describe(result));

        byte[] altered = (byte[])original.Clone();
        altered[^1] ^= 0x01;
        XadesValidationResult alteredResult = validator.Validate(signature, originalData: altered);
        alteredResult.IsSignatureValid.ShouldBeFalse();
        alteredResult.HasValidArchiveTimeStamp.ShouldBe(false);
    }

    /// <summary>An external XAdES vector with a copied archive timestamp must not be accepted.</summary>
    [Fact]
    public void XadesBLTA_CopiedArchiveTimestamp_RejectsArchiveTimestamp()
    {
        XadesValidationResult result = ValidateXades("xades/xades-blta-copied-ats.xml");

        result.HasValidArchiveTimeStamp.ShouldBe(false);
    }

    private static CadesValidationResult ValidateCades(string signatureResource, byte[] content)
    {
        var validator = new CadesSignatureValidator(OfflineValidation);
        return validator.Validate(LoadResource(signatureResource), content);
    }

    private static CadesValidationResult ValidateCades(string signatureResource, string contentResource) =>
        ValidateCades(signatureResource, LoadResource(contentResource));

    private static XadesValidationResult ValidateXades(string signatureResource)
    {
        var validator = new XadesSignatureValidator(OfflineValidation);
        return validator.Validate(LoadResource(signatureResource));
    }

    private static JsonDocument LoadManifest() => JsonDocument.Parse(LoadResource("ades/manifest.json"));

    private static void AssertResourceHash(string resource, string expectedHash)
    {
        string actualHash = Convert.ToHexString(SHA256.HashData(LoadResource(resource))).ToLowerInvariant();
        actualHash.ShouldBe(expectedHash);
    }

    private static string Describe(CadesValidationResult result) =>
        $"Errors: {string.Join(" | ", result.Errors)}; warnings: {string.Join(" | ", result.Warnings)}";

    private static string Describe(XadesValidationResult result) =>
        $"Errors: {string.Join(" | ", result.Errors)}; warnings: {string.Join(" | ", result.Warnings)}";

    private static byte[] LoadResource(string relativePath)
    {
        Assembly assembly = typeof(ExternalAdesCorpusTests).Assembly;
        string resourceName = ResourcePrefix + relativePath.Replace('/', '.');
        using Stream stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Corpus resource '{resourceName}' was not found.");
        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }
}
