using FluentAssertions;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Inspection;
using SimpleSign.Pdf;
using Xunit;

namespace SimpleSign.PAdES.Tests.Inspection;

public sealed class ConformanceDetectorTests
{
    [Fact(DisplayName = "Detect returns CmsOnly when no signingCertificateV2")]
    public void Detect_NoSigningCertV2_ReturnsCmsOnly()
    {
        var sig = MakeSig(hasSigningCertV2: false);
        var doc = MakeDoc();

        var level = ConformanceDetector.Detect(sig, doc, [sig]);

        level.Should().Be(PAdESConformanceLevel.CmsOnly);
    }

    [Fact(DisplayName = "Detect returns BaselineB with signingCertificateV2 only")]
    public void Detect_SigningCertV2Only_ReturnsBaselineB()
    {
        var sig = MakeSig(hasSigningCertV2: true);
        var doc = MakeDoc();

        var level = ConformanceDetector.Detect(sig, doc, [sig]);

        level.Should().Be(PAdESConformanceLevel.BaselineB);
    }

    [Fact(DisplayName = "Detect returns BaselineT with timestamp")]
    public void Detect_WithTimestamp_ReturnsBaselineT()
    {
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true);
        var doc = MakeDoc();

        var level = ConformanceDetector.Detect(sig, doc, [sig]);

        level.Should().Be(PAdESConformanceLevel.BaselineT);
    }

    [Fact(DisplayName = "Detect returns BaselineLT with timestamp and DSS")]
    public void Detect_WithTimestampAndDss_ReturnsBaselineLT()
    {
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true);
        var doc = MakeDoc(hasDss: true);

        var level = ConformanceDetector.Detect(sig, doc, [sig]);

        level.Should().Be(PAdESConformanceLevel.BaselineLT);
    }

    [Fact(DisplayName = "Detect returns BaselineLTA with timestamp, DSS and doc timestamp")]
    public void Detect_WithTimestampDssAndDocTimestamp_ReturnsBaselineLTA()
    {
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true, byteRangeOffset2: 1000);
        var docTs = MakeDocTimestamp(byteRangeOffset2: 2000);
        var doc = MakeDoc(hasDss: true);

        var level = ConformanceDetector.Detect(sig, doc, [sig, docTs]);

        level.Should().Be(PAdESConformanceLevel.BaselineLTA);
    }

    [Fact(DisplayName = "Detect does not promote to LTA when doc timestamp is before signature")]
    public void Detect_DocTimestampBeforeSignature_NotLTA()
    {
        var sig = MakeSig(hasSigningCertV2: true, hasTimestamp: true, byteRangeOffset2: 2000);
        var docTs = MakeDocTimestamp(byteRangeOffset2: 1000);
        var doc = MakeDoc(hasDss: true);

        var level = ConformanceDetector.Detect(sig, doc, [sig, docTs]);

        level.Should().Be(PAdESConformanceLevel.BaselineLT);
    }

    [Fact(DisplayName = "DetectAll returns levels for all signatures")]
    public void DetectAll_MultipleSignatures_ReturnsAll()
    {
        var sig1 = MakeSig(hasSigningCertV2: true);
        var sig2 = MakeSig(hasSigningCertV2: true, hasTimestamp: true);
        var doc = MakeDoc();

        var result = new PdfInspectionResult
        {
            Document = doc,
            Signatures = [sig1, sig2]
        };

        var levels = ConformanceDetector.DetectAll(result);

        levels.Should().HaveCount(2);
        levels[0].Level.Should().Be(PAdESConformanceLevel.BaselineB);
        levels[1].Level.Should().Be(PAdESConformanceLevel.BaselineT);
    }

    [Fact(DisplayName = "DetectHighest returns lowest (weakest) conformance among signatures")]
    public void DetectHighest_MixedLevels_ReturnsLowest()
    {
        var sig1 = MakeSig(hasSigningCertV2: true);
        var sig2 = MakeSig(hasSigningCertV2: true, hasTimestamp: true);
        var doc = MakeDoc();

        var result = new PdfInspectionResult
        {
            Document = doc,
            Signatures = [sig1, sig2]
        };

        var level = ConformanceDetector.DetectHighest(result);

        // Document conformance = weakest signature = B-B (sig1 has no timestamp)
        level.Should().Be(PAdESConformanceLevel.BaselineB);
    }

    [Fact(DisplayName = "DetectHighest with no signatures returns Unknown")]
    public void DetectHighest_NoSignatures_ReturnsUnknown()
    {
        var result = new PdfInspectionResult
        {
            Document = MakeDoc(),
            Signatures = []
        };

        ConformanceDetector.DetectHighest(result).Should().Be(PAdESConformanceLevel.Unknown);
    }

    private static SignatureFieldInfo MakeSig(
        bool hasSigningCertV2 = false,
        bool hasTimestamp = false,
        long byteRangeOffset2 = 500)
    {
        return new SignatureFieldInfo
        {
            FieldName = "Sig",
            HasSigningCertificateV2 = hasSigningCertV2,
            Timestamp = hasTimestamp
                ? new TimestampInfo { GenerationTime = DateTimeOffset.UtcNow }
                : null,
            ByteRange = new PdfByteRange
            {
                Offset1 = 0,
                Length1 = 100,
                Offset2 = byteRangeOffset2,
                Length2 = 50
            }
        };
    }

    private static SignatureFieldInfo MakeDocTimestamp(long byteRangeOffset2 = 2000)
    {
        return new SignatureFieldInfo
        {
            FieldName = "DocTS",
            SubFilter = "ETSI.RFC3161",
            ByteRange = new PdfByteRange
            {
                Offset1 = 0,
                Length1 = 100,
                Offset2 = byteRangeOffset2,
                Length2 = 50
            }
        };
    }

    private static PdfDocumentInfo MakeDoc(bool hasDss = false)
    {
        return new PdfDocumentInfo
        {
            SecurityStore = hasDss
                ? new DssInfo { CrlCount = 1, OcspResponseCount = 1 }
                : null
        };
    }
}
