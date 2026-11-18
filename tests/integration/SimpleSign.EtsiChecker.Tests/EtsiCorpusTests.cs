using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// The corpus <see cref="EtsiCorpus"/> sends to the ETSI checker, checked offline: every sample is made and reaches
/// the level it claims, so a finding of the checker is about the structure, not about a sample that failed to build.
/// With <c>SIMPLESIGN_ETSI_CORPUS</c> set, the samples are also written there, for an upload by hand.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EtsiCorpusTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    [Fact]
    public void Samples_Ids_AreUniqueAndFileSafe()
    {
        EtsiCorpus.Samples.Select(s => s.Id).ShouldBeUnique();
        EtsiCorpus.Samples.ShouldAllBe(s => s.Id.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-'));
    }

    [Theory]
    [MemberData(nameof(EtsiCorpus.Ids), MemberType = typeof(EtsiCorpus))]
    public async Task Sign_EverySample_ReachesItsLevel(string id)
    {
        var sample = EtsiCorpus.Get(id);

        byte[] signed = await sample.Sign(pki);

        signed.Length.ShouldBeLessThan(EtsiChecker.MaxUploadBytes);
        switch (sample.Format)
        {
            case EtsiFormat.Cades:
                CadesAugmenter.LevelOf(signed).ShouldBe(sample.Level);
                break;
            case EtsiFormat.Xades:
                XadesAugmenter.LevelOf(signed).ShouldBe(sample.Level);
                break;
            default:
                var inspection = await PdfSignatureInspector.InspectAsync(new MemoryStream(signed));
                inspection.Signatures.ShouldNotBeEmpty();
                ConformanceDetector.DetectHighest(inspection).ShouldBe(sample.IsBaseline
                    ? sample.Level switch
                    {
                        AdesBaselineLevel.Basic => PAdESConformanceLevel.BaselineB,
                        AdesBaselineLevel.Timestamped => PAdESConformanceLevel.BaselineT,
                        AdesBaselineLevel.LongTerm => PAdESConformanceLevel.BaselineLT,
                        _ => PAdESConformanceLevel.BaselineLTA,
                    }
                    : PAdESConformanceLevel.CmsOnly);
                bool documentTimestamp = inspection.Signatures.Any(s => s.IsDocumentTimestamp);
                documentTimestamp.ShouldBe(sample.Level == AdesBaselineLevel.Archive);
                // B-T is a signature time-stamp, or a document time-stamp over the signature (an augmentation, EN 319 142-1 5.3).
                inspection.Signatures.Where(s => !s.IsDocumentTimestamp)
                    .ShouldAllBe(s => (s.Timestamp != null || documentTimestamp) == (sample.Level >= AdesBaselineLevel.Timestamped));
                break;
        }

        if (EtsiChecker.CorpusDirectory is { } directory)
        {
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, sample.FileName);
            await File.WriteAllBytesAsync(path, signed);
            output.WriteLine($"Written to {path}");
        }
    }
}
