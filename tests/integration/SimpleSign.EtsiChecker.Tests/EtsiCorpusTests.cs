using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>
/// The corpus <see cref="EtsiCorpus"/> sends to the ETSI checker, checked offline: every sample is made, reaches
/// the level it claims, and every signature in it — the earlier ones of a PDF signed again included — is intact and
/// valid for SimpleSign's own validators. So a finding of the checker is about the structure, not about a sample
/// that failed to build or that a later signature broke.
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

    [Theory]
    [MemberData(nameof(EtsiCorpus.Ids), MemberType = typeof(EtsiCorpus))]
    public async Task Validate_EverySample_EverySignatureIsIntactAndValid(string id)
    {
        var sample = EtsiCorpus.Get(id);
        byte[] signed = await sample.Sign(pki);
        var options = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [pki.Pki.RootCa] };

        switch (sample.Format)
        {
            case EtsiFormat.Cades:
                var report = new CadesSignatureValidator(options).ValidateAll(signed, trustAnchors: [pki.Pki.RootCa]);
                report.Signers.Count.ShouldBe(sample.Signatures);
                report.IsValid.ShouldBeTrue(string.Join("; ", report.Errors.Concat(report.Signers.SelectMany(s => s.Result.Errors))));
                break;
            case EtsiFormat.Xades:
                var results = new XadesSignatureValidator(options).ValidateAll(signed, [pki.Pki.RootCa]);
                results.Count.ShouldBe(sample.Signatures);
                results.ShouldAllBe(r => r.IsValid, string.Join("\n", results.Where(r => !r.IsValid).Select(r =>
                    $"{r.SignatureId}: {r.Indication}/{r.SubIndication} {string.Join("; ", r.Errors)} | "
                    + string.Join("; ", r.Constraints.Where(c => c.Status is not (ConstraintStatus.Passed or ConstraintStatus.NotChecked))
                        .Select(c => $"{c.Id} {c.Status}: {c.Message}")))));
                results.ShouldAllBe(r => XadesAugmenter.LevelOf(signed, r.SignatureId) == sample.Level);
                break;
            default:
                var validated = await new PdfSignatureValidator(options).ValidateAsync(new MemoryStream(signed));
                var inspection = await PdfSignatureInspector.InspectAsync(new MemoryStream(signed));
                inspection.Signatures.Count(s => !s.IsDocumentTimestamp).ShouldBe(sample.Signatures);
                validated.Count.ShouldBe(inspection.Signatures.Count);
                foreach (var result in validated)
                {
                    string what = $"{result.FieldName}: {string.Join("; ", result.Errors)}";
                    result.IsIntegrityValid.ShouldBeTrue(what);
                    result.IsSignatureValid.ShouldBeTrue(what);
                    result.IsCertificateChainValid.ShouldBeTrue(what);
                }

                break;
        }
    }
}
