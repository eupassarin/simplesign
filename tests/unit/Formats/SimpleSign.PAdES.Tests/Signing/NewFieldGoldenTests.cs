using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Signing a new field on the PDF object model (ADR 0032), with the time fixed, on the writers' corpus: invisible, named,
/// visible (placed automatically, or on page 2), certifying, and with document information. Each update reads back
/// with one more signature on a field of its own, the earlier fields kept; and is its snapshot (SHA-256, per
/// framework). The snapshots were taken when each update had been checked against the writer before the model: the
/// same bytes, or a difference that writer's defect explained (catalogued in the ADR).
/// </summary>
[Trait("Category", "Unit")]
public sealed class NewFieldGoldenTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 23, 11, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<string, string> s_info = new(StringComparer.Ordinal) { ["Producer"] = "SimpleSign", ["Title"] = "Contrato nº 7" };

    private static readonly Dictionary<string, Func<SignatureFieldOptions>> s_options = new(StringComparer.Ordinal)
    {
        ["invisible"] = () => new() { ContentsReservedBytes = 1024 },
        ["named"] = () => new()
        {
            FieldName = "Assinatura",
            ContentsReservedBytes = 1024,
            SubFilter = PdfSignatureSubFilter.PbadPades,
            Reason = "Aprovação",
            Location = "São Paulo",
        },
        ["visible-auto"] = () => new() { ContentsReservedBytes = 1024, SignerName = "Fulano", Appearance = SignatureAppearance.Auto() },
        ["visible-page-2"] = () => new() { ContentsReservedBytes = 1024, SignerName = "Fulano", Appearance = new SignatureAppearance { Page = 2, X = 50, Y = 60 } },
        ["certified"] = () => new() { ContentsReservedBytes = 1024, CertificationLevel = CertificationLevel.FormFillingAndAnnotations },
        ["info"] = () => new() { ContentsReservedBytes = 1024 },
    };

    public static TheoryData<string, string> Cases()
    {
        var data = new TheoryData<string, string>();
        foreach (string document in WriterCorpus.Documents.Keys)
        {
            foreach (string options in s_options.Keys)
            {
                data.Add(document, options);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task PrepareAsync_NewField_IsItsSnapshot(string document, string optionsKind)
    {
        byte[] original = await WriterCorpus.Documents[document]();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        var options = s_options[optionsKind]();
        var info = optionsKind == "info" ? s_info : null;
        using var modelOutput = new MemoryStream();
        var modelResult = await PdfSignatureWriter.PrepareAsync(new MemoryStream(original), modelOutput, options, null, null, s_now, info, CancellationToken.None);
        byte[] model = modelOutput.ToArray();

        // The update reads back: one more signature, on a field of its own, its byte range the whole file but
        // the contents, the earlier fields all there.
        var before = source.View();
        var after = PdfDocument.Open(model).View();
        after.Signatures.Count.ShouldBe(before.Signatures.Count + 1);
        var signature = after.Signatures.Single(s => s.Id?.Number == modelResult.SigDictObjectNumber);
        (modelResult.ByteRange.Offset2 + modelResult.ByteRange.Length2).ShouldBe(model.Length);
        signature.ByteRange.ShouldBe([0, modelResult.ByteRange.Length1, modelResult.ByteRange.Offset2, modelResult.ByteRange.Length2]);
        before.Fields.Select(f => f.FullName).Except(after.Fields.Select(f => f.FullName)).ShouldBeEmpty();
        after.Fields.Count(f => f.FullName == signature.Field!.FullName).ShouldBe(1);

        if (WriterCorpus.IsDeterministic(document))
        {
            Snapshot.MatchCompressed("writers/new-field", $"{document}|{optionsKind}", model);
        }
    }
}
