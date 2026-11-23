using System.Text;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Signing an existing field as it was done before the PDF object model (ADR 0032): the field found by searching the
/// file's text for <c>/FT /Sig</c>. Kept, internal, for the golden tests of the model path until the old code is
/// removed.
/// </summary>
public sealed partial class PdfSignatureWriter
{
    /// <summary>Prepares a signature of an existing field as the writer did before the object model.</summary>
    internal static async Task<PdfSignaturePrepareResult> PrepareExistingFieldLegacyAsync(
        Stream inputPdf, Stream outputStream, SignatureFieldOptions options, PdfALevel? pdfALevel, DateTimeOffset? signingTime, CancellationToken cancellationToken)
    {
        var (_, inputMem) = await CopyAndLoadPdfAsync(inputPdf, outputStream, cancellationToken).ConfigureAwait(false);
        return await PrepareExistingFieldLegacyAsync(outputStream, inputPdf, inputMem, options, pdfALevel, cancellationToken, signingTime).ConfigureAwait(false);
    }

    private static async Task<PdfSignaturePrepareResult> PrepareExistingFieldLegacyAsync(
        Stream outputStream, Stream inputPdf, Memory<byte> inputMem, SignatureFieldOptions options, PdfALevel? pdfALevel, CancellationToken cancellationToken, DateTimeOffset? signingTime = null)
    {
        int fieldObjNum = PdfStructureParser.FindEmptySignatureField(inputMem.Span, options.ExistingFieldName!);
        if (fieldObjNum < 0)
        {
            throw new InvalidOperationException(
                $"Signature field '{options.ExistingFieldName}' not found in the PDF. " +
                "Ensure the field exists with /FT /Sig and has an empty /V value.");
        }

        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(inputMem.Span);
        int sigObjNum = nextObjNum;
        int contentsHexLength = options.ContentsReservedBytes * 2;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        // Build signature dictionary
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);

        // Build updated field object with /V pointing to the new sig dict
        var (fObjStart, fObjEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, fieldObjNum);
        string fieldText = Encoding.Latin1.GetString(inputMem.Span.Slice(fObjStart, fObjEnd - fObjStart));
        string updatedField;
        int vKeyPos = PdfStructureParser.FindTopLevelKey(fieldText, "/V");
        if (vKeyPos >= 0)
        {
            // Replace the existing /V value (reference, name, null, or empty string).
            int vEnd = FindValueEnd(fieldText, vKeyPos);
            updatedField = string.Concat(fieldText.AsSpan(0, vKeyPos), $"/V {sigObjNum} 0 R", fieldText.AsSpan(vEnd));
        }
        else
        {
            // Insert /V before the closing >>
            updatedField = PdfStructureParser.InsertIntoDict(fieldText, $"   /V {sigObjNum} 0 R\n");
        }
        // A visible appearance is drawn into the field's own rectangle (merged field/widget).
        int appObjNum = nextObjNum + 2;
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        float appWidth = 0f, appHeight = 0f;
        if (options.Appearance is not null)
        {
            (appWidth, appHeight) = ReadRectSize(fieldText)
                ?? throw new ArgumentException(
                    $"Signature field '{options.ExistingFieldName}' has no visible rectangle, so the appearance cannot be drawn. Sign it without an appearance.");
            updatedField = SetTopLevelValue(updatedField, "/AP", $"<< /N {appObjNum} 0 R >>");
        }

        // The next object's number must start a line (ISO 32000-1 §7.3.10): the field ends at its endobj.
        if (!updatedField.EndsWith('\n'))
        {
            updatedField += "\n";
        }

        byte[] updatedFieldBytes = Encoding.Latin1.GetBytes(updatedField);

        // Write objects
        long sigObjOffset = outputStream.Position;
        await outputStream.WriteAsync(sigDictBytes, cancellationToken).ConfigureAwait(false);
        long fieldObjOffset = outputStream.Position;
        await outputStream.WriteAsync(updatedFieldBytes, cancellationToken).ConfigureAwait(false);

        // Build xref and trailer
        var objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset
        };

        if (options.Appearance is not null)
        {
            objectOffsets[fontFileObjNum] = outputStream.Position;
            await outputStream.WriteAsync(PdfFontWriter.BuildFontFileObject(fontFileObjNum), cancellationToken).ConfigureAwait(false);
            objectOffsets[fontDescriptorObjNum] = outputStream.Position;
            await outputStream.WriteAsync(PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum), cancellationToken).ConfigureAwait(false);
            bool hasImage = options.Appearance.HasBackgroundImage();
            var colorProfiles = AppearanceColorProfiles.For(pdfALevel, appObjNum);
            byte[] appearanceBytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0, fontFileObjNum, fontDescriptorObjNum, hasImage ? softMaskObjNum : 0, colorProfiles);
            long appObjOffset = outputStream.Position;
            objectOffsets[appObjNum] = appObjOffset;
            await outputStream.WriteAsync(appearanceBytes, cancellationToken).ConfigureAwait(false);
            foreach (var (appendedObjNum, appendedOffset) in FindAppendedObjects(appearanceBytes, appObjOffset, imageObjNum, softMaskObjNum, colorProfiles))
            {
                objectOffsets[appendedObjNum] = appendedOffset;
            }
        }

        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);

        // If DocMDP, also update the catalog (a stale /Perms goes). The field is already in the form: the AcroForm
        // stays as it is, inline or its own object (writing a reference to a new AcroForm object here, which was
        // never written, lost the form of a document whose AcroForm is inline).
        if (options.CertificationLevel is not null)
        {
            int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catalogObjNum);
            byte[]? catalogBytes = existingAcroFormObjNum > 0
                ? BuildCatalogDictionary(catalogObjNum, inputMem.Span, existingAcroFormObjNum, options.CertificationLevel)
                : BuildCatalogWithoutPerms(catalogObjNum, inputMem.Span);
            if (catalogBytes is not null)
            {
                long catalogObjOffset = outputStream.Position;
                await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
                objectOffsets[catalogObjNum] = catalogObjOffset;
            }
        }

        int newTrailerSize = Math.Max(sigObjNum + 1, objectOffsets.Keys.Max() + 1);
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        string? trailerId = PdfStructureParser.FindTrailerId(inputMem.Span);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(inputMem.Span);
        long xrefOffset = outputStream.Position;

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(inputMem.Span);
        if (useXRefStream)
        {
            int xrefObjNum = objectOffsets.Keys.Max() + 1;
            newTrailerSize = Math.Max(newTrailerSize, xrefObjNum + 1);
            var (xrefBytes, _) = BuildXrefStream(objectOffsets, xrefObjNum, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }

        PdfByteRange byteRange = await BackfillByteRangeAsync(outputStream, sigDictText, sigObjOffset, contentsHexLength, cancellationToken).ConfigureAwait(false);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
    }
}
