using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf.Constants;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Signing as it was done before the PDF object model (ADR 0032): the objects a signature updates (the catalog, the
/// AcroForm, the page, an existing field) found by searching the file's text. Kept, internal, for the golden tests of
/// the model paths and behind <see cref="PdfWriterSwitch"/> until the old code is removed.
/// </summary>
public sealed partial class PdfSignatureWriter
{
    /// <summary>Prepares a signature as the writer did before the object model (a new field, or an existing one).</summary>
    internal static async Task<PdfSignaturePrepareResult> PrepareLegacyAsync(
        Stream inputPdf, Stream outputStream, SignatureFieldOptions options, ILogger? logger, PdfALevel? pdfALevel, DateTimeOffset? signingTime,
        IReadOnlyDictionary<string, string>? documentInfo, CancellationToken cancellationToken)
    {
        var (_, inputMem) = await CopyAndLoadPdfAsync(inputPdf, outputStream, cancellationToken).ConfigureAwait(false);
        return string.IsNullOrEmpty(options.ExistingFieldName)
            ? await PrepareNewFieldLegacyAsync(inputPdf, outputStream, inputMem, options, logger, pdfALevel, signingTime, documentInfo, cancellationToken).ConfigureAwait(false)
            : await PrepareExistingFieldLegacyAsync(outputStream, inputPdf, inputMem, options, pdfALevel, cancellationToken, signingTime).ConfigureAwait(false);
    }

    /// <summary>A new signature field, as the writer added it before the object model.</summary>
    private static async Task<PdfSignaturePrepareResult> PrepareNewFieldLegacyAsync(
        Stream inputPdf, Stream outputStream, Memory<byte> inputMem, SignatureFieldOptions options, ILogger? logger, PdfALevel? pdfALevel,
        DateTimeOffset? signingTime, IReadOnlyDictionary<string, string>? documentInfo, CancellationToken cancellationToken)
    {
        // Step 2: Determine the next available object number.
        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(inputMem.Span);

        // Step 2b: Ensure unique field name — auto-increment if the default name is already used.
        string fieldName = options.FieldName;
        if (fieldName == "Signature1")
        {
            // Count existing fields from AcroForm /Fields array (handles ObjStm-compressed fields)
            int catObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);
            int acroObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catObjNum);
            int existingSigFields = 0;
            if (acroObjNum > 0)
            {
                var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, acroObjNum);
                if (objStart >= 0)
                {
                    string acroText = Encoding.Latin1.GetString(inputMem.Span.Slice(objStart, objEnd - objStart));
                    var refs = PdfStructureParser.ParseFieldsArray(acroText);
                    if (refs.Count == 0)
                    {
                        refs = PdfStructureParser.ResolveIndirectFields(inputMem.Span, acroText);
                    }
                    existingSigFields = refs.Count;
                }
                else
                {
                    existingSigFields = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(inputMem.Span, acroObjNum).Count;
                }
            }

            // Fallback: scan raw bytes for /FT /Sig (catches uncompressed fields)
            if (existingSigFields == 0)
            {
                ReadOnlySpan<byte> ftSigToken = "/FT /Sig"u8;
                int searchPos = 0;
                while (searchPos < inputMem.Span.Length)
                {
                    int idx = inputMem.Span.Slice(searchPos).IndexOf(ftSigToken);
                    if (idx < 0)
                    {
                        break;
                    }
                    existingSigFields++;
                    searchPos += idx + ftSigToken.Length;
                }
            }

            if (existingSigFields > 0)
            {
                fieldName = $"Signature{existingSigFields + 1}";
            }
        }

        // Step 3: Locate the target page object for the widget annotation.
        bool hasAppearance = options.Appearance != null;
        int targetPage = options.Appearance?.Page ?? 1;

        // An anchored stamp goes on the page of its text, at the start of the text plus the offsets.
        (float X, float Y)? anchoredAt = null;
        if (options.Appearance?.Anchor is { } anchor)
        {
            var placement = anchor.Locate(inputMem.ToArray());
            targetPage = placement.Page;
            anchoredAt = (placement.X, placement.Y);
        }
        int pageObjNum;
        int pageObjDictStart;
        int pageObjDictEnd;

        if (targetPage > 1)
        {
            pageObjNum = PdfStructureParser.FindNthPageObjNum(inputMem.Span, targetPage);
            if (pageObjNum > 0)
            {
                var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, pageObjNum);
                if (objStart >= 0)
                {
                    pageObjDictStart = -1;
                    for (int pos = objStart; pos < objEnd - 1; pos++)
                    {
                        if (inputMem.Span[pos] == (byte)'<' && inputMem.Span[pos + 1] == (byte)'<')
                        {
                            pageObjDictStart = pos;
                            break;
                        }
                    }
                    pageObjDictEnd = objEnd;
                }
                else
                {
                    pageObjDictStart = -1;
                    pageObjDictEnd = -1;
                }
            }
            else
            {
                (pageObjNum, pageObjDictStart, pageObjDictEnd) = (-1, -1, -1);
            }
        }
        else
        {
            (pageObjNum, pageObjDictStart, pageObjDictEnd) = PdfStructureParser.FindFirstPageObject(inputMem.Span);
        }

        (logger ?? NullLogger.Instance).PdfStructureParsed(nextObjNum, $"{pageObjNum} 0 R");
        if (hasAppearance && pageObjNum <= 0)
        {
            hasAppearance = false;
        }

        // Step 4: Assign object numbers for the new PDF objects.
        int sigObjNum = nextObjNum;
        int fieldObjNum = nextObjNum + 1;
        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);
        int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catalogObjNum);
        // Reuse existing AcroForm object number to avoid changing the Catalog reference
        // (changing it breaks EU DSS validation of the first signature in multi-sig PDFs).
        bool reuseAcroForm = existingAcroFormObjNum > 0;
        // An inline /AcroForm dictionary in the Catalog must stay inline: converting it to an
        // indirect object drops entries such as /DA and /DR, and Acrobat's modification analysis
        // then invalidates earlier signatures.
        bool preserveInlineAcroForm = !reuseAcroForm
            && PdfStructureParser.HasUpdatableInlineAcroForm(inputMem.Span, catalogObjNum);
        int acroFormObjNum = reuseAcroForm ? existingAcroFormObjNum : (nextObjNum + 2);
        int appObjNum = (reuseAcroForm || preserveInlineAcroForm) ? (nextObjNum + 2) : (nextObjNum + 3);
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        int contentsHexLength = options.ContentsReservedBytes * 2;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        // Compute appearance dimensions and auto-position if requested.
        float appWidth = 0f, appHeight = 0f;
        float appX = 0f, appY = 0f;
        if (hasAppearance && options.Appearance != null)
        {
            var a = options.Appearance;
            bool hasReason = !string.IsNullOrEmpty(options.Reason);
            bool hasLocation = !string.IsNullOrEmpty(options.Location);
            appWidth = a.ComputeWidth(options.SignerName ?? "Signer", options.Reason, options.Location, sigNow);
            appHeight = a.ComputeHeight(hasReason, hasLocation);

            // A page inside a compressed object stream (ISO 32000 §7.5.7) has no dictionary bytes of its own to slice.
            string? pageDict = pageObjNum <= 0 ? null
                : pageObjDictStart >= 0 ? Encoding.Latin1.GetString(inputMem.Span.Slice(pageObjDictStart, pageObjDictEnd - pageObjDictStart))
                : PdfStructureParser.ExtractObjectFromObjStm(inputMem.Span, pageObjNum);
            if (anchoredAt is { } anchored)
            {
                (appX, appY) = anchored;
            }
            else if (a.AutoPosition && pageDict is not null)
            {
                float pageWidth = PdfStructureParser.ParseMediaBoxWidth(inputMem.Span, pageDict);
                int rotation = PdfStructureParser.ParsePageRotation(inputMem.Span, pageDict);
                int existingSigCount = PdfStructureParser.CountVisibleSignatureAnnotations(inputMem.Span);

                // For 90°/270° rotation, the effective page dimensions are swapped (§8.3.2.4)
                float effectiveWidth = (rotation == 90 || rotation == 270)
                    ? PdfStructureParser.ParsePageHeight(inputMem.Span, pageDict)
                    : pageWidth;

                (appX, appY) = SignatureAppearance.ComputeAutoPosition(effectiveWidth, 0f, existingSigCount, appWidth, appHeight);
            }
            else
            {
                appX = a.X;
                appY = a.Y;
            }
        }

        // Step 5: Build all new PDF objects.
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        var fieldAnnParams = new FieldAnnotationParams(fieldName, fieldObjNum, sigObjNum, appObjNum, appX, appY, appWidth, appHeight, pageObjNum);
        string fieldDictText = BuildFieldAnnotation(options, fieldAnnParams, pdfALevel);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDictText);
        byte[]? acroFormBytes = preserveInlineAcroForm
            ? null
            : BuildAcroFormDictionary(acroFormObjNum, inputMem.Span, existingAcroFormObjNum, fieldObjNum, catalogObjNum);

        // Only rewrite the Catalog when the AcroForm reference changes or certification is needed.
        // Rewriting the Catalog in a 2nd incremental update (even with identical content) causes
        // EU DSS to flag the 1st signature as inconsistent.
        bool needCatalogUpdate = !reuseAcroForm || options.CertificationLevel is not null;
        byte[]? catalogBytes = needCatalogUpdate
            ? preserveInlineAcroForm
                ? BuildCatalogWithUpdatedInlineAcroForm(catalogObjNum, inputMem.Span, fieldObjNum, options.CertificationLevel)
                : BuildCatalogDictionary(catalogObjNum, inputMem.Span, acroFormObjNum, options.CertificationLevel)
            : null;

        // Step 6: Write objects and compute byte offsets.
        long sigObjOffset = outputStream.Position;
        long fieldObjOffset = sigObjOffset + sigDictBytes.Length;
        long acroFormObjOffset = fieldObjOffset + fieldDictBytes.Length;

        await outputStream.WriteAsync(sigDictBytes, cancellationToken).ConfigureAwait(false);
        int byteRangePos = sigDictText.IndexOf(PdfKeys.ByteRange, StringComparison.Ordinal);
        (logger ?? NullLogger.Instance).PdfSigDictWritten(sigObjOffset, sigObjOffset + byteRangePos);
        await outputStream.WriteAsync(fieldDictBytes, cancellationToken).ConfigureAwait(false);
        if (acroFormBytes != null)
        {
            await outputStream.WriteAsync(acroFormBytes, cancellationToken).ConfigureAwait(false);
        }

        long catalogObjOffset = 0L;
        if (catalogBytes != null)
        {
            catalogObjOffset = outputStream.Position;
            await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 7: Write font embedding infrastructure (for PDF/A-1 / visible signatures).
        long fontFileObjOffset = 0L;
        long fontDescriptorObjOffset = 0L;
        if (hasAppearance)
        {
            var fontFileBytes = PdfFontWriter.BuildFontFileObject(fontFileObjNum);
            var fontDescriptorBytes = PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum);
            fontFileObjOffset = outputStream.Position;
            await outputStream.WriteAsync(fontFileBytes, cancellationToken).ConfigureAwait(false);
            fontDescriptorObjOffset = outputStream.Position;
            await outputStream.WriteAsync(fontDescriptorBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 8: Write appearance XObject (if visible) and update page /Annots (always).
        long appObjOffset = 0L;
        long updPageObjOffset = 0L;
        Dictionary<int, long> appendedObjOffsets = [];
        bool hasImage = hasAppearance && options.Appearance?.HasBackgroundImage() == true;
        if (hasAppearance && options.Appearance != null)
        {
            var colorProfiles = AppearanceColorProfiles.For(pdfALevel, appObjNum);
            byte[] appearanceBytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0,
                fontFileObjNum,
                fontDescriptorObjNum,
                hasImage ? softMaskObjNum : 0,
                colorProfiles);
            appObjOffset = outputStream.Position;
            await outputStream.WriteAsync(appearanceBytes, cancellationToken).ConfigureAwait(false);

            // The image XObject, its soft mask and the ICC profiles, when present, follow the form XObject.
            appendedObjOffsets = FindAppendedObjects(appearanceBytes, appObjOffset, imageObjNum, softMaskObjNum, colorProfiles);
        }

        // Always add the widget annotation to the page's /Annots array.
        // Adobe Reader requires this to display the signature in the signature panel,
        // even for invisible signatures (Rect [0 0 0 0], no /AP).
        if (pageObjNum > 0)
        {
            byte[] updatedPageBytes;
            if (pageObjDictStart >= 0)
            {
                updatedPageBytes = BuildUpdatedPageObject(pageObjNum, inputMem.Span, pageObjDictStart, pageObjDictEnd, fieldObjNum);
            }
            else
            {
                // Page object is in a compressed ObjStm — extract and rewrite as regular object
                updatedPageBytes = BuildUpdatedPageObjectFromObjStm(pageObjNum, inputMem.Span, fieldObjNum);
            }

            if (updatedPageBytes.Length > 0)
            {
                updPageObjOffset = outputStream.Position;
                await outputStream.WriteAsync(updatedPageBytes, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                pageObjNum = -1; // failed to extract — skip page offset entry
            }
        }

        // Step 8: Build and write the cross-reference section and trailer.
        // Use xref streams when the original PDF uses them (ISO 32000 §7.5.8);
        // otherwise use classic xref tables for maximum compatibility.
        SortedDictionary<int, long> objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset
        };
        if (acroFormBytes != null)
        {
            objectOffsets[acroFormObjNum] = acroFormObjOffset;
        }
        if (needCatalogUpdate)
        {
            objectOffsets[catalogObjNum] = catalogObjOffset;
        }
        if (pageObjNum > 0)
        {
            objectOffsets[pageObjNum] = updPageObjOffset;
        }
        if (hasAppearance)
        {
            objectOffsets[appObjNum] = appObjOffset;
            foreach (var (appendedObjNum, appendedOffset) in appendedObjOffsets)
            {
                objectOffsets[appendedObjNum] = appendedOffset;
            }
            objectOffsets[fontFileObjNum] = fontFileObjOffset;
            objectOffsets[fontDescriptorObjNum] = fontDescriptorObjOffset;
        }
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        string? trailerId = PdfStructureParser.FindTrailerId(inputMem.Span);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(inputMem.Span);
        if (documentInfo is { Count: > 0 })
        {
            int infoObjNum = Math.Max(objectOffsets.Keys.Max() + 1, nextObjNum);
            objectOffsets[infoObjNum] = outputStream.Position;
            await outputStream.WriteAsync(BuildInfoObject(inputMem.Span, trailerInfo, infoObjNum, documentInfo), cancellationToken).ConfigureAwait(false);
            trailerInfo = $"/Info {infoObjNum} 0 R";
        }

        long xrefOffset = outputStream.Position;

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(inputMem.Span);
        if (useXRefStream)
        {
            int xrefObjNum = objectOffsets.Keys.Max() + 1;
            int newTrailerSize = xrefObjNum + 1;
            var (xrefBytes, _) = BuildXrefStream(objectOffsets, xrefObjNum, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            int maxObjNum = objectOffsets.Keys.Max();
            int newTrailerSize = maxObjNum + 1;
            byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 9: Back-fill the ByteRange placeholder with actual offsets.
        PdfByteRange byteRange = await BackfillByteRangeAsync(outputStream, sigDictText, sigObjOffset, contentsHexLength, cancellationToken).ConfigureAwait(false);
        (logger ?? NullLogger.Instance).PdfByteRangeCalculated(byteRange.Offset1, byteRange.Length1, byteRange.Offset2, byteRange.Length2);
        (logger ?? NullLogger.Instance).PdfPrepareCompleted(outputStream.Position, objectOffsets.Count);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
    }

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
