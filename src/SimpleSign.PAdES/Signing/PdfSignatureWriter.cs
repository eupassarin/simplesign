using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF digital signature structures using incremental updates (appending new objects,
/// cross-reference table, and trailer to an existing PDF without modifying the original bytes).
/// Delegates PDF parsing to <see cref="PdfStructureParser"/> and visual rendering to <see cref="SignatureAppearanceRenderer"/>.
/// </summary>
public sealed class PdfSignatureWriter
{
    /// <summary>
    /// Default number of bytes reserved for the CMS signature hex contents (64 KB).
    /// </summary>
    public const int DefaultContentsReservedBytes = 65536;

    /// <summary>
    /// Prepares a PDF for digital signing by appending signature dictionary, field, AcroForm,
    /// catalog, optional appearance, cross-reference table, and trailer to the output stream.
    /// The ByteRange placeholder is then back-filled with actual offsets.
    /// </summary>
    public static async Task<PdfSignaturePrepareResult> PrepareAsync(Stream inputPdf, Stream outputStream, SignatureFieldOptions options, ILogger? logger = null, CancellationToken cancellationToken = default(CancellationToken))
    {
        ArgumentNullException.ThrowIfNull(inputPdf, nameof(inputPdf));
        ArgumentNullException.ThrowIfNull(outputStream, nameof(outputStream));
        ArgumentNullException.ThrowIfNull(options, nameof(options));
        if (!inputPdf.CanSeek)
        {
            throw new ArgumentException("Input PDF stream must be seekable.", nameof(inputPdf));
        }
        if (!outputStream.CanWrite)
        {
            throw new ArgumentException("Output stream must be writable.", nameof(outputStream));
        }

        // Step 1: Copy the original PDF to output and load into memory for parsing.
        (logger ?? NullLogger.Instance).PdfPrepareStarted(inputPdf.Length, options.FieldName, options.ContentsReservedBytes);
        var (_, inputMem) = await CopyAndLoadPdfAsync(inputPdf, outputStream, cancellationToken).ConfigureAwait(false);

        // Step 1b: If signing an existing field, use the dedicated path.
        if (!string.IsNullOrEmpty(options.ExistingFieldName))
        {
            return await PrepareExistingFieldAsync(outputStream, inputPdf, inputMem, options, cancellationToken).ConfigureAwait(false);
        }

        // Step 2: Determine the next available object number.
        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(inputMem.Span);

        // Step 2b: Ensure unique field name — auto-increment if the default name is already used.
        string fieldName = options.FieldName;
        if (fieldName == "Signature1")
        {
            // Count ALL /FT /Sig fields (visible and invisible) to auto-increment
            int existingSigFields = 0;
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

            if (existingSigFields > 0)
            {
                fieldName = $"Signature{existingSigFields + 1}";
            }
        }

        // Step 3: Locate the first page object.
        // Always needed so the widget annotation is added to /Annots (required for Adobe Reader's signature panel).
        bool hasAppearance = options.Appearance != null;
        var (pageObjNum, pageObjDictStart, pageObjDictEnd) = PdfStructureParser.FindFirstPageObject(inputMem.Span);
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
        int acroFormObjNum = reuseAcroForm ? existingAcroFormObjNum : (nextObjNum + 2);
        int appObjNum = reuseAcroForm ? (nextObjNum + 2) : (nextObjNum + 3);
        int imageObjNum = appObjNum + 1;
        int contentsHexLength = options.ContentsReservedBytes * 2;
        DateTime sigNow = DateTime.UtcNow;

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

            if (a.AutoPosition && pageObjNum > 0)
            {
                string pageDict = Encoding.Latin1.GetString(inputMem.Span.Slice(pageObjDictStart, pageObjDictEnd - pageObjDictStart));
                float pageWidth = PdfStructureParser.ParseMediaBoxWidth(inputMem.Span, pageDict);
                int existingSigCount = PdfStructureParser.CountVisibleSignatureAnnotations(inputMem.Span);
                (appX, appY) = SignatureAppearance.ComputeAutoPosition(pageWidth, 0f, existingSigCount, appWidth, appHeight);
            }
            else
            {
                appX = a.X;
                appY = a.Y;
            }
        }

        // Step 5: Build all new PDF objects.
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        string fieldDictText = BuildFieldAnnotation(fieldObjNum, sigObjNum, fieldName, options, hasAppearance, appObjNum, appX, appY, appWidth, appHeight);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDictText);
        byte[] acroFormBytes = BuildAcroFormDictionary(acroFormObjNum, inputMem.Span, existingAcroFormObjNum, fieldObjNum);

        // Only rewrite the Catalog when the AcroForm reference changes or certification is needed.
        // Rewriting the Catalog in a 2nd incremental update (even with identical content) causes
        // EU DSS to flag the 1st signature as inconsistent.
        bool needCatalogUpdate = !reuseAcroForm || options.CertificationLevel is not null;
        byte[]? catalogBytes = needCatalogUpdate
            ? BuildCatalogDictionary(catalogObjNum, inputMem.Span, acroFormObjNum, sigObjNum, options.CertificationLevel)
            : null;

        // Step 6: Write objects and compute byte offsets.
        long sigObjOffset = outputStream.Position;
        long fieldObjOffset = sigObjOffset + sigDictBytes.Length;
        long acroFormObjOffset = fieldObjOffset + fieldDictBytes.Length;

        await outputStream.WriteAsync(sigDictBytes, cancellationToken).ConfigureAwait(false);
        (logger ?? NullLogger.Instance).PdfSigDictWritten(sigObjOffset, sigObjOffset + sigDictText.IndexOf("/ByteRange", StringComparison.Ordinal));
        await outputStream.WriteAsync(fieldDictBytes, cancellationToken).ConfigureAwait(false);
        await outputStream.WriteAsync(acroFormBytes, cancellationToken).ConfigureAwait(false);

        long catalogObjOffset = 0L;
        if (catalogBytes != null)
        {
            catalogObjOffset = outputStream.Position;
            await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 7: Write appearance XObject (if visible) and update page /Annots (always).
        long appObjOffset = 0L;
        long imageObjOffset = 0L;
        long updPageObjOffset = 0L;
        bool hasImage = hasAppearance && options.Appearance?.HasBackgroundImage() == true;
        if (hasAppearance && options.Appearance != null)
        {
            byte[] appearanceBytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0);
            appObjOffset = outputStream.Position;
            await outputStream.WriteAsync(appearanceBytes, cancellationToken).ConfigureAwait(false);

            // If the appearance includes an image XObject, it's concatenated after the form XObject.
            // We need to find where the image object starts within the written bytes.
            if (hasImage)
            {
                string appText = Encoding.Latin1.GetString(appearanceBytes);
                int imgObjIdx = appText.IndexOf($"{imageObjNum} 0 obj", StringComparison.Ordinal);
                if (imgObjIdx >= 0)
                {
                    imageObjOffset = appObjOffset + imgObjIdx;
                }
            }
        }

        // Always add the widget annotation to the page's /Annots array.
        // Adobe Reader requires this to display the signature in the signature panel,
        // even for invisible signatures (Rect [0 0 0 0], no /AP).
        if (pageObjNum > 0)
        {
            byte[] updatedPageBytes = BuildUpdatedPageObject(pageObjNum, inputMem.Span, pageObjDictStart, pageObjDictEnd, fieldObjNum);
            updPageObjOffset = outputStream.Position;
            await outputStream.WriteAsync(updatedPageBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 8: Build and write the cross-reference table and trailer.
        SortedDictionary<int, long> objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset,
            [acroFormObjNum] = acroFormObjOffset
        };
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
            if (hasImage && imageObjOffset > 0)
            {
                objectOffsets[imageObjNum] = imageObjOffset;
            }
        }
        // Trailer /Size must be at least max(all object numbers) + 1.
        int maxObjNum = objectOffsets.Keys.Max();
        int newTrailerSize = maxObjNum + 1;
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        long xrefOffset = outputStream.Position;
        byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset);
        await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);

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

    /// <summary>
    /// Writes the CMS signature bytes (as hex) into the /Contents placeholder of the prepared PDF.
    /// </summary>
    public static async Task FinalizeAsync(Stream outputStream, PdfSignaturePrepareResult prepareResult, byte[] cmsBytes, ILogger? logger = null, CancellationToken cancellationToken = default(CancellationToken))
    {
        ArgumentNullException.ThrowIfNull(outputStream, nameof(outputStream));
        ArgumentNullException.ThrowIfNull(prepareResult, nameof(prepareResult));
        ArgumentNullException.ThrowIfNull(cmsBytes, nameof(cmsBytes));
        if (cmsBytes.Length > prepareResult.ContentsReservedBytes)
        {
            throw new ArgumentException($"CMS bytes ({cmsBytes.Length}) exceed reserved space ({prepareResult.ContentsReservedBytes}).", nameof(cmsBytes));
        }

        string hexSignature = Convert.ToHexString(cmsBytes).ToLowerInvariant().PadRight(prepareResult.ContentsReservedBytes * 2, '0');
        outputStream.Seek(prepareResult.ContentsHexOffset, SeekOrigin.Begin);
        await outputStream.WriteAsync(Encoding.Latin1.GetBytes(hexSignature), cancellationToken).ConfigureAwait(false);
        outputStream.Seek(0L, SeekOrigin.End);
        (logger ?? NullLogger.Instance).PdfFinalized(hexSignature.Length, prepareResult.ContentsReservedBytes * 2);
    }

    // ── Private: I/O helpers ─────────────────────────────────────────────────

    private static async Task<PdfSignaturePrepareResult> PrepareExistingFieldAsync(
        Stream outputStream, Stream inputPdf, Memory<byte> inputMem, SignatureFieldOptions options, CancellationToken cancellationToken)
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
        DateTime sigNow = DateTime.UtcNow;

        // Build signature dictionary
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);

        // Build updated field object with /V pointing to the new sig dict
        var (fObjStart, fObjEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, fieldObjNum);
        string fieldText = Encoding.Latin1.GetString(inputMem.Span.Slice(fObjStart, fObjEnd - fObjStart));
        string updatedField;
        if (fieldText.Contains("/V ", StringComparison.Ordinal))
        {
            // Replace existing /V value
            int vIdx = fieldText.IndexOf("/V ", StringComparison.Ordinal);
            int vEnd = fieldText.IndexOfAny(['\n', '\r', '/'], vIdx + 3);
            if (vEnd < 0)
            {
                vEnd = fieldText.IndexOf(">>", vIdx + 3, StringComparison.Ordinal);
            }

            updatedField = string.Concat(fieldText.AsSpan(0, vIdx), $"/V {sigObjNum} 0 R", fieldText.AsSpan(vEnd));
        }
        else
        {
            // Insert /V before the closing >>
            updatedField = PdfStructureParser.InsertIntoDict(fieldText, $"   /V {sigObjNum} 0 R\n");
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

        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);

        // If DocMDP, also update catalog
        if (options.CertificationLevel is not null)
        {
            int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catalogObjNum);
            int acroFormObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : (nextObjNum + 1);
            byte[] catalogBytes = BuildCatalogDictionary(catalogObjNum, inputMem.Span, acroFormObjNum, sigObjNum, options.CertificationLevel);
            long catalogObjOffset = outputStream.Position;
            await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
            objectOffsets[catalogObjNum] = catalogObjOffset;
        }

        int newTrailerSize = Math.Max(sigObjNum + 1, objectOffsets.Keys.Max() + 1);
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        long xrefOffset = outputStream.Position;
        byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset);
        await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);

        PdfByteRange byteRange = await BackfillByteRangeAsync(outputStream, sigDictText, sigObjOffset, contentsHexLength, cancellationToken).ConfigureAwait(false);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
    }

    private static async Task<(long OriginalPdfLength, Memory<byte> InputMemory)> CopyAndLoadPdfAsync(Stream inputPdf, Stream outputStream, CancellationToken cancellationToken)
    {
        inputPdf.Seek(0L, SeekOrigin.Begin);
        await inputPdf.CopyToAsync(outputStream, cancellationToken).ConfigureAwait(false);
        long originalPdfLength = outputStream.Position;

        inputPdf.Seek(0L, SeekOrigin.Begin);
        byte[] inputBuffer = new byte[originalPdfLength];
        int totalRead;
        int bytesRead;
        for (totalRead = 0; totalRead < inputBuffer.Length; totalRead += bytesRead)
        {
            bytesRead = await inputPdf.ReadAsync(inputBuffer.AsMemory(totalRead), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }
        }

        return (originalPdfLength, inputBuffer.AsMemory(0, totalRead));
    }

    // ── Private: Signature dictionary builders ───────────────────────────────

    private static string BuildSignatureDictionary(int sigObjNum, SignatureFieldOptions options, int contentsHexLength, DateTime signingTime)
    {
        string contentsHexPlaceholder = new string('0', contentsHexLength);

        StringBuilder sigDict = new StringBuilder();
        sigDict.Append($"{sigObjNum} 0 obj\n");
        sigDict.Append("<< /Type /Sig\n");
        sigDict.Append("   /Filter /Adobe.PPKLite\n");
        string subFilterName = (options.SubFilter == PdfSignatureSubFilter.EtsiCadesDetached)
            ? "ETSI.CAdES.detached"
            : "adbe.pkcs7.detached";
        sigDict.Append($"   /SubFilter /{subFilterName}\n");
        sigDict.Append("   /ByteRange [0000000000 0000000000 0000000000 0000000000]\n");
        sigDict.Append($"   /Contents <{contentsHexPlaceholder}>\n");
        if (!string.IsNullOrEmpty(options.SignerName))
        {
            sigDict.Append($"   /Name ({SignatureAppearanceRenderer.EscapePdfString(options.SignerName)})\n");
        }
        if (!string.IsNullOrEmpty(options.Reason))
        {
            sigDict.Append($"   /Reason ({SignatureAppearanceRenderer.EscapePdfString(options.Reason)})\n");
        }
        if (!string.IsNullOrEmpty(options.Location))
        {
            sigDict.Append($"   /Location ({SignatureAppearanceRenderer.EscapePdfString(options.Location)})\n");
        }
        if (!string.IsNullOrEmpty(options.ContactInfo))
        {
            sigDict.Append($"   /ContactInfo ({SignatureAppearanceRenderer.EscapePdfString(options.ContactInfo)})\n");
        }
        sigDict.Append($"   /M (D:{signingTime:yyyyMMddHHmmss}Z)\n");

        // DocMDP: certification signature with transformation method
        if (options.CertificationLevel is { } level)
        {
            sigDict.Append($"   /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P {(int)level} /V /1.2 >> >>]\n");
        }

        sigDict.Append(">>\nendobj\n");

        return sigDict.ToString();
    }

    private static string BuildFieldAnnotation(int fieldObjNum, int sigObjNum, string fieldName, SignatureFieldOptions options, bool hasAppearance, int appObjNum, float appX, float appY, float appWidth, float appHeight)
    {
        StringBuilder fieldDict = new StringBuilder();
        fieldDict.Append($"{fieldObjNum} 0 obj\n");
        fieldDict.Append("<< /Type /Annot\n");
        fieldDict.Append("   /Subtype /Widget\n");
        fieldDict.Append("   /FT /Sig\n");
        fieldDict.Append($"   /T ({SignatureAppearanceRenderer.EscapePdfString(fieldName)})\n");
        fieldDict.Append($"   /V {sigObjNum} 0 R\n");
        fieldDict.Append("   /Border [0 0 0]\n");
        if (hasAppearance)
        {
            fieldDict.Append($"   /Rect [{F(appX)} {F(appY)} {F(appX + appWidth)} {F(appY + appHeight)}]\n");
            fieldDict.Append($"   /AP << /N {appObjNum} 0 R >>\n");
        }
        else
        {
            fieldDict.Append("   /Rect [0 0 0 0]\n");
        }
        fieldDict.Append(">>\nendobj\n");

        return fieldDict.ToString();
    }

    // ── Private: AcroForm & Catalog builders ─────────────────────────────────

    private static byte[] BuildCatalogDictionary(int catalogObjNum, ReadOnlySpan<byte> data, int acroFormObjNum, int sigObjNum = 0, CertificationLevel? certLevel = null)
    {
        var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, catalogObjNum);
        if (objStart >= 0)
        {
            string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
            string updatedCatalog = PdfStructureParser.RemoveKeyFromDict(catalogText, "/AcroForm");
            if (certLevel is not null)
            {
                updatedCatalog = PdfStructureParser.RemoveKeyFromDict(updatedCatalog, "/Perms");
            }
            string inserts = $"   /AcroForm {acroFormObjNum} 0 R\n";
            if (certLevel is not null && sigObjNum > 0)
            {
                inserts += $"   /Perms << /DocMDP {sigObjNum} 0 R >>\n";
            }
            updatedCatalog = PdfStructureParser.InsertIntoDict(updatedCatalog, inserts);
            return Encoding.Latin1.GetBytes(updatedCatalog);
        }

        string permsStr = certLevel is not null && sigObjNum > 0
            ? $" /Perms << /DocMDP {sigObjNum} 0 R >>"
            : "";
        return Encoding.Latin1.GetBytes($"{catalogObjNum} 0 obj\n<< /Type /Catalog /AcroForm {acroFormObjNum} 0 R{permsStr} >>\nendobj\n");
    }

    private static byte[] BuildAcroFormDictionary(int acroFormObjNum, ReadOnlySpan<byte> data, int existingAcroFormObjNum, int fieldObjNum)
    {
        List<string> fieldRefs = [];

        // When reusing an existing AcroForm (same object number) or migrating from
        // a different one, copy the existing /Fields array entries.
        int sourceObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : acroFormObjNum;
        if (sourceObjNum > 0)
        {
            var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, sourceObjNum);
            if (objStart >= 0)
            {
                fieldRefs = PdfStructureParser.ParseFieldsArray(Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart)));
            }
        }

        fieldRefs.Add($"{fieldObjNum} 0 R");
        string fieldsValue = string.Join(" ", fieldRefs);
        return Encoding.Latin1.GetBytes($"{acroFormObjNum} 0 obj\n<< /Type /AcroForm\n   /Fields [{fieldsValue}]\n   /SigFlags 3\n>>\nendobj\n");
    }

    // ── Private: Xref & ByteRange ────────────────────────────────────────────

    private static byte[] BuildXrefTableAndTrailer(SortedDictionary<int, long> objectOffsets, int newTrailerSize, int catalogObjNum, long prevXRef, long xrefOffset)
    {
        StringBuilder xref = new StringBuilder();
        xref.Append("xref\n");

        List<int> sortedObjNums = objectOffsets.Keys.ToList();
        int groupStart = 0;
        while (groupStart < sortedObjNums.Count)
        {
            int firstObjNumInGroup = sortedObjNums[groupStart];
            int groupEnd;
            for (groupEnd = groupStart; groupEnd + 1 < sortedObjNums.Count && sortedObjNums[groupEnd + 1] == sortedObjNums[groupEnd] + 1; groupEnd++)
            {
            }
            int groupCount = groupEnd - groupStart + 1;
            xref.Append($"{firstObjNumInGroup} {groupCount}\n");
            for (int entryIdx = groupStart; entryIdx <= groupEnd; entryIdx++)
            {
                xref.Append($"{objectOffsets[sortedObjNums[entryIdx]]:D10} 00000 n\r\n");
            }
            groupStart = groupEnd + 1;
        }

        xref.Append("trailer\n");
        xref.Append($"<< /Size {newTrailerSize}\n");
        xref.Append($"   /Root {catalogObjNum} 0 R\n");
        xref.Append($"   /Prev {prevXRef}\n");
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(xref.ToString());
    }

    private static async Task<PdfByteRange> BackfillByteRangeAsync(Stream outputStream, string sigDictText, long sigObjOffset, int contentsHexLength, CancellationToken cancellationToken)
    {
        long totalFileLength = outputStream.Position;

        int contentsHexLocalOffset = sigDictText.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
        long byteRange1Length = sigObjOffset + contentsHexLocalOffset - 1;
        long byteRange2Offset = sigObjOffset + contentsHexLocalOffset + contentsHexLength + 1;
        long byteRange2Length = totalFileLength - byteRange2Offset;

        PdfByteRange byteRange = new PdfByteRange
        {
            Offset1 = 0L,
            Length1 = byteRange1Length,
            Offset2 = byteRange2Offset,
            Length2 = byteRange2Length
        };

        string byteRangeValue = $"[0 {byteRange1Length} {byteRange2Offset} {byteRange2Length}]"
            .PadRight("[0000000000 0000000000 0000000000 0000000000]".Length);

        int byteRangeLocalOffset = sigDictText.IndexOf("/ByteRange ", StringComparison.Ordinal);
        long byteRangeWriteOffset = sigObjOffset + byteRangeLocalOffset + "/ByteRange ".Length;

        outputStream.Seek(byteRangeWriteOffset, SeekOrigin.Begin);
        await outputStream.WriteAsync(Encoding.Latin1.GetBytes(byteRangeValue), cancellationToken).ConfigureAwait(false);
        outputStream.Seek(0L, SeekOrigin.End);

        return byteRange;
    }

    // ── Private: Page object update ──────────────────────────────────────────

    private static byte[] BuildUpdatedPageObject(int pageObjNum, ReadOnlySpan<byte> data, int dictStart, int objEnd, int fieldObjNum)
    {
        string dictContent = Encoding.Latin1.GetString(data.Slice(dictStart, objEnd - dictStart));
        string fieldRef = $"{fieldObjNum} 0 R";
        string pageText = $"{pageObjNum} 0 obj {dictContent}";

        int annotsPos = pageText.IndexOf("/Annots [", StringComparison.Ordinal);
        if (annotsPos < 0)
        {
            annotsPos = pageText.IndexOf("/Annots[", StringComparison.Ordinal);
        }

        string updatedPage;
        if (annotsPos >= 0)
        {
            int closeBracketPos = pageText.IndexOf(']', annotsPos);
            if (closeBracketPos >= 0)
            {
                updatedPage = string.Concat(pageText.AsSpan(0, closeBracketPos), " ", fieldRef, pageText.AsSpan(closeBracketPos));
            }
            else
            {
                updatedPage = AppendAnnots(pageText, fieldRef);
            }
        }
        else
        {
            updatedPage = AppendAnnots(pageText, fieldRef);
        }

        return Encoding.Latin1.GetBytes(updatedPage);
    }

    private static string AppendAnnots(string pageObj, string fieldRef)
    {
        int insertPos = pageObj.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertPos < 0)
        {
            insertPos = pageObj.LastIndexOf(">>", StringComparison.Ordinal);
        }
        if (insertPos < 0)
        {
            return pageObj;
        }

        string[] parts = new string[5]
        {
            pageObj.Substring(0, insertPos),
            "   /Annots [",
            fieldRef,
            "]\n",
            null!
        };
        parts[4] = pageObj[insertPos..];
        return string.Concat(parts);
    }

    /// <summary>Formats a float with '.' decimal separator regardless of system locale.</summary>
    private static string F(float value) => value.ToString("F2", CultureInfo.InvariantCulture);
}
