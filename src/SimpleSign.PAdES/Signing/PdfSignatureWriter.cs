using System.Globalization;
using System.IO.Compression;
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
    /// Default number of bytes reserved for the CMS signature hex contents (16 KB).
    /// Typical PAdES CMS signatures are 7–14 KB; 16 KB provides safe headroom
    /// while avoiding the excessive padding that inflates file size.
    /// </summary>
    public const int DefaultContentsReservedBytes = 16384;

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
        string fieldDictText = BuildFieldAnnotation(fieldObjNum, sigObjNum, fieldName, options, hasAppearance, appObjNum, appX, appY, appWidth, appHeight, pageObjNum);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDictText);
        byte[] acroFormBytes = BuildAcroFormDictionary(acroFormObjNum, inputMem.Span, existingAcroFormObjNum, fieldObjNum, catalogObjNum);

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
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        string? trailerId = PdfStructureParser.FindTrailerId(inputMem.Span);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(inputMem.Span);
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

        string hexSignature = Convert.ToHexString(cmsBytes).PadRight(prepareResult.ContentsReservedBytes * 2, '0');
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
        sigDict.Append($"   /M (D:{signingTime:yyyyMMddHHmmss}+00'00')\n");

        // DocMDP: certification signature with transformation method
        if (options.CertificationLevel is { } level)
        {
            sigDict.Append($"   /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P {(int)level} /V /1.2 >> >>]\n");
        }

        sigDict.Append(">>\nendobj\n");

        return sigDict.ToString();
    }

    private static string BuildFieldAnnotation(int fieldObjNum, int sigObjNum, string fieldName, SignatureFieldOptions options, bool hasAppearance, int appObjNum, float appX, float appY, float appWidth, float appHeight, int pageObjNum = 0)
    {
        StringBuilder fieldDict = new StringBuilder();
        fieldDict.Append($"{fieldObjNum} 0 obj\n");
        fieldDict.Append("<< /Type /Annot\n");
        fieldDict.Append("   /Subtype /Widget\n");
        fieldDict.Append("   /FT /Sig\n");
        fieldDict.Append($"   /T ({SignatureAppearanceRenderer.EscapePdfString(fieldName)})\n");
        fieldDict.Append($"   /V {sigObjNum} 0 R\n");
        if (pageObjNum > 0)
        {
            fieldDict.Append($"   /P {pageObjNum} 0 R\n");
        }
        // /F 132 = Print (4) + Locked (128) for visible; /F 0 for invisible (ISO 32000 §12.5.3)
        fieldDict.Append($"   /F {(hasAppearance ? 132 : 0)}\n");
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
            if (!updatedCatalog.EndsWith('\n'))
            {
                updatedCatalog += "\n";
            }
            return Encoding.Latin1.GetBytes(updatedCatalog);
        }

        // Catalog may be in a compressed Object Stream (common in iText/Adobe PDFs).
        // Try to extract its content and preserve all existing keys.
        string? compressedCatalogContent = PdfStructureParser.ExtractObjectFromObjStm(data, catalogObjNum);
        if (compressedCatalogContent != null)
        {
            // The extracted content is just the dictionary body (e.g. "<< /Type /Catalog /Pages 2 0 R ... >>")
            string catalogDict = compressedCatalogContent.Trim();
            // Wrap it as a proper object
            string fullObj = $"{catalogObjNum} 0 obj\n{catalogDict}\nendobj\n";
            string updatedCatalog = PdfStructureParser.RemoveKeyFromDict(fullObj, "/AcroForm");
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
            if (!updatedCatalog.EndsWith('\n'))
            {
                updatedCatalog += "\n";
            }
            return Encoding.Latin1.GetBytes(updatedCatalog);
        }

        string permsStr = certLevel is not null && sigObjNum > 0
            ? $" /Perms << /DocMDP {sigObjNum} 0 R >>"
            : "";
        return Encoding.Latin1.GetBytes($"{catalogObjNum} 0 obj\n<< /Type /Catalog /AcroForm {acroFormObjNum} 0 R{permsStr} >>\nendobj\n");
    }

    internal static byte[] BuildAcroFormDictionary(int acroFormObjNum, ReadOnlySpan<byte> data, int existingAcroFormObjNum, int fieldObjNum, int catalogObjNum = 0)
    {
        List<string> fieldRefs = [];
        string extraKeys = "";

        // When reusing an existing AcroForm (same object number) or migrating from
        // a different one, copy the existing /Fields array entries and preserve extra keys.
        int sourceObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : acroFormObjNum;
        if (sourceObjNum > 0)
        {
            var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, sourceObjNum);
            if (objStart >= 0)
            {
                string acroFormText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
                fieldRefs = PdfStructureParser.ParseFieldsArray(acroFormText);
                // /Fields may be an indirect reference (e.g., "/Fields 50 0 R" → separate array object)
                if (fieldRefs.Count == 0)
                {
                    fieldRefs = PdfStructureParser.ResolveIndirectFields(data, acroFormText);
                }
                extraKeys = ExtractExtraAcroFormKeys(acroFormText);
            }
            else
            {
                // The AcroForm object may be stored in a compressed Object Stream (PDF 1.5+).
                // This is common with iText, Adobe, and other modern PDF generators.
                string? compressedContent = PdfStructureParser.ExtractObjectFromObjStm(data, sourceObjNum);
                if (compressedContent != null)
                {
                    fieldRefs = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(data, sourceObjNum);
                    extraKeys = ExtractExtraAcroFormKeys(compressedContent);
                }
            }
        }

        // Fallback: if no fields found from indirect AcroForm, try inline AcroForm in Catalog
        if (fieldRefs.Count == 0 && catalogObjNum > 0)
        {
            fieldRefs = PdfStructureParser.ExtractInlineAcroFormFields(data, catalogObjNum);
        }

        fieldRefs.Add($"{fieldObjNum} 0 R");
        string fieldsValue = string.Join(" ", fieldRefs);
        return Encoding.Latin1.GetBytes($"{acroFormObjNum} 0 obj\n<< /Fields [{fieldsValue}]\n   /SigFlags 3\n{extraKeys}>>\nendobj\n");
    }

    /// <summary>
    /// Extracts AcroForm dictionary keys other than /Fields, /SigFlags, and /Type,
    /// preserving them for the rebuilt AcroForm (e.g., /DR, /DA, /Q, /NeedAppearances, /XFA).
    /// </summary>
    private static string ExtractExtraAcroFormKeys(string acroFormText)
    {
        var sb = new StringBuilder();
        int pos = 0;
        while (pos < acroFormText.Length)
        {
            int keyStart = acroFormText.IndexOf('/', pos);
            if (keyStart < 0)
            {
                break;
            }

            // Extract key name (stops at whitespace, '/', '<', '[', or '>')
            int nameEnd = keyStart + 1;
            while (nameEnd < acroFormText.Length &&
                   acroFormText[nameEnd] != ' ' && acroFormText[nameEnd] != '\n' &&
                   acroFormText[nameEnd] != '\r' && acroFormText[nameEnd] != '/' &&
                   acroFormText[nameEnd] != '<' && acroFormText[nameEnd] != '[' &&
                   acroFormText[nameEnd] != '>')
            {
                nameEnd++;
            }

            string keyName = acroFormText[keyStart..nameEnd];

            // Skip keys we already handle explicitly
            if (keyName is "/Fields" or "/SigFlags" or "/Type")
            {
                pos = nameEnd;
                continue;
            }

            // Extract the value — find where the next top-level key starts
            int valueStart = nameEnd;
            int valueEnd = FindNextTopLevelKey(acroFormText, valueStart);
            string value = acroFormText[valueStart..valueEnd].TrimEnd();

            sb.Append($"   {keyName}{value}\n");
            pos = valueEnd;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Finds the position of the next top-level PDF dictionary key (starting with '/')
    /// or the end-of-dictionary marker ('>>'), skipping nested structures.
    /// </summary>
    private static int FindNextTopLevelKey(string text, int start)
    {
        int depth = 0;
        for (int i = start; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '<' && i + 1 < text.Length && text[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (c == '[')
            {
                depth++;
            }
            else if (c == '>' && i + 1 < text.Length && text[i + 1] == '>')
            {
                if (depth > 0)
                {
                    depth--;
                    i++;
                }
                else
                {
                    return i;
                }
            }
            else if (c == ']')
            {
                if (depth > 0)
                {
                    depth--;
                }
            }
            else if (c == '/' && depth == 0 && i > start)
            {
                return i;
            }
        }

        return text.Length;
    }

    // ── Private: Xref & ByteRange ────────────────────────────────────────────

    private static byte[] BuildXrefTableAndTrailer(SortedDictionary<int, long> objectOffsets, int newTrailerSize, int catalogObjNum, long prevXRef, long xrefOffset, string? trailerId = null, string? trailerInfo = null)
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
        if (trailerId != null)
        {
            xref.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            xref.Append($"   {trailerInfo}\n");
        }
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(xref.ToString());
    }

    /// <summary>
    /// Builds a cross-reference stream (ISO 32000 §7.5.8) for incremental updates.
    /// Used when the original PDF uses xref streams. The stream dictionary serves as the trailer.
    /// Returns the xref stream bytes and a tuple indicating the object number used.
    /// </summary>
    internal static (byte[] Bytes, int XRefObjNum) BuildXrefStream(
        SortedDictionary<int, long> objectOffsets, int xrefObjNum, int newTrailerSize,
        int catalogObjNum, long prevXRef, long xrefStreamOffset,
        string? trailerId = null, string? trailerInfo = null)
    {
        // ISO 32000 §7.5.8: the cross-reference stream MUST include an entry for itself
        var allOffsets = new SortedDictionary<int, long>(objectOffsets)
        {
            [xrefObjNum] = xrefStreamOffset
        };

        // Build /Index array and binary entry data
        // /W [1 4 1] = 6 bytes per entry: type(1) + offset(4, big-endian) + gen(1)
        List<int> sortedObjNums = allOffsets.Keys.ToList();

        // Build /Index groups (contiguous object number ranges)
        var indexParts = new List<string>();
        var entries = new List<byte>();

        int groupStart = 0;
        while (groupStart < sortedObjNums.Count)
        {
            int firstObjNum = sortedObjNums[groupStart];
            int groupEnd;
            for (groupEnd = groupStart;
                 groupEnd + 1 < sortedObjNums.Count &&
                 sortedObjNums[groupEnd + 1] == sortedObjNums[groupEnd] + 1;
                 groupEnd++)
            {
            }
            int groupCount = groupEnd - groupStart + 1;
            indexParts.Add($"{firstObjNum} {groupCount}");

            for (int i = groupStart; i <= groupEnd; i++)
            {
                long offset = allOffsets[sortedObjNums[i]];
                entries.Add(1); // type 1 = regular object
                entries.Add((byte)((offset >> 24) & 0xFF));
                entries.Add((byte)((offset >> 16) & 0xFF));
                entries.Add((byte)((offset >> 8) & 0xFF));
                entries.Add((byte)(offset & 0xFF));
                entries.Add(0); // generation 0
            }
            groupStart = groupEnd + 1;
        }

        // Compress the entry data with zlib (RFC 1950 = 2-byte header + deflate + Adler-32)
        // PDF /FlateDecode expects zlib-wrapped data, NOT raw deflate
        byte[] rawData = entries.ToArray();
        byte[] compressedData;
        using (var ms = new MemoryStream())
        {
            using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write(rawData, 0, rawData.Length);
            }
            compressedData = ms.ToArray();
        }

        string indexArray = string.Join(" ", indexParts);

        var sb = new StringBuilder();
        sb.Append($"{xrefObjNum} 0 obj\n");
        sb.Append("<< /Type /XRef\n");
        sb.Append($"   /Size {newTrailerSize}\n");
        sb.Append($"   /Root {catalogObjNum} 0 R\n");
        sb.Append($"   /Prev {prevXRef}\n");
        sb.Append("   /W [1 4 1]\n");
        sb.Append($"   /Index [{indexArray}]\n");
        sb.Append("   /Filter /FlateDecode\n");
        sb.Append($"   /Length {compressedData.Length}\n");
        if (trailerId != null)
        {
            sb.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            sb.Append($"   {trailerInfo}\n");
        }
        sb.Append(">>\n");
        sb.Append("stream\n");

        byte[] headerBytes = Encoding.Latin1.GetBytes(sb.ToString());

        byte[] footerBytes = Encoding.Latin1.GetBytes(
            $"\nendstream\nendobj\nstartxref\n{xrefStreamOffset}\n%%EOF\n");

        // Combine: header + compressed data + footer
        byte[] result = new byte[headerBytes.Length + compressedData.Length + footerBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
        Buffer.BlockCopy(compressedData, 0, result, headerBytes.Length, compressedData.Length);
        Buffer.BlockCopy(footerBytes, 0, result, headerBytes.Length + compressedData.Length, footerBytes.Length);

        return (result, xrefObjNum);
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

    internal static byte[] BuildUpdatedPageObject(int pageObjNum, ReadOnlySpan<byte> data, int dictStart, int objEnd, int fieldObjNum)
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
            // Find the matching ']' using bracket counting (handles nested arrays like /Border [0 0 0])
            int openBracketPos = pageText.IndexOf('[', annotsPos);
            int closeBracketPos = -1;
            if (openBracketPos >= 0)
            {
                int depth = 0;
                for (int i = openBracketPos; i < pageText.Length; i++)
                {
                    if (pageText[i] == '[')
                    {
                        depth++;
                    }
                    else if (pageText[i] == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            closeBracketPos = i;
                            break;
                        }
                    }
                }
            }

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
            // Check for /Annots as indirect reference (e.g., "/Annots 45 0 R")
            int annotsKeyPos = pageText.IndexOf("/Annots", StringComparison.Ordinal);
            if (annotsKeyPos >= 0)
            {
                int cursor = annotsKeyPos + "/Annots".Length;
                while (cursor < pageText.Length && (pageText[cursor] == ' ' || pageText[cursor] == '\n' || pageText[cursor] == '\r'))
                {
                    cursor++;
                }

                // Check if it's an indirect reference (digit starts object number)
                if (cursor < pageText.Length && char.IsDigit(pageText[cursor]))
                {
                    // Parse the object number
                    int refObjNum = 0;
                    while (cursor < pageText.Length && char.IsDigit(pageText[cursor]))
                    {
                        refObjNum = refObjNum * 10 + (pageText[cursor++] - '0');
                    }

                    if (refObjNum > 0)
                    {
                        // Resolve the indirect reference and get the array contents
                        var (refStart, refEnd) = PdfStructureParser.FindObjectBytes(data, refObjNum);
                        string existingRefs = "";
                        if (refStart >= 0)
                        {
                            string refObj = Encoding.Latin1.GetString(data.Slice(refStart, refEnd - refStart));
                            int bracketOpen = refObj.IndexOf('[');
                            int bracketClose = refObj.LastIndexOf(']');
                            if (bracketOpen >= 0 && bracketClose > bracketOpen)
                            {
                                existingRefs = refObj.Substring(bracketOpen + 1, bracketClose - bracketOpen - 1).Trim();
                            }
                        }

                        // Replace the indirect reference with an inline array that includes the new field
                        string annotsSection = string.IsNullOrEmpty(existingRefs)
                            ? $"/Annots [{fieldRef}]"
                            : $"/Annots [{existingRefs} {fieldRef}]";

                        // Find the end of the indirect reference ("N 0 R")
                        int refEnd2 = cursor;
                        // skip " 0 R"
                        while (refEnd2 < pageText.Length && pageText[refEnd2] != 'R')
                        {
                            refEnd2++;
                        }
                        if (refEnd2 < pageText.Length)
                        {
                            refEnd2++; // include 'R'
                        }

                        updatedPage = string.Concat(pageText.AsSpan(0, annotsKeyPos), annotsSection, pageText.AsSpan(refEnd2));
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
            }
            else
            {
                updatedPage = AppendAnnots(pageText, fieldRef);
            }
        }

        if (!updatedPage.EndsWith('\n'))
        {
            updatedPage += "\n";
        }
        return Encoding.Latin1.GetBytes(updatedPage);
    }

    /// <summary>
    /// Extracts a page object from a compressed ObjStm and rewrites it as a regular object
    /// with the new field annotation appended to /Annots.
    /// </summary>
    internal static byte[] BuildUpdatedPageObjectFromObjStm(int pageObjNum, ReadOnlySpan<byte> data, int fieldObjNum)
    {
        string? pageContent = PdfStructureParser.ExtractObjectFromObjStm(data, pageObjNum);
        if (pageContent == null)
        {
            return [];
        }

        string fieldRef = $"{fieldObjNum} 0 R";
        string pageText = $"{pageObjNum} 0 obj\n{pageContent.Trim()}\nendobj\n";

        // Reuse the same /Annots manipulation logic
        int annotsPos = pageText.IndexOf("/Annots [", StringComparison.Ordinal);
        if (annotsPos < 0)
        {
            annotsPos = pageText.IndexOf("/Annots[", StringComparison.Ordinal);
        }

        string updatedPage;
        if (annotsPos >= 0)
        {
            int openBracketPos = pageText.IndexOf('[', annotsPos);
            int closeBracketPos = -1;
            if (openBracketPos >= 0)
            {
                int depth = 0;
                for (int i = openBracketPos; i < pageText.Length; i++)
                {
                    if (pageText[i] == '[')
                    {
                        depth++;
                    }
                    else if (pageText[i] == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            closeBracketPos = i;
                            break;
                        }
                    }
                }
            }

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
