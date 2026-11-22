using SimpleSign.TestHelpers;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The documents the parity harness compares the readers on: every PDF committed under <c>tests/integration</c>, and
/// documents generated in memory with each kind of cross-reference and the usual breakages.
/// </summary>
internal static class ParityCorpus
{
    /// <summary>
    /// The committed fixtures, by a short name (<c>Integration/51sigs.pdf</c>: the test project without
    /// <c>SimpleSign.</c> and <c>.Tests</c>, then the path under its <c>Fixtures</c>), and their full paths.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Fixtures { get; } = FindFixtures();

    private static SortedDictionary<string, string> FindFixtures()
    {
        var fixtures = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (string project in Directory.EnumerateDirectories(RepositoryPaths.Get("tests", "integration")))
        {
            string dir = Path.Combine(project, "Fixtures");
            if (!Directory.Exists(dir))
            {
                continue;
            }

            string shortName = Path.GetFileName(project).Replace("SimpleSign.", "", StringComparison.Ordinal).Replace(".Tests", "", StringComparison.Ordinal);
            foreach (string path in Directory.EnumerateFiles(dir, "*.pdf", SearchOption.AllDirectories))
            {
                fixtures[shortName + "/" + Path.GetRelativePath(dir, path).Replace('\\', '/')] = path;
            }
        }

        return fixtures;
    }

    private static PdfFileBuilder Base(string eol = "\n") => new PdfFileBuilder(eol: eol)
        .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");

    /// <summary>
    /// The catalogued differences each generated document must show (by rule name); a document not listed must show none.
    /// </summary>
    public static IReadOnlyDictionary<string, string[]> ExpectedRules { get; } = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["hybrid"] = ["HybridXRefStm"],
        ["generation-2"] = ["GenerationAboveZero"],
        ["free-in-update"] = ["FreeEntryHonoured"],
        ["subsection-shifted"] = ["LegacyMisreadsTable"],
        ["lone-cr-table"] = ["LegacyMisreadsTable"],
        ["blank-line-before-trailer"] = ["LegacyMisreadsTable"],
        ["no-startxref"] = ["RebuiltWhereLegacyFailed"],
        ["stray-object-after-eof"] = ["LookupByXref"],
        ["nested-pages"] = ["NestedPageTree"],
        ["signature-field-in-objstm"] = ["FieldInObjectStream"],
        ["signature-nested-field"] = ["FullyQualifiedFieldName"],
        ["signature-prop-build-name"] = ["LegacyKeyAnywhereInDictionary"],
        ["signature-dictionary-rewritten"] = ["ContentsFromDictionary"],
        ["dss-indirect-arrays"] = ["LegacyDssArrayInlineWithSpace", "LegacyVriInlineOnly"],
        ["text-inline-descendant-font"] = ["LegacyInlineDescendantFont"],
        ["text-encrypted"] = ["EncryptedContentUnreadable"],
        ["attachment-predictor"] = ["EmbeddedFileDecodeParms"],
        ["attachment-pdfdoc-name"] = ["PdfDocEncodingText"],
        ["attachment-tree-loop"] = ["NameTreeNodeReadOnce"],
    };

    /// <summary>A document whose catalog's /Names /EmbeddedFiles is object 5.</summary>
    private static PdfFileBuilder Attachments() => new PdfFileBuilder()
        .Object(1, "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 5 0 R >> >>")
        .Object(2, "<< /Type /Pages /Kids [] /Count 0 >>");

    private const string CMap = "/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <0000> <FFFF> "
        + "endcodespacerange 2 beginbfchar <0001> <0041> <0002> <0020> endbfchar 1 beginbfrange <0003> <0005> <0043> endbfrange "
        + "endcmap end end";

    /// <summary>A one-page document that shows "A CDE" with font 4, and the objects it needs after it.</summary>
    private static PdfFileBuilder Text(string font, string content = "BT /F1 10 Tf 20 40 Td <00010002000300040005> Tj ET") => new PdfFileBuilder()
        .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
        .Object(4, font)
        .Stream(5, "", System.Text.Encoding.Latin1.GetBytes(content))
        .Stream(6, "", System.Text.Encoding.Latin1.GetBytes(CMap));

    /// <summary>
    /// Writes a signature dictionary whose /ByteRange gap is exactly its /Contents, as a signer writes it (the CMS is
    /// made up).
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="number">The object number.</param>
    /// <param name="extra">More entries.</param>
    /// <param name="contents">The /Contents, in hexadecimal.</param>
    /// <param name="gapStart">Where the /ByteRange gap starts instead: an earlier copy's /Contents.</param>
    private static PdfFileBuilder Signature(this PdfFileBuilder builder, int number, string extra = "", string contents = "3082AABB", long? gapStart = null)
    {
        gapStart ??= SignatureGap(builder, number);
        long gapEnd = gapStart.Value + contents.Length + 2;
        return builder.Object(number, $"{SignaturePrefix}<{contents}> /ByteRange [0 {gapStart:D10} {gapEnd:D10} 0000000001] /M (D:20260101120000Z) {extra}>>");
    }

    private const string SignaturePrefix = "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /Contents ";

    /// <summary>Where the /Contents of a signature dictionary written next would start.</summary>
    private static long SignatureGap(PdfFileBuilder builder, int number) => builder.Position + $"{number} 0 obj\n".Length + SignaturePrefix.Length;

    private static PdfFileBuilder Catalog(string acroForm, string extra = "") => new PdfFileBuilder()
        .Object(1, $"<< /Type /Catalog /Pages 2 0 R /AcroForm {acroForm} {extra}>>")
        .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .Object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");

    /// <summary>The generated documents, by name.</summary>
    public static IReadOnlyDictionary<string, Func<byte[]>> Generated { get; } = new Dictionary<string, Func<byte[]>>(StringComparer.Ordinal)
    {
        ["table"] = () => Base().EndRevision().ToArray(),
        ["table-crlf"] = () => Base("\r\n").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" }).ToArray(),
        ["table-updates"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision()
            .Object(4, "<< /Producer (update) >>").EndRevision().ToArray(),
        ["stream"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 }).ToArray(),
        ["stream-predictor"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4, Predictor = true }).ToArray(),
        ["stream-updates"] = () => Base().EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 })
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 180 >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 5 }).ToArray(),
        ["table-then-stream"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 270 >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 4 }).ToArray(),
        ["objstm"] = () => new PdfFileBuilder()
            .Compressed(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 5, ObjectStreamNumber = 4 }).ToArray(),
        ["hybrid"] = () => new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Compressed(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R >>")
            .EndRevision(XrefStyle.Hybrid, new RevisionOptions { XrefStreamNumber = 5, ObjectStreamNumber = 4 }).ToArray(),
        ["generation-2"] = () => Base().Object(4, "<< /Tag (gen 2) >>", generation: 2).EndRevision().ToArray(),
        ["free-in-update"] = () => Base().Object(4, "<< /Tag (to delete) >>").EndRevision()
            .Free(4, 1).Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Tag (after delete) >>").EndRevision().ToArray(),
        ["offsets-shifted"] = () => Base().EndRevision(options: new RevisionOptions { OffsetShift = 2 }).ToArray(),
        ["subsection-shifted"] = () => Base().EndRevision(options: new RevisionOptions { ShiftedSubsection = true }).ToArray(),
        ["no-startxref"] = () => Base().EndRevision(options: new RevisionOptions { OmitStartXref = true }).ToArray(),
        ["stray-object-after-eof"] = () => Base().EndRevision()
            .Raw("3 0 obj\n<< /Type /Page /Tag (not in any xref) >>\nendobj\n").ToArray(),
        ["lone-cr-table"] = () => Base("\r").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" })
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision(options: new RevisionOptions { EntryEnd = "\r\n" }).ToArray(),
        ["blank-line-before-trailer"] = () => Base().EndRevision()
            .Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>").EndRevision(options: new RevisionOptions { BeforeTrailer = "\n" }).ToArray(),
        ["nested-pages"] = () => new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 3 /MediaBox [0 0 612 792] >>")
            .Object(3, "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R 6 0 R] /Count 2 /MediaBox [0 0 100 200] >>")
            .Object(4, "<< /Type /Page /Parent 2 0 R >>")
            .Object(5, "<< /Type /Page /Parent 3 0 R >>")
            .Object(6, "<< /Type /Page /Parent 3 0 R /Rotate 90 >>")
            .EndRevision().ToArray(),
        ["signature-held"] = () => Catalog("<< /Fields [10 0 R 12 0 R] /SigFlags 3 >>")
            .Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R >>")
            .Signature(11, "/Reason (approved) /Name (Signer) ")
            .Object(12, "<< /FT /Sig /T (Empty) /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R >>")
            .EndRevision().ToArray(),
        ["signature-certification"] = () => Catalog("<< /Fields [10 0 R] /SigFlags 3 >>", "/Perms << /DocMDP 11 0 R >> ")
            .Object(10, "<< /FT /Sig /T (Cert) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Signature(11, "/Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >>] ")
            .EndRevision().ToArray(),
        ["signature-field-in-objstm"] = () => Catalog("<< /Fields [10 0 R 12 0 R] /SigFlags 3 >>")
            .Compressed(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Compressed(12, "<< /FT /Sig /T (Empty) /Subtype /Widget /Rect [0 0 0 0] >>")
            .Signature(11)
            .EndRevision(XrefStyle.Stream, new RevisionOptions { XrefStreamNumber = 14, ObjectStreamNumber = 13 }).ToArray(),
        ["signature-nested-field"] = () => Catalog("<< /Fields [9 0 R] /SigFlags 3 >>")
            .Object(9, "<< /T (form) /Kids [10 0 R] >>")
            .Object(10, "<< /FT /Sig /T (Sig1) /Parent 9 0 R /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Signature(11)
            .EndRevision().ToArray(),
        ["signature-prop-build-name"] = () => Catalog("<< /Fields [10 0 R] /SigFlags 3 >>")
            .Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>")
            .Signature(11, "/Prop_Build << /App << /Name (Some Signing App) /REx (1.0) >> >> ")
            .EndRevision().ToArray(),
        ["signature-dictionary-rewritten"] = () =>
        {
            // The update writes the signature dictionary again with another /Contents, and the old /ByteRange.
            var builder = Catalog("<< /Fields [10 0 R] /SigFlags 3 >>")
                .Object(10, "<< /FT /Sig /T (Sig1) /V 11 0 R /Subtype /Widget /Rect [0 0 0 0] >>");
            long gap = SignatureGap(builder, 11);
            return builder.Signature(11).EndRevision().Signature(11, contents: "3082CCDD", gapStart: gap).EndRevision().ToArray();
        },
        ["dss-indirect-arrays"] = () => Catalog("<< /Fields [] >>", "/DSS 20 0 R ")
            .Object(20, "<< /Type /DSS /Certs 21 0 R /OCSPs [] /CRLs [] /VRI 22 0 R >>")
            .Object(21, "[23 0 R]")
            .Object(22, "<< /AABBCCDDEEFF00112233445566778899AABBCCDD 24 0 R >>")
            .Stream(23, "", [0x30, 0x00])
            .Object(24, "<< /Cert [23 0 R] >>")
            .EndRevision().ToArray(),
        ["text-helvetica"] = () => Text("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>", "BT /F1 12 Tf 50 700 Td (Contratante: Fulano) Tj ET")
            .EndRevision().ToArray(),
        ["text-type0"] = () => Text("<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Arial /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 6 0 R >>")
            .Object(7, "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+Arial /DW 1000 /W [1 [500 250] 3 5 600] >>")
            .EndRevision().ToArray(),
        ["text-inline-descendant-font"] = () => Text(
                "<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Arial /Encoding /Identity-H /ToUnicode 6 0 R "
                + "/DescendantFonts [<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+Arial /FontDescriptor 7 0 R /DW 1000 /W [1 [500 250] 3 5 600] >>] >>")
            .Object(7, "<< /Type /FontDescriptor /FontName /ABCDEF+Arial /Flags 32 >>")
            .EndRevision().ToArray(),
        ["text-encrypted"] = () => new PdfFileBuilder()
            .Object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
            .Object(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

            // Not zlib (0x0524): what an encrypted stream looks like; after those two bytes, an empty deflate block.
            .Stream(5, "/Filter /FlateDecode", [0x05, 0x24, 0x03, 0x00])
            .Object(9, "<< /Filter /Standard /V 1 /R 2 /O <00> /U <00> /P -4 >>")
            .EndRevision(options: new RevisionOptions { TrailerExtra = "/Encrypt 9 0 R " }).ToArray(),
        ["attachments"] = () => Attachments()
            .Object(5, "<< /Kids [6 0 R] >>")
            .Object(6, "<< /Names [(a.xml) 7 0 R (b.txt) 9 0 R] >>")
            .Object(7, "<< /Type /Filespec /F (a.xml) /UF (a.xml) /EF << /F 8 0 R >> >>")
            .Stream(8, "/Type /EmbeddedFile /Filter /FlateDecode", PdfFileBuilder.Zlib(System.Text.Encoding.ASCII.GetBytes("<invoice/>")))
            .Object(9, "<< /Type /Filespec /F (b.txt) /EF << /F 10 0 R >> >>")
            .Stream(10, "/Type /EmbeddedFile", System.Text.Encoding.ASCII.GetBytes("plain"))
            .EndRevision().ToArray(),
        ["attachment-predictor"] = () => Attachments()
            .Object(5, "<< /Names [(rows.bin) 7 0 R] >>")
            .Object(7, "<< /Type /Filespec /F (rows.bin) /EF << /F 8 0 R >> >>")
            .Stream(8, "/Type /EmbeddedFile /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 2 >>", PdfFileBuilder.Zlib([2, 1, 2, 2, 1, 1]))
            .EndRevision().ToArray(),
        ["attachment-pdfdoc-name"] = () => Attachments()
            .Object(5, "<< /Names [(x) 7 0 R] >>")
            .Object(7, "<< /Type /Filespec /F (\\200 quote.txt) /EF << /F 8 0 R >> >>")
            .Stream(8, "/Type /EmbeddedFile", System.Text.Encoding.ASCII.GetBytes("x"))
            .EndRevision().ToArray(),
        ["attachment-tree-loop"] = () => Attachments()
            .Object(5, "<< /Names [(k) 7 0 R] /Kids [5 0 R] >>")
            .Object(7, "<< /Type /Filespec /F (k) /EF << /F 8 0 R >> >>")
            .Stream(8, "/Type /EmbeddedFile", System.Text.Encoding.ASCII.GetBytes("k"))
            .EndRevision().ToArray(),
        ["prev-loop"] = () =>
        {
            var builder = Base().EndRevision().Object(3, "<< /Type /Page /Parent 2 0 R /Rotate 90 >>");
            return builder.EndRevision(options: new RevisionOptions { Prev = builder.Position }).ToArray();
        },
    };
}
