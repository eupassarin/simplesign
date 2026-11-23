using System.Globalization;
using System.IO.Compression;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>What <see cref="PdfEnvelopeWriter.Write"/> writes besides the manifest.</summary>
/// <param name="Signers">The signers, in order, with their placements.</param>
/// <param name="TimestampUrl">The time-stamp server the fields of a level that needs one name in their seed values; null: none named.</param>
/// <param name="Certification">The certification the first field's seed values ask for (<c>/SV /MDP</c>); null: none.</param>
/// <param name="LockDocument">Whether the last field of a sequential envelope locks the document once signed (<c>/Lock /P 1</c>).</param>
internal sealed record PdfEnvelopeLayout(IReadOnlyList<EnvelopeSigner> Signers, Uri? TimestampUrl, CertificationLevel? Certification, bool LockDocument);

/// <summary>
/// Writes an envelope into a document (ADR 0033) in one incremental update: a signature field per signer (merged with
/// its widget, with seed values and a lock), the manifest as an associated file in <c>/AF</c> and
/// <c>/Names /EmbeddedFiles</c>, the AcroForm and the pages that hold the widgets, and, for PDF/A-2, an XMP that
/// declares PDF/A-3.
/// </summary>
internal static class PdfEnvelopeWriter
{
    /// <summary>The digest methods the fields' seed values offer (<c>/SV /DigestMethod</c>), not required.</summary>
    private static readonly string[] s_digestMethods = ["SHA256", "SHA384", "SHA512"];

    /// <summary>The prefix of the envelope's field names.</summary>
    public const string FieldPrefix = "SimpleSign_";

    /// <summary>Writes the envelope.</summary>
    /// <param name="pdf">The document.</param>
    /// <param name="manifest">The manifest, whose signers' fields are those of <paramref name="layout"/>.</param>
    /// <param name="layout">The fields' placements and seed values.</param>
    /// <returns>The document with the envelope.</returns>
    /// <exception cref="SigningException">The document is encrypted, signed, certified, PDF/A-1 or PDF/A-4 without embedded files, or already holds an envelope.</exception>
    /// <exception cref="ArgumentException">A placement is outside the document's pages.</exception>
    public static byte[] Write(ReadOnlyMemory<byte> pdf, EnvelopeManifest manifest, PdfEnvelopeLayout layout)
    {
        var document = PdfDocument.Open(pdf);
        if (document.IsEncrypted)
        {
            throw new SigningException("The PDF is encrypted: an envelope cannot be prepared in it. Decrypt it first.", SigningErrorReason.DocumentEncrypted);
        }

        var view = document.View();
        if (document.RootId is not { } rootId || document.GetObject(rootId) is not { Value: PdfDictionary catalog } catalogObject)
        {
            throw new PdfStructureException("The PDF's catalog cannot be read: an envelope cannot be prepared in it.");
        }

        Refuse(view);
        var pdfA = PdfStructureReader.PdfALevelOf(view);
        if (pdfA is PdfALevel.A1a or PdfALevel.A1b or PdfALevel.A4a or PdfALevel.A4b or PdfALevel.A4u or PdfALevel.Unknown)
        {
            throw new SigningException(
                $"The PDF declares PDF/A ({pdfA}), which cannot hold the envelope's associated file: PDF/A-2, PDF/A-3 and PDF/A-4e can.",
                SigningErrorReason.DocumentNotSignable);
        }

        var pages = layout.Signers.Select(s => PageOf(view, s.Placement)).ToList();
        bool pdfAFlags = pdfA is not PdfALevel.None;

        // Object numbers: each field and its appearance, the file specification and the embedded file, a new AcroForm.
        int next = view.NextObjectNumber;
        int count = layout.Signers.Count;
        var fieldNumbers = Enumerable.Range(0, count).Select(i => next + (2 * i)).ToArray();
        next += 2 * count;
        int fileSpecNumber = next++;
        int embeddedFileNumber = next++;
        var acroFormValue = catalog.Get(PdfName.AcroForm);
        int acroFormNumber = acroFormValue is PdfReference acroFormReference ? acroFormReference.Id.Number : next++;

        var update = new PdfIncrementalUpdate(document);
        string[] names = [.. manifest.Signers.Select(s => s.Field)];
        for (int i = 0; i < count; i++)
        {
            var signer = layout.Signers[i];
            var placement = signer.Placement;
            int appearance = fieldNumbers[i] + 1;
            update.Add(fieldNumbers[i], Field(names, i, signer, manifest.Order, layout, pages[i].Id!.Value.Number, appearance, pdfAFlags));
            var form = new PdfDictionary(
                ("Type", PdfName.Of("XObject")),
                ("Subtype", PdfName.Of("Form")),
                ("BBox", new PdfArray([PdfObjectSerializer.Coordinate(0), PdfObjectSerializer.Coordinate(0), PdfObjectSerializer.Coordinate(placement.Width), PdfObjectSerializer.Coordinate(placement.Height)])),
                ("Resources", new PdfDictionary()),
                ("Length", new PdfInteger(0)));
            update.Add(appearance, new PdfStream(form, ReadOnlyMemory<byte>.Empty));
        }

        // The manifest: the file specification and the embedded file.
        byte[] json = EnvelopeManifestJson.Serialize(manifest);
        byte[] compressed = Deflate(json);
        var date = PdfObjectSerializer.TextString(string.Create(CultureInfo.InvariantCulture, $"D:{manifest.PreparedAt.UtcDateTime:yyyyMMddHHmmss}+00'00'"));
        var fileName = PdfObjectSerializer.TextString(EnvelopeManifest.FileName);
        update.Add(fileSpecNumber, new PdfDictionary(
            ("Type", PdfName.Of("Filespec")),
            ("F", fileName),
            ("UF", fileName),
            ("Desc", PdfObjectSerializer.TextString("SimpleSign signature envelope")),
            ("AFRelationship", PdfName.Of("Data")),
            ("EF", new PdfDictionary(("F", new PdfReference(embeddedFileNumber)), ("UF", new PdfReference(embeddedFileNumber))))));
        update.Add(embeddedFileNumber, new PdfStream(
            new PdfDictionary(
                ("Type", PdfName.Of("EmbeddedFile")),
                ("Subtype", PdfName.Of("application/json")),
                ("Params", new PdfDictionary(("Size", new PdfInteger(json.Length)), ("CreationDate", date), ("ModDate", date))),
                ("Filter", PdfName.Of("FlateDecode")),
                ("Length", new PdfInteger(compressed.Length))),
            compressed));

        // The AcroForm with the fields: the existing object, or a new one (an inline AcroForm moved out of the catalog).
        string fieldRefs = string.Join(" ", fieldNumbers.Select(n => string.Create(CultureInfo.InvariantCulture, $"{n} 0 R")));
        var catalogSource = PdfObjectSource.Of(document, rootId.Number, catalogObject, keepHeader: true);
        var (existingAcroForm, acroFormSource) = acroFormValue is PdfReference reference
            ? document.GetObject(reference.Id) is { Value: PdfDictionary indirect } acroFormObject
                ? (indirect, PdfObjectSource.Of(document, reference.Id.Number, acroFormObject).Buffer)
                : (null, ReadOnlyMemory<byte>.Empty)
            : (acroFormValue as PdfDictionary, catalogSource.Buffer);
        update.Add(acroFormNumber, PdfFormUpdate.AcroFormObject(document, acroFormNumber, existingAcroForm, acroFormSource, fieldRefs));

        // The catalog: the AcroForm, the name tree of embedded files and /AF.
        var patch = new PdfDictionaryPatch(catalogSource.ObjectBytes);
        if (acroFormValue is not PdfReference)
        {
            patch.Set(PdfName.AcroForm.Value, $"{acroFormNumber} 0 R");
        }

        var fileSpec = new PdfReference(fileSpecNumber);
        var namesValue = catalog.Get("Names");
        var namesDictionary = view.Resolve(namesValue) as PdfDictionary ?? new PdfDictionary();
        var tree = PdfNameTreeWriter.Insert(view, namesDictionary.Get("EmbeddedFiles"), fileName, fileSpec);
        foreach (var (number, node) in tree.Objects)
        {
            update.Add(number, node);
        }

        if (tree.InlineRoot is { } root)
        {
            var names2 = PdfNameTreeWriter.With(namesDictionary, PdfName.Of("EmbeddedFiles"), root);
            if (namesValue is PdfReference namesReference)
            {
                update.Add(namesReference.Id.Number, names2);
            }
            else
            {
                patch.Set("Names", PdfObjectSerializer.ToText(names2));
            }
        }

        var associated = view.Resolve(catalog.Get("AF")) is PdfArray af ? af.ToList() : [];
        associated.Add(fileSpec);
        patch.Set("AF", PdfObjectSerializer.ToText(new PdfArray(associated)));
        update.Add(rootId.Number, PdfFormUpdate.WithFinalLineFeed(patch.ToBytes()));

        // The pages, each with its widgets in /Annots.
        foreach (var group in Enumerable.Range(0, count).GroupBy(i => pages[i].Id!.Value.Number))
        {
            if (document.GetObject(group.Key) is { } pageObject)
            {
                string refs = string.Join(" ", group.Select(i => string.Create(CultureInfo.InvariantCulture, $"{fieldNumbers[i]} 0 R")));
                update.Add(group.Key, PdfFormUpdate.WithFinalLineFeed(PdfFormUpdate.PageWithAnnotation(document, group.Key, pageObject, refs)));
            }
        }

        // PDF/A-2 declared PDF/A-3: an associated file of any type needs part 3.
        if (pdfA is PdfALevel.A2a or PdfALevel.A2b or PdfALevel.A2u)
        {
            WritePdfAPart3(document, view, catalog, update);
        }

        return update.Finish(update.Offsets.Keys.Max() + 1, rootId.Number);
    }

    /// <summary>Refuses a document that is signed or certified, or already holds an envelope.</summary>
    private static void Refuse(PdfRevisionView view)
    {
        if (view.CertificationSignature is not null || view.Signatures.Any(s => !s.IsUsageRights))
        {
            throw new SigningException(
                "The PDF is already signed: an envelope is prepared before the first signature, since a field added after one is a change validators report.",
                SigningErrorReason.DocumentNotSignable);
        }

        if (view.Fields.Any(f => f.FullName.StartsWith(FieldPrefix, StringComparison.Ordinal))
            || view.NameTree("EmbeddedFiles").Any(e => e.Key.Text == EnvelopeManifest.FileName))
        {
            throw new SigningException("The PDF already holds an envelope.", SigningErrorReason.DocumentNotSignable);
        }
    }

    private static PdfPage PageOf(PdfRevisionView view, EnvelopePlacement placement)
    {
        if (placement.Page < 1 || placement.Page > view.Pages.Count)
        {
            throw new ArgumentException($"Page {placement.Page} is not a page of the document, which has {view.Pages.Count}.", nameof(placement));
        }

        var page = view.Pages[placement.Page - 1];
        return page.Id is null
            ? throw new PdfStructureException($"Page {placement.Page} is not an object of its own: a field cannot be placed on it.")
            : page;
    }

    /// <summary>The signature field, merged with its widget: no <c>/V</c>, its seed values and its lock.</summary>
    private static PdfDictionary Field(string[] names, int index, EnvelopeSigner signer, EnvelopeOrder order, PdfEnvelopeLayout layout, int page, int appearance, bool pdfA)
    {
        var p = signer.Placement;
        var seedValues = new List<PdfDictionaryEntry> { new(PdfName.Type, PdfName.Of("SV"), null) };
        if (signer.Level.Timestamp && layout.TimestampUrl is { } tsa)
        {
            seedValues.Add(new(PdfName.Of("TimeStamp"), new PdfDictionary(
                ("URL", new PdfString(System.Text.Encoding.ASCII.GetBytes(tsa.AbsoluteUri), PdfStringForm.Literal)),
                ("Ff", new PdfInteger(1))), null));
        }

        if (index == 0 && layout.Certification is { } certification)
        {
            seedValues.Add(new(PdfName.Of("MDP"), new PdfDictionary(("P", new PdfInteger((int)certification))), null));
        }

        seedValues.Add(new(PdfName.Of("DigestMethod"), new PdfArray(s_digestMethods.Select(d => (PdfObject)PdfName.Of(d))), null));
        seedValues.Add(new(PdfName.Of("Cert"), new PdfDictionary(
            ("Type", PdfName.Of("SVCert")),
            ("KeyUsage", new PdfArray([PdfObjectSerializer.TextString("1XXXXXXXX")]))), null));
        if (signer.Reasons.Count > 0)
        {
            seedValues.Add(new(PdfName.Of("Reasons"), new PdfArray(signer.Reasons.Select(r => (PdfObject)PdfObjectSerializer.TextString(r))), null));
        }

        var others = names.Where((_, i) => i != index).Select(n => (PdfObject)PdfObjectSerializer.TextString(n)).ToList();
        var fieldLock = new List<PdfDictionaryEntry> { new(PdfName.Type, PdfName.Of("SigFieldLock"), null) };
        if (others.Count == 0)
        {
            fieldLock.Add(new(PdfName.Of("Action"), PdfName.Of("All"), null));
        }
        else
        {
            fieldLock.Add(new(PdfName.Of("Action"), PdfName.Of("Exclude"), null));
            fieldLock.Add(new(PdfName.Of("Fields"), new PdfArray(others), null));
        }

        if (layout.LockDocument && order == EnvelopeOrder.Sequential && index == names.Length - 1)
        {
            fieldLock.Add(new(PdfName.Of("P"), new PdfInteger(1), null));
        }

        return new PdfDictionary(
            ("Type", PdfName.Of("Annot")),
            ("Subtype", PdfName.Of("Widget")),
            ("FT", PdfName.Of("Sig")),
            ("T", PdfObjectSerializer.TextString(names[index])),
            ("F", new PdfInteger(pdfA ? 4 : 132)),
            ("P", new PdfReference(page)),
            ("Rect", new PdfArray([
                PdfObjectSerializer.Coordinate(p.X), PdfObjectSerializer.Coordinate(p.Y),
                PdfObjectSerializer.Coordinate(p.X + p.Width), PdfObjectSerializer.Coordinate(p.Y + p.Height)])),
            ("AP", new PdfDictionary(("N", new PdfReference(appearance)))),
            ("SV", new PdfDictionary(seedValues)),
            ("Lock", new PdfDictionary(fieldLock)));
    }

    /// <summary>The catalog's XMP written again, unfiltered, with <c>pdfaid:part</c> 3.</summary>
    private static void WritePdfAPart3(PdfDocument document, PdfRevisionView view, PdfDictionary catalog, PdfIncrementalUpdate update)
    {
        if (catalog.Get("Metadata") is not PdfReference metadataReference || view.Resolve(metadataReference) is not PdfStream metadata)
        {
            throw new PdfStructureException("The PDF/A document's XMP metadata cannot be read: it cannot be declared PDF/A-3.");
        }

        byte[] xmp = PdfXmpPatch.SetPdfAPart(document.DecodeStream(metadata), 3)
            ?? throw new PdfStructureException("The PDF/A part of the document's XMP metadata cannot be changed: it cannot be declared PDF/A-3.");
        var entries = metadata.Dictionary
            .Where(e => e.Key.Value is not ("Filter" or "DecodeParms" or "Length" or "DL"))
            .Select(e => new PdfDictionaryEntry(e.Key, e.Value, null))
            .Append(new PdfDictionaryEntry(PdfName.Of("Length"), new PdfInteger(xmp.Length), null));
        update.Add(metadataReference.Id.Number, new PdfStream(new PdfDictionary(entries), xmp));
    }

    private static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return output.ToArray();
    }
}
