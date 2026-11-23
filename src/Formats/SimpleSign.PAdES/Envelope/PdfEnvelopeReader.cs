using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Envelope;

/// <summary>Where an envelope stands.</summary>
public enum EnvelopeStatus
{
    /// <summary>Prepared: no field is signed yet.</summary>
    Prepared = 0,

    /// <summary>Some fields are signed, others not.</summary>
    InProgress = 1,

    /// <summary>Every field is signed.</summary>
    Completed = 2,

    /// <summary>The fields and the manifest do not agree, or the manifest changed after the first signature: see <see cref="PdfEnvelopeInfo.Problems"/>.</summary>
    Inconsistent = 3,
}

/// <summary>The seed values of an envelope's field (<c>/SV</c>, ISO 32000-1 §12.7.4.5, Table 234).</summary>
public sealed record EnvelopeSeedValue
{
    /// <summary>The time-stamp server (<c>/TimeStamp /URL</c>); null when none.</summary>
    public Uri? TimestampUrl { get; init; }

    /// <summary>Whether a signature time-stamp is required (<c>/TimeStamp /Ff 1</c>).</summary>
    public bool TimestampRequired { get; init; }

    /// <summary>The certification asked for (<c>/MDP /P</c>): 1, 2 or 3; null when none.</summary>
    public int? CertificationPermissions { get; init; }

    /// <summary>The digest methods offered (<c>/DigestMethod</c>).</summary>
    public IReadOnlyList<string> DigestMethods { get; init; } = [];

    /// <summary>The reasons offered (<c>/Reasons</c>).</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

/// <summary>The lock of an envelope's field (<c>/Lock</c>, ISO 32000-1 §12.7.4.5, Table 233).</summary>
/// <param name="Action"><c>All</c>, <c>Include</c> or <c>Exclude</c>.</param>
/// <param name="Fields">The fields it includes or excludes.</param>
/// <param name="Permissions">The document permissions once signed (<c>/P</c>, PDF 2.0); null when none.</param>
public sealed record EnvelopeFieldLock(string Action, IReadOnlyList<string> Fields, int? Permissions);

/// <summary>A field of an envelope, as the document has it.</summary>
public sealed record EnvelopeFieldInfo
{
    /// <summary>The field's name.</summary>
    public required string Name { get; init; }

    /// <summary>The signer the manifest gives the field; null for a field the manifest does not list.</summary>
    public EnvelopeManifestSigner? Signer { get; init; }

    /// <summary>Whether the document has the field.</summary>
    public bool Exists { get; init; }

    /// <summary>Its widget's page and rectangle; null when it has none.</summary>
    public EnvelopePlacement? Placement { get; init; }

    /// <summary>Its seed values; null when it has none.</summary>
    public EnvelopeSeedValue? SeedValue { get; init; }

    /// <summary>Its lock; null when it has none.</summary>
    public EnvelopeFieldLock? Lock { get; init; }

    /// <summary>Whether it is signed.</summary>
    public bool IsSigned { get; init; }

    /// <summary>The position of its signature among the envelope's signatures, from 1, in the order they were made; null when not signed.</summary>
    public int? SignatureOrder { get; init; }

    /// <summary>The signer's certificate, from the signature; null when not signed, or when the signature cannot be read.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>The signer's name: the certificate's common name, else the signature's <c>/Name</c>; null when not signed.</summary>
    public string? SignerName { get; init; }

    /// <summary>The signing time the signature declares; null when not signed or not declared.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>The roles claimed in the signature (signer-attributes-v2).</summary>
    public IReadOnlyList<string> ClaimedRoles { get; init; } = [];
}

/// <summary>An envelope as a document holds it: its manifest, its fields and where it stands.</summary>
public sealed record PdfEnvelopeInfo
{
    /// <summary>The manifest; null when it cannot be read (the status is then <see cref="EnvelopeStatus.Inconsistent"/>).</summary>
    public EnvelopeManifest? Manifest { get; init; }

    /// <summary>Where the envelope stands.</summary>
    public EnvelopeStatus Status { get; init; }

    /// <summary>The fields: the manifest's, in its order, then any other <c>SimpleSign_</c> field.</summary>
    public IReadOnlyList<EnvelopeFieldInfo> Fields { get; init; } = [];

    /// <summary>
    /// The field to sign next: the first not signed, in a sequential envelope; null in a parallel one (any field not
    /// signed may be), or when every field is signed or the envelope is inconsistent.
    /// </summary>
    public EnvelopeFieldInfo? Next { get; init; }

    /// <summary>The fields not signed yet, in order.</summary>
    public IReadOnlyList<EnvelopeFieldInfo> Pending => [.. Fields.Where(f => f.Signer is not null && f.Exists && !f.IsSigned)];

    /// <summary>Why the envelope is inconsistent; empty when it is not.</summary>
    public IReadOnlyList<string> Problems { get; init; } = [];
}

/// <summary>Reads the envelope of a document (ADR 0033): its manifest, its fields, what is signed, and who is next.</summary>
public static class PdfEnvelopeReader
{
    /// <summary>Reads the envelope.</summary>
    /// <param name="pdf">The document.</param>
    /// <returns>The envelope; null when the document holds none (no manifest and no <c>SimpleSign_</c> field).</returns>
    /// <exception cref="EncryptedPdfException">The document is encrypted.</exception>
    /// <exception cref="PdfStructureException">The document's catalog cannot be read.</exception>
    public static PdfEnvelopeInfo? Read(ReadOnlyMemory<byte> pdf)
    {
        var document = PdfDocument.Open(pdf);
        if (document.IsEncrypted)
        {
            throw new EncryptedPdfException("This PDF is encrypted: its envelope cannot be read. Decrypt it first.");
        }

        var view = document.View();
        if (view.Catalog is null)
        {
            throw new PdfStructureException("The PDF's catalog cannot be read.");
        }

        var manifestFile = PdfEmbeddedFiles.Read(pdf).FirstOrDefault(f => f.Name == EnvelopeManifest.FileName);
        var envelopeFields = view.Fields.Where(f => f.FullName.StartsWith(PdfEnvelopeWriter.FieldPrefix, StringComparison.Ordinal)).ToList();
        if (manifestFile is null && envelopeFields.Count == 0)
        {
            return null;
        }

        var problems = new List<string>();
        EnvelopeManifest? manifest = null;
        if (manifestFile is null)
        {
            problems.Add($"The document has envelope fields but no manifest ({EnvelopeManifest.FileName}).");
        }
        else
        {
            try
            {
                manifest = EnvelopeManifestJson.Parse(manifestFile.Data.Span);
            }
            catch (FormatException ex)
            {
                problems.Add(ex.Message);
            }

            if (!manifestFile.IsAssociated)
            {
                problems.Add("The manifest is not an associated file of the document (/AF).");
            }
        }

        // The signatures, in the order they were made (the end of their byte range).
        var signatures = PdfStructureReader.ReadSignatureFields(document)
            .Where(s => !s.IsDocumentTimestamp)
            .OrderBy(s => s.ByteRange.Offset2 + s.ByteRange.Length2)
            .ToList();
        var fields = new List<EnvelopeFieldInfo>();
        var listed = manifest?.Signers ?? [];
        var names = listed.Select(s => s.Field).ToList();
        foreach (var signer in listed)
        {
            fields.Add(FieldInfo(view, signer.Field, signer, envelopeFields, signatures, names, problems));
        }

        foreach (var extra in envelopeFields.Where(f => !names.Contains(f.FullName)))
        {
            problems.Add($"The field '{extra.FullName}' is not in the manifest.");
            fields.Add(FieldInfo(view, extra.FullName, null, envelopeFields, signatures, names, problems));
        }

        if (manifestFile is not null)
        {
            CheckManifestUnchanged(pdf, manifestFile, fields, signatures, problems);
        }

        var status = problems.Count > 0 ? EnvelopeStatus.Inconsistent
            : fields.All(f => f.IsSigned) ? EnvelopeStatus.Completed
            : fields.Any(f => f.IsSigned) ? EnvelopeStatus.InProgress
            : EnvelopeStatus.Prepared;
        return new PdfEnvelopeInfo
        {
            Manifest = manifest,
            Status = status,
            Fields = fields,
            Next = status is EnvelopeStatus.Prepared or EnvelopeStatus.InProgress && manifest?.Order == EnvelopeOrder.Sequential
                ? fields.FirstOrDefault(f => !f.IsSigned)
                : null,
            Problems = problems,
        };
    }

    private static EnvelopeFieldInfo FieldInfo(
        PdfRevisionView view, string name, EnvelopeManifestSigner? signer, List<PdfField> envelopeFields,
        List<PdfSignatureField> signatures, List<string> names, List<string> problems)
    {
        var field = envelopeFields.FirstOrDefault(f => f.FullName == name);
        if (field is null)
        {
            problems.Add($"The field '{name}' of the manifest is not in the document.");
            return new EnvelopeFieldInfo { Name = name, Signer = signer };
        }

        if (!field.IsSignature)
        {
            problems.Add($"The field '{name}' is not a signature field.");
        }

        var fieldLock = LockOf(view, field.Lock);
        if (signer is not null)
        {
            var others = names.Where(n => n != name).ToHashSet(StringComparer.Ordinal);
            bool expected = others.Count == 0
                ? fieldLock?.Action == "All"
                : fieldLock is { Action: "Exclude" } && fieldLock.Fields.ToHashSet(StringComparer.Ordinal).SetEquals(others);
            if (!expected)
            {
                problems.Add($"The lock of the field '{name}' is not the one the envelope gives it.");
            }
        }

        int? order = null;
        X509Certificate2? certificate = null;
        string? signerName = null;
        DateTimeOffset? signingTime = null;
        IReadOnlyList<string> roles = [];
        bool signed = field.Value is not null;
        int index = signatures.FindIndex(s => s.FieldName == field.PartialName);
        if (signed && index >= 0)
        {
            var signature = signatures[index];
            order = signatures.Take(index + 1).Count(s => s.FieldName.StartsWith(PdfEnvelopeWriter.FieldPrefix, StringComparison.Ordinal));
            signerName = signature.SignerName;
            signingTime = signature.PdfSigningTime;
            try
            {
                var cms = CmsParser.Parse(signature.ContentsBytes);
                certificate = cms.SignerCertificate;
                signerName = certificate?.GetNameInfo(X509NameType.SimpleName, false) is { Length: > 0 } cn ? cn : signerName;
                signingTime = cms.SigningTime ?? signingTime;
                roles = Core.Validation.Policy.SignedAttributeFacts.FromCms(cms.SignedAttrs)?.ClaimedRoles ?? [];
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException or InvalidOperationException or ArgumentException)
            {
                // The signature cannot be read: the validator says why.
            }
        }

        return new EnvelopeFieldInfo
        {
            Name = name,
            Signer = signer,
            Exists = true,
            Placement = PlacementOf(view, field),
            SeedValue = SeedValueOf(view, field.SeedValue),
            Lock = fieldLock,
            IsSigned = signed,
            SignatureOrder = order,
            SignerCertificate = certificate,
            SignerName = signed ? signerName : null,
            SigningTime = signed ? signingTime : null,
            ClaimedRoles = roles,
        };
    }

    /// <summary>
    /// After the first signature, the manifest is the one that signature covers: the manifest of the revision it signed
    /// is compared with the current one.
    /// </summary>
    private static void CheckManifestUnchanged(
        ReadOnlyMemory<byte> pdf, PdfEmbeddedFile current, List<EnvelopeFieldInfo> fields, List<PdfSignatureField> signatures, List<string> problems)
    {
        var first = signatures.FirstOrDefault(s => fields.Any(f => f.IsSigned && f.Name == s.FieldName));
        if (first is null)
        {
            return;
        }

        long end = first.ByteRange.Offset2 + first.ByteRange.Length2;
        if (end <= 0 || end > pdf.Length)
        {
            return;
        }

        PdfEmbeddedFile? signed;
        try
        {
            signed = PdfEmbeddedFiles.Read(pdf[..(int)end]).FirstOrDefault(f => f.Name == EnvelopeManifest.FileName);
        }
        catch (PdfStructureException)
        {
            signed = null;
        }

        if (signed is null || !signed.Data.Span.SequenceEqual(current.Data.Span))
        {
            problems.Add("The manifest changed after the first signature.");
        }
    }

    private static EnvelopePlacement? PlacementOf(PdfRevisionView view, PdfField field)
    {
        var widget = field.Widgets.FirstOrDefault(w => w is not null) is { } id && id != field.Id
            ? view.Document.GetObject(id)?.Value as PdfDictionary
            : field.Dictionary;
        if (widget is null || view.Resolve(widget.Get("Rect")) is not PdfArray { Count: 4 } rect)
        {
            return null;
        }

        var numbers = rect.Select(n => view.Resolve(n) switch
        {
            PdfInteger i => i.Value,
            PdfReal r => (float)r.Value,
            _ => float.NaN,
        }).ToArray();
        if (numbers.Any(float.IsNaN))
        {
            return null;
        }

        int page = 0;
        var pageId = (widget.Get("P") as PdfReference)?.Id;
        var widgetId = field.Widgets.FirstOrDefault(w => w is not null) ?? field.Id;
        for (int i = 0; i < view.Pages.Count && page == 0; i++)
        {
            var candidate = view.Pages[i];
            if (pageId is not null && candidate.Id == pageId)
            {
                page = i + 1;
            }
            else if (widgetId is { } w && view.Resolve(candidate.Dictionary.Get("Annots")) is PdfArray annots
                && annots.Any(a => a is PdfReference r && r.Id == w))
            {
                page = i + 1;
            }
        }

        float x = Math.Min(numbers[0], numbers[2]);
        float y = Math.Min(numbers[1], numbers[3]);
        return new EnvelopePlacement(page, x, y, Math.Abs(numbers[2] - numbers[0]), Math.Abs(numbers[3] - numbers[1]));
    }

    private static EnvelopeSeedValue? SeedValueOf(PdfRevisionView view, PdfDictionary? seedValue)
    {
        if (seedValue is null)
        {
            return null;
        }

        var timestamp = view.Resolve(seedValue.Get("TimeStamp")) as PdfDictionary;
        string? url = (view.Resolve(timestamp?.Get("URL")) as PdfString)?.Text;
        return new EnvelopeSeedValue
        {
            TimestampUrl = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri : null,
            TimestampRequired = view.Resolve(timestamp?.Get("Ff")) is PdfInteger { Value: var ff } && (ff & 1) == 1,
            CertificationPermissions = view.Resolve(view.Resolve(seedValue.Get("MDP")) is PdfDictionary mdp ? mdp.Get("P") : null) is PdfInteger p ? (int)p.Value : null,
            DigestMethods = view.Resolve(seedValue.Get("DigestMethod")) is PdfArray digests ? [.. digests.Select(view.Resolve).OfType<PdfName>().Select(n => n.Value)] : [],
            Reasons = view.Resolve(seedValue.Get("Reasons")) is PdfArray reasons ? [.. reasons.Select(view.Resolve).OfType<PdfString>().Select(s => s.Text)] : [],
        };
    }

    private static EnvelopeFieldLock? LockOf(PdfRevisionView view, PdfDictionary? fieldLock) =>
        fieldLock is null || view.Resolve(fieldLock.Get("Action")) is not PdfName action
            ? null
            : new EnvelopeFieldLock(
                action.Value,
                view.Resolve(fieldLock.Get("Fields")) is PdfArray fields ? [.. fields.Select(view.Resolve).OfType<PdfString>().Select(s => s.Text)] : [],
                view.Resolve(fieldLock.Get("P")) is PdfInteger p ? (int)p.Value : null);
}
