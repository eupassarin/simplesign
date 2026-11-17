using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// The stamp as the library draws it, for the Stamp page: the signed copy, the page and the widget rectangle
/// [x, y, width, height] in points (origin at the bottom left), and how long it took.
/// </summary>
/// <param name="FileId">The signed copy, to show with pdf.js.</param>
/// <param name="Page">The page of the stamp (1 is the first; automatic placement too); null: the existing field's page.</param>
/// <param name="Rect">The widget rectangle the library wrote, or null when it cannot be read.</param>
/// <param name="Ms">How long the signature took.</param>
public sealed record StampPreview(string FileId, int? Page, IReadOnlyList<double>? Rect, long Ms);

/// <summary>
/// Renders the stamp for the live preview: signs a throwaway copy (B-B, no network) with the chosen field and appearance,
/// so pdf.js shows exactly what the library draws. A local credential signs with its real holder name; otherwise a
/// throwaway self-signed certificate does (tokens and cloud signers would prompt).
/// </summary>
internal sealed class StampPreviewService(SandboxEnvironment sandbox, DocumentStore documents, CredentialStore credentials) : IDisposable
{
    private readonly Lock _gate = new();
    private CredentialHandle? _throwaway;
    private string? _lastId;

    public async Task<StampPreview> RenderAsync(SigningOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var document = documents.Get(options.DocumentId ?? throw new ArgumentException(L.T("Choose a document first.")));
        var signer = credentials.TryGet(options.CredentialId, out var chosen) && chosen!.External is null ? chosen : Throwaway();
        var preview = options with
        {
            Kind = SignatureKind.Baseline,
            Level = BaselineLevel.BB,
            Mode = RunMode.Sign,
            SubFilter = SubFilterChoice.EtsiCadesDetached,
            Padding = RsaPadding.Pkcs1,
            Hash = HashChoice.Sha256,
            PreservePdfA = false,
            Certification = CertificationChoice.None,
            UseSignerDetails = false,
            DocumentInfo = [],
            SigningPolicyId = null,
            Appearance = options.Appearance with { Visible = true },
        };
        var plan = new SigningPlan(preview, signer, sandbox, documents);
        var watch = Stopwatch.StartNew();
        var builder = PadesSigner.Document(document.Content)
            .WithCertificate(signer.Certificate, signer.Chain)
            .WithFieldOptions(plan.Field)
            .WithLevel(AdesBaselineProfile.Basic());
        if (preview.SigningTime is { } time)
        {
            builder = builder.WithSigningTime(time);
        }

        byte[] signed = await builder.SignAsync(cancellationToken);
        long ms = watch.ElapsedMilliseconds;
        string id = documents.Add("stamp-preview.pdf", signed).Id;
        lock (_gate)
        {
            // Only the latest preview is kept.
            if (_lastId is { } old)
            {
                documents.Remove(old);
            }

            _lastId = id;
        }

        var a = preview.Appearance;
        int? page = preview.FieldMode == FieldMode.Existing ? null : a.Page;
        return new StampPreview(id, page, Rect(signed, preview.FieldMode == FieldMode.Existing ? preview.ExistingFieldName : preview.FieldName), ms);
    }

    /// <summary>The /Rect of the signature field's widget, as [x, y, width, height]; null when it cannot be read.</summary>
    internal static IReadOnlyList<double>? Rect(byte[] pdf, string? fieldName)
    {
        try
        {
            var widget = PdfStructureDumper.ExtractSignatureObjects(pdf)
                .LastOrDefault(o => o.Entries.Any(e => e.Key == "/Rect")
                    && (fieldName is null || o.Entries.Any(e => e.Key == "/T" && e.RawValue.Contains(fieldName, StringComparison.Ordinal))));
            string? raw = widget?.Entries.First(e => e.Key == "/Rect").RawValue;
            if (raw is null)
            {
                return null;
            }

            double[] n = [.. raw.Trim('[', ']', ' ').Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(v => double.Parse(v, NumberStyles.Float, CultureInfo.InvariantCulture))];
            return n.Length == 4 ? [Math.Min(n[0], n[2]), Math.Min(n[1], n[3]), Math.Abs(n[2] - n[0]), Math.Abs(n[3] - n[1])] : null;
        }
        catch (Exception ex) when (ex is FormatException or InvalidDataException or ArgumentException)
        {
            return null;
        }
    }

    private CredentialHandle Throwaway()
    {
        lock (_gate)
        {
            if (_throwaway is null)
            {
                using var key = RSA.Create(2048);
                var request = new CertificateRequest("CN=Stamp preview, O=SimpleSign TestBench", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
                var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
                _throwaway = new CredentialHandle(CredentialKind.Pfx, "stamp preview", certificate, [certificate], null, certificate);
            }

            return _throwaway;
        }
    }

    public void Dispose() => _throwaway?.Dispose();
}
