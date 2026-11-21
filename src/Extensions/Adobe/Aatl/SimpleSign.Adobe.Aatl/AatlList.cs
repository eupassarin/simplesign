using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Adobe.Aatl;

/// <summary>
/// One copy of the Adobe Approved Trust List, read after its signature has been checked: the list is a PDF signed by
/// Adobe (<c>.acrobatsecuritysettings</c>) that embeds <c>SecuritySettings.xml</c>, the trusted identities.
/// <para>
/// It is a trust anchor provider: the identities that are trusted roots and not removed are the anchors
/// (<see cref="AatlIdentity.IsAnchor"/>). An identity that is not self-signed helps build a chain and decides for it, but
/// the validators trust a chain only when it ends at a self-signed anchor. An anchor with policy restrictions refuses a
/// chain whose signer certificate asserts none of its certificate policies (<see cref="WhyRefused"/>), as Acrobat does.
/// </para>
/// <para>
/// The list has no history: a certification authority taken out of it stops being trusted for the signatures it
/// vouched for before, too. It has no expiry date either: <see cref="SignedAt"/> says how old the copy is.
/// </para>
/// </summary>
public sealed class AatlList : IConstrainedTrustAnchorProvider
{
    /// <summary>The name of the file the list embeds.</summary>
    public const string SettingsFileName = "SecuritySettings.xml";

    private const string CertificatePoliciesOid = "2.5.29.32";

    private static readonly System.Buffers.SearchValues<byte> s_hexadecimalDigits = System.Buffers.SearchValues.Create("0123456789abcdefABCDEF"u8);

    private readonly List<X509Certificate2> _anchors;
    private readonly List<X509Certificate2> _intermediates;

    private AatlList(IReadOnlyList<AatlIdentity> identities, X509Certificate2 signer, DateTimeOffset? signedAt, string sha256)
    {
        Identities = identities;
        Signer = signer;
        SignedAt = signedAt;
        Sha256 = sha256;
        _anchors = [.. identities.Where(i => i.IsAnchor).Select(i => i.Certificate)];
        _intermediates = [.. _anchors.Where(c => !c.IsSelfSigned())];
    }

    /// <summary>Every identity of the list, the removed ones and those that are not trusted roots included.</summary>
    public IReadOnlyList<AatlIdentity> Identities { get; }

    /// <summary>The certificate that signed the list (Adobe's).</summary>
    public X509Certificate2 Signer { get; }

    /// <summary>When the list was signed, as its signature says; null when it does not say.</summary>
    public DateTimeOffset? SignedAt { get; }

    /// <summary>The SHA-256 of the list's file, in lowercase hexadecimal.</summary>
    public string Sha256 { get; }

    /// <summary>Where the list was read from; null when it was given as bytes.</summary>
    public Uri? Location { get; internal init; }

    /// <summary>When this copy was read.</summary>
    public DateTimeOffset LoadedAt { get; internal init; } = DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public string RegionCode => "AATL";

    /// <inheritdoc />
    public string DisplayName => SignedAt is { } signed
        ? string.Create(CultureInfo.InvariantCulture, $"Adobe Approved Trust List ({signed:yyyy-MM-dd}, {_anchors.Count} anchors)")
        : string.Create(CultureInfo.InvariantCulture, $"Adobe Approved Trust List ({_anchors.Count} anchors)");

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _anchors;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => _intermediates;

    /// <summary>This copy, saying where and when it was read.</summary>
    internal AatlList At(Uri location, DateTimeOffset loadedAt) => new(Identities, Signer, SignedAt, Sha256) { Location = location, LoadedAt = loadedAt };

    /// <summary>The identity of a certificate; null when the list does not have it.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The identity, or null.</returns>
    public AatlIdentity? Find(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Identities.FirstOrDefault(i => i.Certificate.RawDataMemory.Span.SequenceEqual(certificate.RawDataMemory.Span));
    }

    /// <summary>
    /// Refuses a chain that reached an anchor with policy restrictions when the signer's certificate asserts none of
    /// the anchor's certificate policies.
    /// </summary>
    /// <inheritdoc />
    public string? WhyRefused(X509Certificate2 anchor, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(anchor);
        ArgumentNullException.ThrowIfNull(chain);
        if (Find(anchor) is not { HasPolicyRestrictions: true } identity || chain.Count == 0)
        {
            return null;
        }

        var asserted = CertificatePoliciesOf(chain[0]);
        if (identity.CertificatePolicies.Any(p => asserted.Contains(p, StringComparer.Ordinal)))
        {
            return null;
        }

        // A list of policies can be long (ICP-Brasil's has almost two hundred): the first ones say which family it is.
        const int shown = 5;
        string what = identity.PolicyDescription is { Length: > 0 } description ? $" ({description})" : "";
        string policies = string.Join(", ", identity.CertificatePolicies.Take(shown))
            + (identity.CertificatePolicies.Count > shown ? $" and {identity.CertificatePolicies.Count - shown} more" : "");
        return $"The Adobe Approved Trust List trusts '{anchor.GetNameInfo(X509NameType.SimpleName, false)}' only for certain certificate " +
            $"policies{what}, and the signer's certificate asserts none of them: {policies}.";
    }

    /// <summary>Reads a copy of the list: its signature is checked, then its identities are read.</summary>
    /// <param name="pdf">The list's file (<c>.acrobatsecuritysettings</c>).</param>
    /// <param name="options">The roots its signature must chain to; null for the bundled Adobe root.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The list.</returns>
    /// <exception cref="CryptographicException">
    /// The file is not signed, its signature does not verify or does not cover the whole file, or the signer does not
    /// chain to <see cref="AatlOptions.ListSigners"/> or is revoked.
    /// </exception>
    /// <exception cref="InvalidDataException">The file is not a PDF with the identities, or they cannot be read.</exception>
    public static async Task<AatlList> LoadAsync(byte[] pdf, AatlOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        options ??= new AatlOptions();
        var (signer, signedAt) = await VerifySignatureAsync(pdf, options, options.CheckRevocation, cancellationToken).ConfigureAwait(false);
        return new AatlList(ReadIdentities(pdf), signer, signedAt, Hash(pdf));
    }

    /// <summary>As <see cref="LoadAsync"/>, for a copy whose signer's revocation is not asked about (the cache file).</summary>
    internal static async Task<AatlList> LoadWithoutRevocationAsync(byte[] pdf, AatlOptions options, CancellationToken cancellationToken)
    {
        var (signer, signedAt) = await VerifySignatureAsync(pdf, options, checkRevocation: false, cancellationToken).ConfigureAwait(false);
        return new AatlList(ReadIdentities(pdf), signer, signedAt, Hash(pdf));
    }

    internal static string Hash(byte[] pdf) => Convert.ToHexString(SHA256.HashData(pdf)).ToLowerInvariant();

    /// <summary>
    /// The signature of the file: it covers the whole file, it verifies, and its signer chains to the list signers
    /// (never to the operating system's roots).
    /// </summary>
    private static async Task<(X509Certificate2 Signer, DateTimeOffset? SignedAt)> VerifySignatureAsync(
        byte[] pdf, AatlOptions options, bool checkRevocation, CancellationToken cancellationToken)
    {
        var signers = options.ListSigners.Count > 0 ? options.ListSigners : AatlExtension.ListSigners;
        var validation = new ValidationOptions { TrustedRoots = signers, TrustSystemRoots = false, CheckRevocation = checkRevocation };
        using var stream = new MemoryStream(pdf, writable: false);
        IReadOnlyList<PdfSignatureField> fields;
        IReadOnlyList<SignatureValidationResult> results;
        try
        {
            fields = [.. (await PdfStructureReader.ReadSignatureFieldsAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false)).Where(f => f.IsSigned)];
            stream.Position = 0;
            results = await new PdfSignatureValidator(options.HttpClientProvider ?? DefaultHttpClientProvider.Instance, validation)
                .ValidateAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is PdfStructureException or EncryptedPdfException)
        {
            throw new InvalidDataException($"The trust list is not a PDF that can be read: {ex.Message}", ex);
        }

        if (fields.Count == 0 || results.Count == 0)
        {
            throw new CryptographicException("The trust list is not signed.");
        }

        // What is read after the signature (the identities) must be what was signed: nothing after the last signature.
        if (!fields.Any(f => f.ByteRange.CoversEntireFile(pdf.Length)))
        {
            throw new CryptographicException("The trust list's signature does not cover the whole file.");
        }

        // Nor in the one place a signature does not cover, its own /Contents: the identities are found by reading the
        // whole file, and an object written there would be read as part of it.
        if (!fields.All(f => HoldsOnlyTheSignature(pdf, f.ByteRange)))
        {
            throw new CryptographicException("The trust list holds something other than the signature where the signature is kept.");
        }

        foreach (var result in results)
        {
            if (!result.IsIntegrityValid || !result.IsSignatureValid)
            {
                throw new CryptographicException($"The trust list's signature does not verify: {Reasons(result)}");
            }

            if (!result.IsCertificateChainValid)
            {
                throw new CryptographicException($"The trust list is not signed by its publisher: {Reasons(result)}");
            }

            if (checkRevocation && !result.IsNotRevoked)
            {
                throw new CryptographicException($"The certificate that signed the trust list is revoked, or its revocation could not be checked: {Reasons(result)}");
            }
        }

        var last = results[^1];
        return (last.SignerCertificate ?? throw new CryptographicException("The trust list's signature has no signer certificate."), last.SigningTime);
    }

    /// <summary>
    /// Whether the bytes a signature's ByteRange leaves out — its /Contents — are a hexadecimal string and nothing else:
    /// <c>&lt;</c>, hexadecimal digits, <c>&gt;</c>. Those bytes are not signed, so anything else there (a PDF object, say)
    /// would be read without any signature vouching for it.
    /// </summary>
    internal static bool HoldsOnlyTheSignature(ReadOnlySpan<byte> pdf, PdfByteRange range)
    {
        long start = range.Offset1 + range.Length1;
        long end = range.Offset2;
        if (start < 0 || end > pdf.Length || end - start < 2)
        {
            return false;
        }

        var contents = pdf[(int)start..(int)end];
        return contents[0] == (byte)'<' && contents[^1] == (byte)'>' && !contents[1..^1].ContainsAnyExcept(s_hexadecimalDigits);
    }

    private static string Reasons(SignatureValidationResult result) =>
        result.Errors.Count > 0 ? string.Join("; ", result.Errors) : "no reason given";

    private static List<AatlIdentity> ReadIdentities(byte[] pdf)
    {
        PdfEmbeddedFile settings;
        try
        {
            settings = PdfEmbeddedFiles.Read(pdf).FirstOrDefault(f => string.Equals(f.Name, SettingsFileName, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidDataException($"The trust list does not embed {SettingsFileName}.");
        }
        catch (Exception ex) when (ex is PdfStructureException or EncryptedPdfException)
        {
            throw new InvalidDataException($"The trust list's embedded files cannot be read: {ex.Message}", ex);
        }

        XDocument document;
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(settings.Data.ToArray()), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document = XDocument.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new InvalidDataException($"{SettingsFileName} is not well-formed XML: {ex.Message}", ex);
        }

        if (document.Root?.Element("TrustedIdentities") is not { } identities)
        {
            throw new InvalidDataException($"{SettingsFileName} has no TrustedIdentities.");
        }

        var read = new List<AatlIdentity>();
        foreach (var identity in identities.Elements("Identity"))
        {
            read.Add(ReadIdentity(identity, read.Count + 1));
        }

        return read;
    }

    // The certificates belong to the list, which lives as long as it is served: not disposed.
#pragma warning disable CA2000
    private static AatlIdentity ReadIdentity(XElement identity, int position)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = LoadCertificate(Convert.FromBase64String((string?)identity.Element("Certificate") ?? ""));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new InvalidDataException($"The certificate of identity {position} of {SettingsFileName} cannot be read: {ex.Message}", ex);
        }

        var trust = identity.Element("Trust");
        var restrictions = identity.Element("PolicyRestrictions");
        return new AatlIdentity(certificate)
        {
            // An identity whose action cannot be read is treated as removed: it gives no trust.
            ImportAction = int.TryParse((string?)identity.Element("ImportAction"), NumberStyles.None, CultureInfo.InvariantCulture, out int action)
                ? action
                : AatlIdentity.RemoveAction,
            IsTrustedRoot = Flag(trust?.Element("Root")),
            IsTrustedForCertifiedDocuments = Flag(trust?.Element("CertifiedDocuments")),
            CertificatePolicies = [.. restrictions?.Element("CertificatePolicies")?.Elements("OID").Select(o => o.Value.Trim()).Where(o => o.Length > 0) ?? []],
            PolicyDescription = (string?)restrictions?.Element("Description"),
            NonExplicitPolicyProcessing = Flag(restrictions?.Element("NonExplicitProcessing")),
            Source = (string?)identity.Element("Identification")?.Element("Source"),
        };
    }

#pragma warning restore CA2000

    private static bool Flag(XElement? element) => element?.Value.Trim() == "1";

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif

    /// <summary>The certificate policies a certificate asserts (RFC 5280 §4.2.1.4); empty when it has no such extension or it cannot be read.</summary>
    internal static IReadOnlyList<string> CertificatePoliciesOf(X509Certificate2 certificate)
    {
        if (certificate.Extensions[CertificatePoliciesOid] is not { } extension)
        {
            return [];
        }

        try
        {
            var policies = new List<string>();
            var sequence = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (sequence.HasData)
            {
                policies.Add(sequence.ReadSequence().ReadObjectIdentifier());
            }

            return policies;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }
}
