using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.XAdES.TrustedLists;

/// <summary>One trust service of a trusted list.</summary>
/// <param name="ProviderName">The trust service provider (TSPName).</param>
/// <param name="ServiceName">The service name.</param>
/// <param name="ServiceType">The ServiceTypeIdentifier URI.</param>
/// <param name="Status">The ServiceStatus URI.</param>
/// <param name="Certificates">The service's digital identity certificates.</param>
public sealed record TrustedListService(
    string ProviderName,
    string ServiceName,
    string ServiceType,
    string Status,
    IReadOnlyList<X509Certificate2> Certificates);

/// <summary>A pointer of a list of trusted lists (LOTL) to another trusted list (<c>OtherTSLPointer</c>).</summary>
/// <param name="Territory">The territory of the pointed list.</param>
/// <param name="Location">Where the list is published (<c>TSLLocation</c>).</param>
/// <param name="MimeType">The MIME type of the list (<c>application/vnd.etsi.tsl+xml</c> for XML), or null.</param>
/// <param name="SignerCertificates">The certificates the pointed list must be signed with.</param>
public sealed record TrustedListPointer(
    string Territory,
    Uri Location,
    string? MimeType,
    IReadOnlyList<X509Certificate2> SignerCertificates);

/// <summary>Which services of a trusted list become trust anchors.</summary>
public sealed record TrustedListOptions
{
    /// <summary>
    /// The certificates the list must be signed with (the scheme operator's). Required: an unsigned list,
    /// or one signed by another key, is refused.
    /// </summary>
    public IReadOnlyList<X509Certificate2> SignerCertificates { get; init; } = [];

    /// <summary>
    /// Endings of the ServiceTypeIdentifier URIs to keep. Default: certification authorities (<c>/CA/QC</c>,
    /// <c>/CA/PKC</c>) and timestamping authorities (<c>/TSA</c>, <c>/TSA/QTST</c>).
    /// </summary>
    public IReadOnlyList<string> ServiceTypes { get; init; } = ["/CA/QC", "/CA/PKC", "/TSA", "/TSA/QTST"];

    /// <summary>
    /// Endings of the ServiceStatus URIs that count as active. Default: granted (TS 119 612),
    /// undersupervision, accredited and supervisionincessation (TS 102 231).
    /// </summary>
    public IReadOnlyList<string> ActiveStatuses { get; init; } = ["/granted", "/undersupervision", "/accredited", "/supervisionincessation"];

    /// <summary>Whether a list whose NextUpdate has passed is refused. Default: <see langword="true"/>.</summary>
    public bool RejectExpired { get; init; } = true;
}

/// <summary>
/// A trusted list (ETSI TS 119 612, and TS 102 231 v3, which shares its structure), read after its XML
/// signature has been checked against the scheme operator's certificate. It is an <see cref="ITrustAnchorProvider"/>:
/// the certificates of the active services of the kept types are the trust anchors.
/// </summary>
public sealed class TrustedList : ITrustAnchorProvider, ITrustedListInfoProvider
{
    private const string Namespace = "http://uri.etsi.org/02231/v2#";
    private readonly List<X509Certificate2> _anchors;
    private readonly List<X509Certificate2> _intermediates;

    private TrustedList(
        string territory, string? operatorName, string? sequenceNumber, DateTimeOffset? issued, DateTimeOffset? nextUpdate,
        IReadOnlyList<TrustedListService> services, TrustedListOptions options, string? version, IReadOnlyList<TrustedListPointer> pointers)
    {
        Version = version;
        Pointers = pointers;
        Territory = territory;
        SchemeOperatorName = operatorName;
        SequenceNumber = sequenceNumber;
        IssueDate = issued;
        NextUpdate = nextUpdate;
        Services = services;
        var kept = services
            .Where(s => options.ServiceTypes.Any(t => s.ServiceType.EndsWith(t, StringComparison.OrdinalIgnoreCase))
                && options.ActiveStatuses.Any(t => s.Status.EndsWith(t, StringComparison.OrdinalIgnoreCase)))
            .SelectMany(s => s.Certificates)
            .ToList();
        _anchors = [.. kept.Where(IsSelfSigned)];
        _intermediates = [.. kept.Where(c => !IsSelfSigned(c))];

        // A trust service identified by a CA certificate that is not self-signed is still an anchor of the list.
        _anchors.AddRange(_intermediates);
    }

    /// <summary>The scheme territory (country code).</summary>
    public string Territory { get; }

    /// <summary>The scheme operator name.</summary>
    public string? SchemeOperatorName { get; }

    /// <summary>The TSLSequenceNumber.</summary>
    public string? SequenceNumber { get; }

    /// <summary>The ListIssueDateTime.</summary>
    public DateTimeOffset? IssueDate { get; }

    /// <summary>The NextUpdate; null for a closed list.</summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>The TSLVersionIdentifier (5 for TS 119 612 v2, 6 for v2.3).</summary>
    public string? Version { get; }

    /// <summary>The pointers to other trusted lists (a LOTL has them: one per member state).</summary>
    public IReadOnlyList<TrustedListPointer> Pointers { get; }

    /// <summary>Where the list was read from, when it was downloaded.</summary>
    public Uri? Location { get; private init; }

    /// <summary>When the list was read (downloaded, or loaded from its cache).</summary>
    public DateTimeOffset LoadedAt { get; private init; } = DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public IReadOnlyList<TrustedListInfo> TrustedLists =>
        [new TrustedListInfo(Territory, Location, Version, IssueDate, NextUpdate, LoadedAt, IsWellSigned: true, _anchors)];

    /// <summary>A copy that records where and when the list was read.</summary>
    internal TrustedList WithOrigin(Uri? location, DateTimeOffset loadedAt) => new(this) { Location = location, LoadedAt = loadedAt };

    private TrustedList(TrustedList other)
    {
        Territory = other.Territory;
        SchemeOperatorName = other.SchemeOperatorName;
        SequenceNumber = other.SequenceNumber;
        IssueDate = other.IssueDate;
        NextUpdate = other.NextUpdate;
        Services = other.Services;
        Version = other.Version;
        Pointers = other.Pointers;
        _anchors = other._anchors;
        _intermediates = other._intermediates;
    }

    /// <summary>Every service of the list, whatever its type and status.</summary>
    public IReadOnlyList<TrustedListService> Services { get; }

    /// <inheritdoc />
    public string RegionCode => Territory;

    /// <inheritdoc />
    public string DisplayName => $"Trusted list {Territory} #{SequenceNumber}";

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _anchors;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => _intermediates;

    /// <summary>Reads a trusted list after checking its signature.</summary>
    /// <param name="xml">The trusted list XML.</param>
    /// <param name="options">The signer certificates and the services to keep.</param>
    /// <returns>The trusted list.</returns>
    /// <exception cref="CryptographicException">The list is not signed by one of <see cref="TrustedListOptions.SignerCertificates"/>, or the signature does not cover the whole list.</exception>
    /// <exception cref="InvalidDataException">The XML is not a trusted list, or its NextUpdate has passed.</exception>
    public static TrustedList Load(byte[] xml, TrustedListOptions options)
    {
        ArgumentNullException.ThrowIfNull(xml);
        ArgumentNullException.ThrowIfNull(options);
        if (options.SignerCertificates.Count == 0)
        {
            throw new ArgumentException("The certificate of the scheme operator is required to check the list.", nameof(options));
        }

        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new InvalidDataException($"The trusted list is not well-formed XML: {ex.Message}", ex);
        }

        var root = doc.DocumentElement;
        if (root is null || root.LocalName != "TrustServiceStatusList" || root.NamespaceURI != Namespace)
        {
            throw new InvalidDataException("The document is not a trusted list (TrustServiceStatusList).");
        }

        VerifySignature(doc, root, options.SignerCertificates);

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("tsl", Namespace);
        var scheme = root.SelectSingleNode("tsl:SchemeInformation", ns)
            ?? throw new InvalidDataException("The trusted list has no SchemeInformation.");
        DateTimeOffset? nextUpdate = ReadDate(scheme.SelectSingleNode("tsl:NextUpdate/tsl:dateTime", ns));
        if (options.RejectExpired && nextUpdate is { } next && next < DateTimeOffset.UtcNow)
        {
            throw new InvalidDataException($"The trusted list expired: its NextUpdate was {next:yyyy-MM-dd HH:mm} UTC.");
        }

        var services = new List<TrustedListService>();
        foreach (XmlNode provider in root.SelectNodes("tsl:TrustServiceProviderList/tsl:TrustServiceProvider", ns)!)
        {
            string providerName = provider.SelectSingleNode("tsl:TSPInformation/tsl:TSPName/tsl:Name", ns)?.InnerText.Trim() ?? string.Empty;
            foreach (XmlNode service in provider.SelectNodes("tsl:TSPServices/tsl:TSPService/tsl:ServiceInformation", ns)!)
            {
                var certificates = new List<X509Certificate2>();
                foreach (XmlNode cert in service.SelectNodes("tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate", ns)!)
                {
                    try
                    {
                        certificates.Add(CertificateLoader.LoadCertificate(Convert.FromBase64String(cert.InnerText.Trim())));
                    }
                    catch (Exception ex) when (ex is FormatException or CryptographicException)
                    {
                        // An unreadable identity adds no anchor.
                    }
                }

                services.Add(new TrustedListService(
                    providerName,
                    service.SelectSingleNode("tsl:ServiceName/tsl:Name", ns)?.InnerText.Trim() ?? string.Empty,
                    service.SelectSingleNode("tsl:ServiceTypeIdentifier", ns)?.InnerText.Trim() ?? string.Empty,
                    service.SelectSingleNode("tsl:ServiceStatus", ns)?.InnerText.Trim() ?? string.Empty,
                    certificates));
            }
        }

        return new TrustedList(
            scheme.SelectSingleNode("tsl:SchemeTerritory", ns)?.InnerText.Trim() ?? string.Empty,
            scheme.SelectSingleNode("tsl:SchemeOperatorName/tsl:Name", ns)?.InnerText.Trim(),
            scheme.SelectSingleNode("tsl:TSLSequenceNumber", ns)?.InnerText.Trim(),
            ReadDate(scheme.SelectSingleNode("tsl:ListIssueDateTime", ns)),
            nextUpdate,
            services,
            options,
            scheme.SelectSingleNode("tsl:TSLVersionIdentifier", ns)?.InnerText.Trim(),
            ReadPointers(scheme, ns));
    }

    /// <summary>
    /// Downloads and reads a trusted list. With <paramref name="cacheFile"/>, a list that was read successfully is
    /// kept there, and used when the download fails while its NextUpdate has not passed.
    /// </summary>
    /// <param name="url">The trusted list location.</param>
    /// <param name="options">The signer certificates and the services to keep.</param>
    /// <param name="httpClientProvider">The HTTP client; the default one when null.</param>
    /// <param name="cacheFile">Where to keep the last good list; null for no cache.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The trusted list.</returns>
    public static async Task<TrustedList> DownloadAsync(
        Uri url,
        TrustedListOptions options,
        IHttpClientProvider? httpClientProvider = null,
        string? cacheFile = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(options);
        var provider = httpClientProvider ?? DefaultHttpClientProvider.Instance;
        byte[]? xml = null;
        try
        {
            xml = await ResilientHttp.GetBytesAsync(provider.GetClient(), url, provider.OutboundPolicy, null, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException) when (cacheFile is not null && File.Exists(cacheFile))
        {
            // Fall back to the cached copy below.
        }

        if (xml is null)
        {
            if (cacheFile is not null && File.Exists(cacheFile))
            {
                return Load(await File.ReadAllBytesAsync(cacheFile, cancellationToken).ConfigureAwait(false), options)
                    .WithOrigin(url, File.GetLastWriteTimeUtc(cacheFile));
            }

            throw new HttpRequestException($"The trusted list could not be downloaded from {url}.");
        }

        var list = Load(xml, options).WithOrigin(url, DateTimeOffset.UtcNow);
        if (cacheFile is not null)
        {
            await File.WriteAllBytesAsync(cacheFile, xml, cancellationToken).ConfigureAwait(false);
        }

        return list;
    }

    private static void VerifySignature(XmlDocument doc, XmlElement root, IReadOnlyList<X509Certificate2> signers)
    {
        var signatures = root.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        if (signatures.Count != 1 || signatures[0] is not XmlElement signatureElement || signatureElement.ParentNode != root)
        {
            throw new CryptographicException("The trusted list must carry exactly one enveloped signature.");
        }

        var signedXml = new SignedXml(doc);
        signedXml.LoadXml(signatureElement);

        // The signature must cover the whole list: a reference to the document or to the root element's Id.
        string rootId = root.GetAttribute("Id");
        bool coversRoot = signedXml.SignedInfo!.References.OfType<Reference>().Any(r =>
            r.Uri is { Length: 0 } || (rootId.Length > 0 && r.Uri == "#" + rootId));
        if (!coversRoot)
        {
            throw new CryptographicException("The signature of the trusted list does not cover the whole list.");
        }

        if (!signers.Any(signer => signedXml.CheckSignature(signer, verifySignatureOnly: true)))
        {
            throw new CryptographicException("The trusted list is not signed by the scheme operator's certificate.");
        }
    }

    /// <summary>The OtherTSLPointer entries of SchemeInformation/PointersToOtherTSL.</summary>
    private static List<TrustedListPointer> ReadPointers(XmlNode scheme, XmlNamespaceManager ns)
    {
        var pointers = new List<TrustedListPointer>();
        foreach (XmlNode pointer in scheme.SelectNodes("tsl:PointersToOtherTSL/tsl:OtherTSLPointer", ns)!)
        {
            string? location = pointer.SelectSingleNode("tsl:TSLLocation", ns)?.InnerText.Trim();
            if (location is null || !Uri.TryCreate(location, UriKind.Absolute, out var uri))
            {
                continue;
            }

            string territory = string.Empty;
            string? mimeType = null;
            foreach (XmlNode info in pointer.SelectNodes("tsl:AdditionalInformation/tsl:OtherInformation/*", ns)!)
            {
                switch (info.LocalName)
                {
                    case "SchemeTerritory":
                        territory = info.InnerText.Trim();
                        break;
                    case "MimeType":
                        mimeType = info.InnerText.Trim();
                        break;
                    default:
                        break;
                }
            }

            var signers = new List<X509Certificate2>();
            foreach (XmlNode cert in pointer.SelectNodes("tsl:ServiceDigitalIdentities/tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate", ns)!)
            {
                try
                {
                    signers.Add(CertificateLoader.LoadCertificate(Convert.FromBase64String(cert.InnerText.Trim())));
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                {
                    // An unreadable identity cannot check the list.
                }
            }

            pointers.Add(new TrustedListPointer(territory, uri, mimeType, signers));
        }

        return pointers;
    }

    private static DateTimeOffset? ReadDate(XmlNode? node) =>
        node is not null && DateTimeOffset.TryParse(node.InnerText.Trim(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var value) ? value : null;

    private static bool IsSelfSigned(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
}
