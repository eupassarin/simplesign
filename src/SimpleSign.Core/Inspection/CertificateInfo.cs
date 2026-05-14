using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Inspection;

/// <summary>
/// Read-only snapshot of an X.509 certificate's metadata.
/// Created from <see cref="X509Certificate2"/> without any network calls.
/// </summary>
public sealed class CertificateInfo
{
    /// <summary>Subject distinguished name.</summary>
    public string Subject { get; init; } = string.Empty;

    /// <summary>Issuer distinguished name.</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>Serial number in hexadecimal.</summary>
    public string SerialNumber { get; init; } = string.Empty;

    /// <summary>Certificate validity start (UTC).</summary>
    public DateTime NotBefore { get; init; }

    /// <summary>Certificate validity end (UTC).</summary>
    public DateTime NotAfter { get; init; }

    /// <summary>SHA-256 thumbprint in hexadecimal.</summary>
    public string Thumbprint { get; init; } = string.Empty;

    /// <summary>Public key algorithm name (e.g., "RSA", "ECDSA", "Ed25519").</summary>
    public string KeyAlgorithm { get; init; } = string.Empty;

    /// <summary>Public key size in bits, or null if not determinable.</summary>
    public int? KeySizeBits { get; init; }

    /// <summary>Whether the certificate has expired relative to <see cref="DateTime.UtcNow"/>.</summary>
    public bool IsExpired => DateTime.UtcNow > NotAfter;

    /// <summary>Whether Key Usage includes Digital Signature or Non-Repudiation.</summary>
    public bool HasNonRepudiation { get; init; }

    /// <summary>Key Usage extension values (e.g., "DigitalSignature", "NonRepudiation").</summary>
    public IReadOnlyList<string> KeyUsages { get; init; } = [];

    /// <summary>Extended Key Usage OIDs (e.g., "1.3.6.1.5.5.7.3.4" for email protection).</summary>
    public IReadOnlyList<string> ExtendedKeyUsages { get; init; } = [];

    /// <summary>OCSP responder URL from Authority Information Access, if present.</summary>
    public string? OcspUrl { get; init; }

    /// <summary>First CRL Distribution Point URL, if present.</summary>
    public string? CrlUrl { get; init; }

    /// <summary>All Authority Information Access URLs (OCSP + CA Issuers).</summary>
    public IReadOnlyList<string> AiaUrls { get; init; } = [];

    /// <summary>The underlying certificate instance for advanced consumers.</summary>
    public X509Certificate2 Certificate { get; init; } = null!;

    /// <summary>
    /// Creates a <see cref="CertificateInfo"/> from an X.509 certificate.
    /// Performs no network calls — all data is extracted locally.
    /// </summary>
    public static CertificateInfo From(X509Certificate2 cert)
    {
        var keyUsages = ExtractKeyUsages(cert);
        var ekus = ExtractExtendedKeyUsages(cert);
        var (ocspUrl, crlUrl, aiaUrls) = ExtractUrls(cert);

        return new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            Thumbprint = cert.Thumbprint,
            KeyAlgorithm = MapKeyAlgorithm(cert),
            KeySizeBits = GetKeySizeBits(cert),
            HasNonRepudiation = keyUsages.Contains("NonRepudiation"),
            KeyUsages = keyUsages,
            ExtendedKeyUsages = ekus,
            OcspUrl = ocspUrl,
            CrlUrl = crlUrl,
            AiaUrls = aiaUrls,
            Certificate = cert
        };
    }

    private static string MapKeyAlgorithm(X509Certificate2 cert)
    {
        var oid = cert.PublicKey.Oid?.Value ?? "Unknown";
        return oid switch
        {
            Constants.Oids.RsaEncryption => "RSA",
            Constants.Oids.EcPublicKey => "ECDSA",
            Constants.Oids.Ed25519 => "Ed25519",
            Constants.Oids.Ed448 => "Ed448",
            _ => oid
        };
    }

    private static int? GetKeySizeBits(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is not null)
            {
                return rsa.KeySize;
            }
        }
        catch { /* not RSA */ }

        try
        {
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                return ecdsa.KeySize;
            }
        }
        catch { /* not ECDSA */ }

        return null;
    }

    private static List<string> ExtractKeyUsages(X509Certificate2 cert)
    {
        var result = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509KeyUsageExtension ku)
            {
                var flags = ku.KeyUsages;
                if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature))
                {
                    result.Add("DigitalSignature");
                }

                if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation))
                {
                    result.Add("NonRepudiation");
                }

                if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                {
                    result.Add("KeyEncipherment");
                }

                if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment))
                {
                    result.Add("DataEncipherment");
                }

                if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement))
                {
                    result.Add("KeyAgreement");
                }

                if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign))
                {
                    result.Add("KeyCertSign");
                }

                if (flags.HasFlag(X509KeyUsageFlags.CrlSign))
                {
                    result.Add("CrlSign");
                }
            }
        }
        return result;
    }

    private static List<string> ExtractExtendedKeyUsages(X509Certificate2 cert)
    {
        var result = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var oid in eku.EnhancedKeyUsages)
                {
                    result.Add(oid.Value ?? string.Empty);
                }
            }
        }
        return result;
    }

    private static (string? ocspUrl, string? crlUrl, List<string> aiaUrls) ExtractUrls(X509Certificate2 cert)
    {
        string? ocspUrl = null;
        string? crlUrl = null;
        var aiaUrls = new List<string>();

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == Constants.Oids.AuthorityInfoAccess)
            {
                TryParseAia(ext.RawData, ref ocspUrl, aiaUrls);
            }
            else if (ext.Oid?.Value == Constants.Oids.CrlDistributionPoints)
            {
                crlUrl ??= TryParseCdp(ext.RawData);
            }
        }

        return (ocspUrl, crlUrl, aiaUrls);
    }

    private static void TryParseAia(byte[] rawData, ref string? ocspUrl, List<string> aiaUrls)
    {
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(rawData, System.Formats.Asn1.AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var accessDesc = seq.ReadSequence();
                var methodOid = accessDesc.ReadObjectIdentifier();
                if (accessDesc.HasData)
                {
                    var tag = accessDesc.PeekTag();
                    if (tag.TagValue == 6) // context [6] = URI
                    {
                        var url = accessDesc.ReadCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, tag);
                        aiaUrls.Add(url);
                        if (methodOid == Constants.Oids.AdOcsp)
                        {
                            ocspUrl ??= url;
                        }
                    }
                    else
                    {
                        accessDesc.ReadEncodedValue();
                    }
                }
            }
        }
        catch { /* best-effort extraction */ }
    }

    private static string? TryParseCdp(byte[] rawData)
    {
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(rawData, System.Formats.Asn1.AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var dp = seq.ReadSequence();
                if (dp.HasData)
                {
                    var tag = dp.PeekTag();
                    if (tag is { TagClass: System.Formats.Asn1.TagClass.ContextSpecific, TagValue: 0 })
                    {
                        var dpName = dp.ReadSequence(tag);
                        if (dpName.HasData)
                        {
                            var nameTag = dpName.PeekTag();
                            if (nameTag is { TagClass: System.Formats.Asn1.TagClass.ContextSpecific, TagValue: 0 })
                            {
                                var generalNames = dpName.ReadSequence(nameTag);
                                while (generalNames.HasData)
                                {
                                    var gnTag = generalNames.PeekTag();
                                    if (gnTag is { TagClass: System.Formats.Asn1.TagClass.ContextSpecific, TagValue: 6 })
                                    {
                                        return generalNames.ReadCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, gnTag);
                                    }
                                    generalNames.ReadEncodedValue();
                                }
                            }
                        }
                    }
                    else
                    {
                        dp.ReadEncodedValue();
                    }
                }
            }
        }
        catch { /* best-effort extraction */ }

        return null;
    }

    /// <inheritdoc />
    public override string ToString() => $"{Subject} (expires {NotAfter:yyyy-MM-dd})";
}
