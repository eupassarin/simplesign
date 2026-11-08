using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Policies;

/// <summary>Reads what the certificate constraints of a policy ask about, with the EU DSS names for the values.</summary>
internal static class CertificateFacts
{
    private static readonly Dictionary<string, X509KeyUsageFlags> KeyUsages = new(StringComparer.OrdinalIgnoreCase)
    {
        ["digitalSignature"] = X509KeyUsageFlags.DigitalSignature,
        ["nonRepudiation"] = X509KeyUsageFlags.NonRepudiation,
        ["keyEncipherment"] = X509KeyUsageFlags.KeyEncipherment,
        ["dataEncipherment"] = X509KeyUsageFlags.DataEncipherment,
        ["keyAgreement"] = X509KeyUsageFlags.KeyAgreement,
        ["keyCertSign"] = X509KeyUsageFlags.KeyCertSign,
        ["crlSign"] = X509KeyUsageFlags.CrlSign,
        ["encipherOnly"] = X509KeyUsageFlags.EncipherOnly,
        ["decipherOnly"] = X509KeyUsageFlags.DecipherOnly,
    };

    private static readonly Dictionary<string, string> ExtendedKeyUsages = new(StringComparer.OrdinalIgnoreCase)
    {
        ["serverAuth"] = "1.3.6.1.5.5.7.3.1",
        ["clientAuth"] = "1.3.6.1.5.5.7.3.2",
        ["codeSigning"] = "1.3.6.1.5.5.7.3.3",
        ["emailProtection"] = "1.3.6.1.5.5.7.3.4",
        ["timeStamping"] = "1.3.6.1.5.5.7.3.8",
        ["OCSPSigning"] = "1.3.6.1.5.5.7.3.9",
    };

    /// <summary>Whether the key usage has one of <paramref name="ids"/>; an empty list asks for no particular usage.</summary>
    public static bool HasAnyKeyUsage(X509Certificate2 certificate, IReadOnlyList<string> ids)
    {
        if (ids.Count == 0)
        {
            return true;
        }

        var extension = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        return extension is not null
            && ids.Any(id => KeyUsages.TryGetValue(id, out var flag) && (extension.KeyUsages & flag) != 0);
    }

    /// <summary>Whether the extended key usage has one of <paramref name="ids"/> (DSS names or OIDs).</summary>
    public static bool HasAnyExtendedKeyUsage(X509Certificate2 certificate, IReadOnlyList<string> ids)
    {
        if (ids.Count == 0)
        {
            return true;
        }

        var extension = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (extension is null)
        {
            return false;
        }

        var present = extension.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToHashSet(StringComparer.Ordinal);
        return ids.Any(id => present.Contains(ExtendedKeyUsages.TryGetValue(id, out string? oid) ? oid : id));
    }

    /// <summary>The OIDs of the certificate policies extension.</summary>
    public static IReadOnlyList<string> PolicyIds(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions["2.5.29.32"];
        if (extension is null)
        {
            return [];
        }

        try
        {
            var policies = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            var oids = new List<string>();
            while (policies.HasData)
            {
                oids.Add(policies.ReadSequence().ReadObjectIdentifier());
            }

            return oids;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    /// <summary>The statement OIDs of the QcStatements extension (RFC 3739; QcCompliance 0.4.0.1862.1.1, QcSSCD 0.4.0.1862.1.4).</summary>
    public static IReadOnlyList<string> QcStatements(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions["1.3.6.1.5.5.7.1.3"];
        if (extension is null)
        {
            return [];
        }

        try
        {
            var statements = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            var oids = new List<string>();
            while (statements.HasData)
            {
                oids.Add(statements.ReadSequence().ReadObjectIdentifier());
            }

            return oids;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }

    /// <summary>Whether the certificate is a CA (basic constraints cA = true).</summary>
    public static bool IsCa(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault()?.CertificateAuthority == true;

    /// <summary>Whether the certificate is self-signed (subject equals issuer).</summary>
    public static bool IsSelfSigned(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
}
