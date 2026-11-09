using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Policies;

/// <summary>
/// The RFC 5280 checks of the certificate constraints that read one certificate, or a certificate and its issuer, and
/// the subject attributes the policies can restrict.
/// </summary>
internal static class CertificateChecks
{
    internal const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    internal const string CrlDistributionPoints = "2.5.29.31";
    internal const string AuthorityKeyIdentifier = "2.5.29.35";
    internal const string SubjectKeyIdentifier = "2.5.29.14";
    internal const string NoRevocationAvailable = "2.5.29.56";
    internal const string OcspNoCheck = "1.3.6.1.5.5.7.48.1.5";
    private const string OcspAccessMethod = "1.3.6.1.5.5.7.48.1";

    /// <summary>The subject attributes a policy can restrict, by constraint name.</summary>
    internal static readonly IReadOnlyDictionary<string, string> SubjectAttributes = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["CommonName"] = "2.5.4.3",
        ["Surname"] = "2.5.4.4",
        ["GivenName"] = "2.5.4.42",
        ["Pseudonym"] = "2.5.4.65",
        ["Title"] = "2.5.4.12",
        ["Email"] = "1.2.840.113549.1.9.1",
        ["OrganizationName"] = "2.5.4.10",
        ["OrganizationUnit"] = "2.5.4.11",
        ["OrganizationIdentifier"] = "2.5.4.97",
        ["Country"] = "2.5.4.6",
        ["Locality"] = "2.5.4.7",
        ["State"] = "2.5.4.8",
    };

    internal static bool HasExtension(X509Certificate2 certificate, string oid) => certificate.Extensions[oid] is not null;

    /// <summary>Whether the certificate says where its revocation data is: CRL distribution points or an OCSP access location.</summary>
    internal static bool HasRevocationInfoAccess(X509Certificate2 certificate) =>
        HasExtension(certificate, CrlDistributionPoints) || HasOcspAccess(certificate);

    /// <summary>The OIDs of the extensions the certificate marks critical.</summary>
    internal static IEnumerable<string> CriticalExtensions(X509Certificate2 certificate) =>
        certificate.Extensions.Where(e => e.Critical && e.Oid?.Value is not null).Select(e => e.Oid!.Value!);

    /// <summary>The OIDs of the certificate's extensions that are in <paramref name="forbidden"/>.</summary>
    internal static IEnumerable<string> ForbiddenPresent(X509Certificate2 certificate, IEnumerable<string> forbidden) =>
        forbidden.Where(oid => HasExtension(certificate, oid));

    /// <summary>
    /// RFC 9608: a certificate with noRevAvail is an end-entity certificate without CRL distribution points or an OCSP
    /// access location. True when the extension is absent.
    /// </summary>
    internal static bool NoRevAvailCompliant(X509Certificate2 certificate) =>
        !HasExtension(certificate, NoRevocationAvailable)
        || (!CertificateFacts.IsCa(certificate) && !HasExtension(certificate, CrlDistributionPoints) && !HasOcspAccess(certificate));

    /// <summary>Whether the subject name has a serialNumber attribute.</summary>
    internal static bool HasSubjectSerialNumber(X509Certificate2 certificate) => SubjectValues(certificate, "2.5.4.5").Any();

    /// <summary>Whether the certificate's issuer name is its issuer's subject name.</summary>
    internal static bool IssuerNameMatches(X509Certificate2 certificate, X509Certificate2 issuer) =>
        certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData);

    /// <summary>Whether revocation need not be checked: the certificate has one of the extensions or policies listed.</summary>
    internal static bool SkipsRevocation(X509Certificate2 certificate, IReadOnlyCollection<string> extensions, IReadOnlyCollection<string> policies) =>
        extensions.Any(oid => HasExtension(certificate, oid)) || CertificateFacts.PolicyIds(certificate).Any(policies.Contains);

    /// <summary>
    /// Whether every CA of the chain (signing certificate first, anchor last) allows the certificates below it by its
    /// pathLenConstraint.
    /// </summary>
    internal static bool PathLengthsRespected(IReadOnlyList<X509Certificate2> chain)
    {
        for (int i = 1; i < chain.Count; i++)
        {
            if (chain[i].Extensions["2.5.29.19"] is X509BasicConstraintsExtension { HasPathLengthConstraint: true } basic)
            {
                // Intermediate CAs between this CA and the end-entity certificate (self-issued ones do not count, RFC 5280 §6.1.4).
                int below = 0;
                for (int j = 1; j < i; j++)
                {
                    if (!CertificateFacts.IsSelfSigned(chain[j]))
                    {
                        below++;
                    }
                }

                if (below > basic.PathLengthConstraint)
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// The status flags the platform chain engine gives the chain (built on its own anchor, without revocation and
    /// without times), for the name-constraint and policy-tree checks of RFC 5280 §6.1.
    /// </summary>
    internal static X509ChainStatusFlags ChainFlags(IReadOnlyList<X509Certificate2> chain)
    {
        if (chain.Count == 0)
        {
            return X509ChainStatusFlags.NoError;
        }

        using var x509 = new X509Chain();
        x509.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        x509.ChainPolicy.CustomTrustStore.Add(chain[^1]);
        foreach (var certificate in chain.Skip(1))
        {
            x509.ChainPolicy.ExtraStore.Add(certificate);
        }

        x509.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreNotTimeNested;
        x509.ChainPolicy.DisableCertificateDownloads = true;
        x509.Build(chain[0]);
        var flags = X509ChainStatusFlags.NoError;
        foreach (var element in x509.ChainElements)
        {
            foreach (var status in element.ChainElementStatus)
            {
                flags |= status.Status;
            }
        }

        return flags;
    }

    /// <summary>Whether the flags say the chain breaks its name constraints.</summary>
    internal static bool NameConstraintsRespected(X509ChainStatusFlags flags) =>
        (flags & (X509ChainStatusFlags.InvalidNameConstraints | X509ChainStatusFlags.HasNotSupportedNameConstraint
            | X509ChainStatusFlags.HasNotPermittedNameConstraint | X509ChainStatusFlags.HasExcludedNameConstraint)) == 0;

    /// <summary>Whether the flags say the chain's policy tree is valid.</summary>
    internal static bool PolicyTreeValid(X509ChainStatusFlags flags) =>
        (flags & (X509ChainStatusFlags.InvalidPolicyConstraints | X509ChainStatusFlags.NoIssuanceChainPolicy)) == 0;

    /// <summary>The values of a subject attribute (by OID), as text.</summary>
    internal static IEnumerable<string> SubjectValues(X509Certificate2 certificate, string oid)
    {
        foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.GetSingleElementType().Value == oid && rdn.GetSingleElementValue() is { } value)
            {
                yield return value;
            }
        }
    }

    private static bool HasOcspAccess(X509Certificate2 certificate)
    {
        if (certificate.Extensions[AuthorityInfoAccess] is not { } aia)
        {
            return false;
        }

        try
        {
            var accesses = new AsnReader(aia.RawData, AsnEncodingRules.DER).ReadSequence();
            while (accesses.HasData)
            {
                var access = accesses.ReadSequence();
                if (access.ReadObjectIdentifier() == OcspAccessMethod)
                {
                    return true;
                }

                access.ReadEncodedValue();
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension gives no OCSP location.
        }

        return false;
    }
}
