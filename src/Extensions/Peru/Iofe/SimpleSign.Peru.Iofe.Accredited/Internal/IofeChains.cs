using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>
/// Completes the chain of a signing certificate. A module usually holds the certificate and, at most, its issuing CAs;
/// the root comes from the trust (the trusted list, the roots installed). The whole chain is what the revocation checks
/// cover (guide Req. 11: "cada uno de los certificados que formen parte de la cadena") and what a B-LT signature embeds.
/// </summary>
internal static class IofeChains
{
    private const int MaxDepth = 10;

    /// <summary>
    /// The issuers of <paramref name="certificate"/>, from its issuer up to the root, found among the certificates of
    /// the module and those of the trust. The search stops where no issuer is known: the signing policy then refuses
    /// the certificate for not chaining to a trust anchor.
    /// </summary>
    internal static IReadOnlyList<X509Certificate2> Complete(
        X509Certificate2 certificate, IReadOnlyList<X509Certificate2> moduleCertificates, IReadOnlyList<ITrustAnchorProvider> trust)
    {
        List<X509Certificate2> pool =
        [
            .. moduleCertificates,
            .. trust.SelectMany(p => p.GetIntermediateCertificates()),
            .. trust.SelectMany(p => p.GetTrustAnchors()),
        ];

        var chain = new List<X509Certificate2>();
        var current = certificate;
        while (!IsSelfIssued(current) && chain.Count < MaxDepth)
        {
            var issuer = pool.Find(candidate => Issued(candidate, current));
            if (issuer is null)
            {
                break;
            }

            chain.Add(issuer);
            current = issuer;
        }

        return chain;
    }

    private static bool IsSelfIssued(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);

    /// <summary>Whether <paramref name="issuer"/> names itself as the issuer of <paramref name="subject"/>, by name and, when both carry them, by key identifier.</summary>
    private static bool Issued(X509Certificate2 issuer, X509Certificate2 subject)
    {
        if (!issuer.SubjectName.RawData.AsSpan().SequenceEqual(subject.IssuerName.RawData))
        {
            return false;
        }

        var authorityKey = subject.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().FirstOrDefault()?.KeyIdentifier;
        string? subjectKey = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifier;
        return authorityKey is not { } key || subjectKey is null
            || string.Equals(Convert.ToHexString(key.Span), subjectKey, StringComparison.OrdinalIgnoreCase);
    }
}
