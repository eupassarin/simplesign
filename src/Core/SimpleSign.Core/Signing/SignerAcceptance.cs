using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Applies a <see cref="SigningPolicy"/> before a signature is made: the signing certificate, its
/// chain and the algorithms. Shared by every signer (PAdES, CAdES, XAdES, deferred and batch).
/// </summary>
internal static class SignerAcceptance
{
    /// <summary>
    /// Checks the certificate and its chain against <paramref name="policy"/>. Throws a
    /// <see cref="SigningException"/> on the first check that fails.
    /// </summary>
    internal static async Task EnsureSignerAcceptableAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        BaselineSigning.EnsureCertificateValidNow(certificate);
        EnsureKeyUsage(certificate, policy);
        EnsureKeyStrength(certificate, policy);

        if (!policy.ValidateChainValidity && !policy.CheckRevocation)
        {
            return;
        }

        var ordered = OrderChain(certificate, chain);
        if (policy.ValidateChainValidity)
        {
            EnsureChainValidNow(ordered);
        }

        if (policy.CheckRevocation)
        {
            await EnsureNotRevokedAsync(ordered, revocationChecker, httpClientProvider, logger, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Throws when <paramref name="hashAlgorithm"/> is not allowed by <paramref name="policy"/>.</summary>
    internal static void EnsureHashAllowed(HashAlgorithmName hashAlgorithm, SigningPolicy policy)
    {
        if (policy.AllowedHashAlgorithms.Count > 0 && !policy.AllowedHashAlgorithms.Contains(hashAlgorithm))
        {
            throw new SigningException(
                $"The hash algorithm {hashAlgorithm.Name} is not allowed by the signing policy " +
                $"(allowed: {string.Join(", ", policy.AllowedHashAlgorithms.Select(h => h.Name))}).",
                SigningErrorReason.AlgorithmNotPermitted);
        }
    }

    private static void EnsureKeyUsage(X509Certificate2 certificate, SigningPolicy policy)
    {
        if (!policy.RequireSigningKeyUsage)
        {
            return;
        }

        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        const X509KeyUsageFlags SigningUsages = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;
        if (keyUsage is null || (keyUsage.KeyUsages & SigningUsages) == 0)
        {
            throw new SigningException(
                $"Certificate '{certificate.Subject}' does not allow digital signatures: " +
                (keyUsage is null
                    ? "it has no key usage extension."
                    : "its key usage has neither digitalSignature nor nonRepudiation."),
                SigningErrorReason.KeyUsageNotPermitted);
        }
    }

    private static void EnsureKeyStrength(X509Certificate2 certificate, SigningPolicy policy)
    {
        string? keyAlgorithm = certificate.PublicKey.Oid.Value;
        if (keyAlgorithm is Oids.RsaEncryption or Oids.RsaPss)
        {
            if (policy.MinimumRsaKeySize <= 0)
            {
                return;
            }

            int keySize = RsaKeySize(certificate);
            if (keySize < policy.MinimumRsaKeySize)
            {
                throw new SigningException(
                    $"The RSA key of '{certificate.Subject}' has {keySize} bits; the signing policy requires at least {policy.MinimumRsaKeySize}.",
                    SigningErrorReason.KeyTooWeak);
            }
        }
        else if (keyAlgorithm == Oids.EcPublicKey && policy.AllowedEllipticCurves.Count > 0)
        {
            string? curve = NamedCurveOid(certificate);
            if (curve is null || !policy.AllowedEllipticCurves.Contains(curve))
            {
                throw new SigningException(
                    $"The elliptic curve {curve ?? "(explicit parameters)"} of '{certificate.Subject}' is not allowed by the signing policy.",
                    SigningErrorReason.AlgorithmNotPermitted);
            }
        }
    }

    private static int RsaKeySize(X509Certificate2 certificate)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(certificate.PublicKey.EncodedKeyValue.RawData, out _);
        return rsa.KeySize;
    }

    private static string? NamedCurveOid(X509Certificate2 certificate)
    {
        try
        {
            if (certificate.PublicKey.EncodedParameters?.RawData is not { Length: > 0 } parameters)
            {
                return null;
            }

            var reader = new AsnReader(parameters, AsnEncodingRules.DER);
            return reader.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier) ? reader.ReadObjectIdentifier() : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// <summary>
    /// The chain of <paramref name="certificate"/> built from the certificates given with it, leaf
    /// first. No certificate is downloaded and no system store is trusted: the order is all that matters.
    /// </summary>
    internal static IReadOnlyList<X509Certificate2> OrderChain(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        if (chain.Count == 0)
        {
            return [certificate];
        }

        using var x509 = new X509Chain();
        x509.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        x509.ChainPolicy.DisableCertificateDownloads = true;
        x509.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        x509.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        x509.ChainPolicy.ExtraStore.AddRange(chain.ToArray());
        x509.Build(certificate);

        var ordered = new List<X509Certificate2>(x509.ChainElements.Count);
        foreach (var element in x509.ChainElements)
        {
            byte[] raw = element.Certificate.RawData;
            ordered.Add(
                raw.AsSpan().SequenceEqual(certificate.RawData) ? certificate
                : chain.FirstOrDefault(c => raw.AsSpan().SequenceEqual(c.RawData))
                ?? CertificateLoader.LoadCertificate(raw));
        }

        return ordered;
    }

    private static void EnsureChainValidNow(IReadOnlyList<X509Certificate2> ordered)
    {
        var now = DateTimeOffset.UtcNow;
        for (int i = 1; i < ordered.Count; i++)
        {
            var issuer = ordered[i];
            if (issuer.NotBefore > now || issuer.NotAfter < now)
            {
                throw new SigningException(
                    $"Certificate '{issuer.Subject}' of the signing chain is not valid at {now:yyyy-MM-dd HH:mm:ss} UTC " +
                    $"(valid from {issuer.NotBefore.ToUniversalTime():yyyy-MM-dd} to {issuer.NotAfter.ToUniversalTime():yyyy-MM-dd}).",
                    SigningErrorReason.ChainCertificateNotValid);
            }
        }
    }

    private static async Task EnsureNotRevokedAsync(
        IReadOnlyList<X509Certificate2> ordered,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var last = ordered[^1];
        if (!last.SubjectName.RawData.AsSpan().SequenceEqual(last.IssuerName.RawData))
        {
            throw new SigningException(
                $"The revocation of the signing chain cannot be checked: the issuer of '{last.Subject}' was not given. " +
                "Pass the whole chain, up to the root, with the signing certificate.",
                SigningErrorReason.RevocationStatusUnknown);
        }

        var checker = revocationChecker
            ?? new ChainRevocationChecker(httpClientProvider.GetClient(), logger, httpClientProvider.OutboundPolicy);
        var result = await checker.CheckAsync(ordered, DateTimeOffset.UtcNow, [], [], allowOnline: true, cancellationToken)
            .ConfigureAwait(false);
        switch (result.Status)
        {
            case ChainRevocationStatus.Revoked:
                throw new SigningException(
                    "A certificate of the signing chain is revoked. " + string.Join(" ", result.Messages),
                    SigningErrorReason.CertificateRevoked);
            case ChainRevocationStatus.Good:
                return;
            default:
                throw new SigningException(
                    "The revocation status of the signing chain could not be established. " + string.Join(" ", result.Messages),
                    SigningErrorReason.RevocationStatusUnknown);
        }
    }
}
