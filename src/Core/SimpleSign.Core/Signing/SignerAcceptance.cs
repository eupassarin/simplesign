using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Internal;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Applies a <see cref="SigningPolicy"/> before a signature is made: the signing certificate, its
/// chain and the algorithms. Shared by every signer (PAdES, CAdES, XAdES, deferred and batch).
/// A FAIL constraint throws a <see cref="SigningException"/>, a WARN one adds a <see cref="SigningWarning"/>,
/// an INFORM one is logged.
/// </summary>
internal static class SignerAcceptance
{
    /// <summary>
    /// Checks the certificate and its chain against <paramref name="policy"/>. Throws a
    /// <see cref="SigningException"/> on the first FAIL constraint the certificate does not pass.
    /// </summary>
    internal static async Task EnsureSignerAcceptableAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        ICollection<SigningWarning>? warnings,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var tree = policy.Tree;
        Apply(policy.Evaluate(certificate, now), warnings, logger);

        bool caValidity = tree.Level("CACertificate/NotExpired") != ConstraintLevel.Ignore;
        bool certificateCrypto = HasOwnCryptographic(tree, "SigningCertificate") || HasOwnCryptographic(tree, "CACertificate");
        if (!caValidity && !certificateCrypto && !policy.ChecksRevocation)
        {
            return;
        }

        var ordered = OrderChain(certificate, chain);
        var findings = new List<SigningPolicyFinding>();
        if (caValidity)
        {
            for (int i = 1; i < ordered.Count; i++)
            {
                var issuer = ordered[i];
                if (issuer.NotBefore.ToUniversalTime() > now || issuer.NotAfter.ToUniversalTime() < now)
                {
                    findings.Add(new SigningPolicyFinding("CACertificate/NotExpired", tree.Level("CACertificate/NotExpired"),
                        SigningErrorReason.ChainCertificateNotValid,
                        $"Certificate '{issuer.Subject}' of the signing chain is not valid at {now:yyyy-MM-dd HH:mm:ss} UTC " +
                        $"(valid from {issuer.NotBefore.ToUniversalTime():yyyy-MM-dd} to {issuer.NotAfter.ToUniversalTime():yyyy-MM-dd})."));
                }
            }
        }

        if (certificateCrypto)
        {
            for (int i = 0; i < ordered.Count; i++)
            {
                var subject = ordered[i];
                if (CertificateFacts.IsSelfSigned(subject))
                {
                    continue; // A trust anchor's own signature is not checked.
                }

                string context = i == 0 ? "SigningCertificate" : "CACertificate";
                if (!HasOwnCryptographic(tree, context))
                {
                    continue;
                }

                var rules = tree.Crypto(context);
                var algorithm = CryptographicRules.SignatureAlgorithmOf(subject);
                var issuerKey = i + 1 < ordered.Count ? CryptographicRules.KeyOf(ordered[i + 1], algorithm?.Pss == true) : null;
                var checks = (algorithm is null ? [] : rules.CheckDigest(algorithm.Value.Digest, now))
                    .Concat(issuerKey is null ? [] : rules.CheckKey(issuerKey.Value.Algorithm, issuerKey.Value.Size, now));
                findings.AddRange(checks.Select(f => new SigningPolicyFinding(context + "/Cryptographic/" + f.Id, f.Level,
                    SigningErrorReason.AlgorithmNotPermitted, $"The signature of '{subject.Subject}': {f.Message}")));
            }
        }

        Apply(findings, warnings, logger);

        if (policy.ChecksRevocation)
        {
            await CheckRevocationAsync(ordered, tree, revocationChecker, httpClientProvider, logger, warnings, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Checks the digest algorithm of the signature to be made against <paramref name="policy"/>.</summary>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <param name="policy">The signing policy.</param>
    /// <param name="warnings">Where WARN constraints go; null to report only FAIL ones.</param>
    /// <param name="logger">Where INFORM constraints go, or null.</param>
    internal static void EnsureHashAllowed(
        HashAlgorithmName hashAlgorithm, SigningPolicy policy, ICollection<SigningWarning>? warnings = null, ILogger? logger = null) =>
        Apply(policy.EvaluateDigest(hashAlgorithm, DateTimeOffset.UtcNow), warnings, logger, failOnly: warnings is null);

    private static void Apply(IEnumerable<SigningPolicyFinding> findings, ICollection<SigningWarning>? warnings, ILogger? logger, bool failOnly = false)
    {
        foreach (var finding in findings)
        {
            switch (finding.Level)
            {
                case ConstraintLevel.Fail:
                    throw new SigningException(finding.Message, finding.Reason);
                case ConstraintLevel.Warn when !failOnly:
                    warnings?.Add(new SigningWarning(SigningWarningCode.PolicyConstraint, finding.Message));
                    break;
                case ConstraintLevel.Inform when !failOnly:
                    logger?.SigningPolicyInformation(finding.Constraint, finding.Message);
                    break;
                default:
                    break;
            }
        }
    }

    private static bool HasOwnCryptographic(PolicyTree tree, string context) =>
        tree.Root.Find(context + "/Cryptographic") is not null
        || tree.Suites.ContainsKey(context);

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

    private static async Task CheckRevocationAsync(
        IReadOnlyList<X509Certificate2> ordered,
        PolicyTree tree,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        ICollection<SigningWarning>? warnings,
        CancellationToken cancellationToken)
    {
        // The stricter of the signing certificate's and the CA certificates' levels decides.
        var notRevoked = Stricter(tree.Level("SigningCertificate/NotRevoked"), tree.Level("CACertificate/NotRevoked"));
        var available = Stricter(tree.Level("SigningCertificate/RevocationDataAvailable"), tree.Level("CACertificate/RevocationDataAvailable"));

        var last = ordered[^1];
        if (!CertificateFacts.IsSelfSigned(last))
        {
            Apply([new SigningPolicyFinding("RevocationDataAvailable", available, SigningErrorReason.RevocationStatusUnknown,
                $"The revocation of the signing chain cannot be checked: the issuer of '{last.Subject}' was not given. " +
                "Pass the whole chain, up to the root, with the signing certificate.")], warnings, logger);
            return;
        }

        var checker = revocationChecker
            ?? new ChainRevocationChecker(httpClientProvider.GetClient(), logger, httpClientProvider.OutboundPolicy);
        // The status now: OCSP first and fresh CRLs, never a CRL cached before a revocation.
        var result = await checker.CheckCurrentAsync(ordered, cancellationToken).ConfigureAwait(false);
        switch (result.Status)
        {
            case ChainRevocationStatus.Revoked:
                Apply([new SigningPolicyFinding("NotRevoked", notRevoked, SigningErrorReason.CertificateRevoked,
                    "A certificate of the signing chain is revoked. " + string.Join(" ", result.Messages))], warnings, logger);
                break;
            case ChainRevocationStatus.Good:
                break;
            default:
                Apply([new SigningPolicyFinding("RevocationDataAvailable", available, SigningErrorReason.RevocationStatusUnknown,
                    "The revocation status of the signing chain could not be established. " + string.Join(" ", result.Messages))], warnings, logger);
                break;
        }
    }

    private static ConstraintLevel Stricter(ConstraintLevel a, ConstraintLevel b) => (ConstraintLevel)Math.Min((int)a, (int)b);
}
