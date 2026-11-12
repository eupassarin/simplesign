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
    private const string TrustConstraint = "SigningCertificate/ProspectiveCertificateChain";

    /// <summary>
    /// Checks the certificate and its chain against <paramref name="policy"/>. Throws a
    /// <see cref="SigningException"/> on the first FAIL constraint the certificate does not pass.
    /// <paramref name="trustAnchors"/> are where <c>SigningCertificate/ProspectiveCertificateChain</c> looks for the
    /// root; when given, they also complete a chain passed without its root.
    /// </summary>
    internal static async Task EnsureSignerAcceptableAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IReadOnlyList<ITrustAnchorProvider> trustAnchors,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        ICollection<SigningWarning>? warnings,
        CancellationToken cancellationToken) =>
        await EvaluateSignerAsync(
            certificate, chain, policy, trustAnchors, revocationChecker, httpClientProvider, logger,
            findings => Apply(findings, warnings, logger), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// The checks of <see cref="EnsureSignerAcceptableAsync"/>, handing each group of findings to
    /// <paramref name="report"/> (which throws to stop, as a signer does, or keeps them all, as
    /// <see cref="SigningCertificateCheck"/> does). <paramref name="now"/> is the time of the validity, trust and
    /// cryptographic checks; revocation is always checked as it is now.
    /// </summary>
    /// <returns>The chain the checks used, leaf first (ending at a trust anchor when one was found).</returns>
    internal static async Task<IReadOnlyList<X509Certificate2>> EvaluateSignerAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IReadOnlyList<ITrustAnchorProvider> trustAnchors,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        Action<IEnumerable<SigningPolicyFinding>> report,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var tree = policy.Tree;
        report(policy.Evaluate(certificate, now));

        bool caValidity = tree.Level("CACertificate/NotExpired") != ConstraintLevel.Ignore;
        bool certificateCrypto = HasOwnCryptographic(tree, "SigningCertificate") || HasOwnCryptographic(tree, "CACertificate");
        var anchorLevel = tree.Level(TrustConstraint);
        var ordered = OrderChain(certificate, chain);
        if (!caValidity && !certificateCrypto && !policy.ChecksRevocation && anchorLevel == ConstraintLevel.Ignore)
        {
            return ordered;
        }

        if (anchorLevel != ConstraintLevel.Ignore || (trustAnchors.Count > 0 && !CertificateFacts.IsSelfSigned(ordered[^1])))
        {
            var trusted = TrustedChain.Build(certificate, chain, trustAnchors, now, out string? error);
            if (trusted is not null)
            {
                ordered = trusted;
            }
            else
            {
                report([new SigningPolicyFinding(TrustConstraint, anchorLevel, SigningErrorReason.UntrustedRoot, error!)]);
            }
        }

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

        report(findings);

        if (policy.ChecksRevocation)
        {
            await CheckRevocationAsync(ordered, tree, revocationChecker, httpClientProvider, logger, report, cancellationToken).ConfigureAwait(false);
        }

        return ordered;
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

    private static Task CheckRevocationAsync(
        IReadOnlyList<X509Certificate2> ordered,
        PolicyTree tree,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        Action<IEnumerable<SigningPolicyFinding>> report,
        CancellationToken cancellationToken) =>
        // The stricter of the signing certificate's and the CA certificates' levels decides.
        CheckChainRevocationAsync(
            ordered,
            Stricter(tree.Level("SigningCertificate/NotRevoked"), tree.Level("CACertificate/NotRevoked")),
            Stricter(tree.Level("SigningCertificate/RevocationDataAvailable"), tree.Level("CACertificate/RevocationDataAvailable")),
            new ChainRevocationFindings("", "signing chain", SigningErrorReason.CertificateRevoked, SigningErrorReason.RevocationStatusUnknown)
            {
                NextUpdate = Stricter(tree.Level("SigningCertificate/CRLNextUpdatePresent"), tree.Level("CACertificate/CRLNextUpdatePresent")),
            },
            revocationChecker, httpClientProvider, logger, report, cancellationToken);

    /// <summary>
    /// Checks the revocation of <paramref name="ordered"/> (leaf first, ending at its root) now, and applies
    /// <paramref name="notRevoked"/> to a revoked certificate and <paramref name="available"/> to an unknown status.
    /// </summary>
    internal static Task CheckChainRevocationAsync(
        IReadOnlyList<X509Certificate2> ordered,
        ConstraintLevel notRevoked,
        ConstraintLevel available,
        ChainRevocationFindings findings,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        ICollection<SigningWarning>? warnings,
        CancellationToken cancellationToken) =>
        CheckChainRevocationAsync(ordered, notRevoked, available, findings, revocationChecker, httpClientProvider, logger,
            f => Apply(f, warnings, logger), cancellationToken);

    /// <summary>
    /// <see cref="CheckChainRevocationAsync(IReadOnlyList{X509Certificate2}, ConstraintLevel, ConstraintLevel, ChainRevocationFindings, IChainRevocationChecker?, IHttpClientProvider, ILogger, ICollection{SigningWarning}?, CancellationToken)"/>,
    /// handing the findings to <paramref name="report"/>.
    /// </summary>
    internal static async Task CheckChainRevocationAsync(
        IReadOnlyList<X509Certificate2> ordered,
        ConstraintLevel notRevoked,
        ConstraintLevel available,
        ChainRevocationFindings findings,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        Action<IEnumerable<SigningPolicyFinding>> report,
        CancellationToken cancellationToken)
    {
        if (notRevoked == ConstraintLevel.Ignore && available == ConstraintLevel.Ignore)
        {
            return;
        }

        var last = ordered[^1];
        if (!CertificateFacts.IsSelfSigned(last))
        {
            report([new SigningPolicyFinding(findings.Prefix + "RevocationDataAvailable", available, findings.UnknownReason,
                $"The revocation of the {findings.Chain} cannot be checked: the issuer of '{last.Subject}' was not given. " +
                "Pass the whole chain, up to the root, or the trust anchors.")]);
            return;
        }

        var checker = revocationChecker
            ?? new ChainRevocationChecker(httpClientProvider.GetClient(), logger, httpClientProvider.OutboundPolicy);
        // The status now: OCSP first and fresh CRLs, never a CRL cached before a revocation.
        var result = await checker.CheckCurrentAsync(ordered, cancellationToken).ConfigureAwait(false);
        switch (result.Status)
        {
            case ChainRevocationStatus.Revoked:
                report([new SigningPolicyFinding(findings.Prefix + "NotRevoked", notRevoked, findings.RevokedReason,
                    $"A certificate of the {findings.Chain} is revoked. " + string.Join(" ", result.Messages))]);
                break;
            case ChainRevocationStatus.Good:
                if (findings.NextUpdate != ConstraintLevel.Ignore && result.Crls.Any(crl => CrlEvaluator.ReadNextUpdate(crl) is null))
                {
                    report([new SigningPolicyFinding(findings.Prefix + "CRLNextUpdatePresent", findings.NextUpdate, findings.UnknownReason,
                        $"A CRL of the {findings.Chain} has no nextUpdate: it cannot be told whether it is current.")]);
                }

                break;
            default:
                report([new SigningPolicyFinding(findings.Prefix + "RevocationDataAvailable", available, findings.UnknownReason,
                    $"The revocation status of the {findings.Chain} could not be established. " + string.Join(" ", result.Messages))]);
                break;
        }
    }

    /// <summary>Throws, warns or logs each finding by its level.</summary>
    internal static void ApplyFindings(IEnumerable<SigningPolicyFinding> findings, ICollection<SigningWarning>? warnings, ILogger? logger) =>
        Apply(findings, warnings, logger);

    private static ConstraintLevel Stricter(ConstraintLevel a, ConstraintLevel b) => (ConstraintLevel)Math.Min((int)a, (int)b);
}

/// <summary>How the findings of a chain revocation check are named.</summary>
/// <param name="Prefix">The prefix of the constraint names ("" or "Timestamp/").</param>
/// <param name="Chain">The chain, as messages name it.</param>
/// <param name="RevokedReason">The reason of a revoked certificate.</param>
/// <param name="UnknownReason">The reason of an unknown status.</param>
internal sealed record ChainRevocationFindings(string Prefix, string Chain, SigningErrorReason RevokedReason, SigningErrorReason UnknownReason)
{
    /// <summary>The level for a CRL without nextUpdate (<c>CRLNextUpdatePresent</c>).</summary>
    public ConstraintLevel NextUpdate { get; init; } = ConstraintLevel.Ignore;
}
