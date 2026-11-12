using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Signing;

/// <summary>What <see cref="SigningCertificateCheck.EvaluateAsync"/> checks a certificate with.</summary>
public sealed record SigningCertificateCheckOptions
{
    /// <summary>The certificates of the chain given with the signing certificate (intermediates, and the root when known).</summary>
    public IReadOnlyList<X509Certificate2> Chain { get; init; } = [];

    /// <summary>The signing policy the signers will apply. Default: <see cref="SigningPolicy.Default"/>.</summary>
    public SigningPolicy Policy { get; init; } = SigningPolicy.Default;

    /// <summary>
    /// Where <c>SigningCertificate/ProspectiveCertificateChain</c> looks for the root; they also complete a chain given
    /// without its root, as on the signer builders' <c>WithTrustAnchors</c>.
    /// </summary>
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchors { get; init; } = [];

    /// <summary>Checks the revocation of the chain when the policy asks for it; null for the default checker.</summary>
    public IChainRevocationChecker? RevocationChecker { get; init; }

    /// <summary>The HTTP client of the default revocation checker; null for the default one.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

    /// <summary>
    /// The digest algorithm of the signature to be made, checked against the policy's <c>Cryptographic</c>; null to
    /// leave it out.
    /// </summary>
    public HashAlgorithmName? HashAlgorithm { get; init; }

    /// <summary>
    /// The time of the validity, trust and cryptographic checks; null for now. Revocation is always checked as it is
    /// now, as the signers do.
    /// </summary>
    public DateTimeOffset? Time { get; init; }

    /// <summary>Where INFORM constraints and the revocation checker log; null for none.</summary>
    public ILogger? Logger { get; init; }
}

/// <summary>The outcome of <see cref="SigningCertificateCheck.EvaluateAsync"/>.</summary>
public sealed record SigningCertificateCheckResult
{
    /// <summary>Whether a signer under the same policy and anchors would sign with the certificate: no FAIL finding.</summary>
    public bool IsAcceptable => Reason is null;

    /// <summary>
    /// The reason of the first FAIL finding: the <see cref="SigningException.Reason"/> a signer would refuse with, or
    /// null when the certificate is acceptable.
    /// </summary>
    public SigningErrorReason? Reason { get; init; }

    /// <summary>The message of the first FAIL finding, or null when the certificate is acceptable.</summary>
    public string? Message { get; init; }

    /// <summary>
    /// Every constraint the certificate does not pass, in the order checked, with its level (FAIL, WARN, INFORM). A
    /// signer stops at the first FAIL; this lists them all.
    /// </summary>
    public IReadOnlyList<SigningPolicyFinding> Findings { get; init; } = [];

    /// <summary>The chain the checks used, signing certificate first, ending at a trust anchor when one was found.</summary>
    public IReadOnlyList<X509Certificate2> Chain { get; init; } = [];
}

/// <summary>
/// Checks a signing certificate the way the signers (PAdES, CAdES, XAdES, deferred and batch) do before they sign,
/// without signing: validity of the certificate and its chain, key usage, key and algorithms, chain to the trust
/// anchors and revocation of the chain, under a <see cref="SigningPolicy"/>. A server can tell a user whether their
/// certificate will be accepted before asking for the PIN.
/// </summary>
/// <remarks>
/// It runs the same code as the signers, so <see cref="SigningCertificateCheckResult.Reason"/> is the reason a signer
/// would refuse with. It never throws for a refused certificate; a revocation check may use the network.
/// </remarks>
public static class SigningCertificateCheck
{
    /// <summary>Checks <paramref name="certificate"/> as a signer would before signing.</summary>
    /// <param name="certificate">The signing certificate (its private key is not needed).</param>
    /// <param name="options">The chain, policy, anchors and revocation checker; null for the defaults.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The findings and, when refused, the reason.</returns>
    public static async Task<SigningCertificateCheckResult> EvaluateAsync(
        X509Certificate2 certificate, SigningCertificateCheckOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        options ??= new SigningCertificateCheckOptions();
        var logger = options.Logger ?? NullLogger.Instance;
        var time = options.Time ?? DateTimeOffset.UtcNow;
        var findings = new List<SigningPolicyFinding>();

        void Report(IEnumerable<SigningPolicyFinding> found)
        {
            foreach (var finding in found)
            {
                if (finding.Level == ConstraintLevel.Ignore)
                {
                    continue;
                }

                findings.Add(finding);
                if (finding.Level == ConstraintLevel.Inform)
                {
                    SignerAcceptance.ApplyFindings([finding], warnings: null, logger);
                }
            }
        }

        var chain = await SignerAcceptance.EvaluateSignerAsync(
            certificate,
            options.Chain,
            options.Policy,
            options.TrustAnchors,
            options.RevocationChecker,
            options.HttpClientProvider ?? DefaultHttpClientProvider.Instance,
            logger,
            Report,
            time,
            cancellationToken).ConfigureAwait(false);

        if (options.HashAlgorithm is { } hash)
        {
            Report(options.Policy.EvaluateDigest(hash, time));
        }

        var refusal = findings.FirstOrDefault(f => f.Level == ConstraintLevel.Fail);
        return new SigningCertificateCheckResult
        {
            Reason = refusal?.Reason,
            Message = refusal?.Message,
            Findings = findings,
            Chain = chain,
        };
    }
}
