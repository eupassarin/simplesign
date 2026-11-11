using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Internal;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Applies the <c>Timestamp</c> constraints of a <see cref="SigningPolicy"/> and
/// <see cref="TimestampOptions.ExpectedTsaCertificate"/> to each timestamp obtained while signing (RFC 3161 §2.4.2):
/// the token comes from the expected TSA, its TSA certificate chains to a trust anchor, is valid at the
/// timestamp's genTime and is not revoked. The token's imprint, nonce and signature are checked by
/// <see cref="TimestampClient"/> before this runs.
/// </summary>
internal sealed class TimestampAcceptance
{
    private const string Prefix = "Timestamp/";

    private readonly SigningPolicy _policy;
    private readonly IReadOnlyList<ITrustAnchorProvider> _trustAnchors;
    private readonly IChainRevocationChecker? _revocationChecker;
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;
    private readonly ICollection<SigningWarning>? _warnings;

    /// <summary>Creates the checks.</summary>
    /// <param name="policy">The signing policy.</param>
    /// <param name="trustAnchors">The trust anchors the TSA certificate must chain to.</param>
    /// <param name="revocationChecker">The revocation checker, or null for one over <paramref name="httpClientProvider"/>.</param>
    /// <param name="httpClientProvider">The HTTP provider for the revocation check.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="warnings">Where WARN constraints go; null logs them instead.</param>
    internal TimestampAcceptance(
        SigningPolicy policy,
        IReadOnlyList<ITrustAnchorProvider> trustAnchors,
        IChainRevocationChecker? revocationChecker,
        IHttpClientProvider httpClientProvider,
        ILogger logger,
        ICollection<SigningWarning>? warnings = null)
    {
        _warnings = warnings;
        _policy = policy;
        _trustAnchors = trustAnchors;
        _revocationChecker = revocationChecker;
        _httpClientProvider = httpClientProvider;
        _logger = logger;
    }

    private ConstraintLevel Level(string constraint) => _policy.Tree.Level(Prefix + constraint);

    private bool ChecksPolicy =>
        Level("ProspectiveCertificateChain") != ConstraintLevel.Ignore
        || Level("NotExpired") != ConstraintLevel.Ignore
        || Level("NotRevoked") != ConstraintLevel.Ignore
        || Level("RevocationDataAvailable") != ConstraintLevel.Ignore;

    /// <summary>
    /// <paramref name="client"/> with these checks applied to each token it returns, or the client itself when
    /// nothing is to be checked.
    /// </summary>
    /// <param name="client">The TSA client.</param>
    /// <param name="options">The TSA settings (for the expected TSA certificate), or null.</param>
    /// <returns>The client to use.</returns>
    internal ITimestampClient Wrap(ITimestampClient client, TimestampOptions? options) =>
        ChecksPolicy || options?.ExpectedTsaCertificate is not null ? new CheckedTimestampClient(client, this, options?.ExpectedTsaCertificate) : client;

    /// <summary><paramref name="factory"/> whose clients are wrapped by <see cref="Wrap(ITimestampClient, TimestampOptions?)"/>.</summary>
    /// <param name="factory">The factory.</param>
    /// <param name="options">The TSA settings, or null.</param>
    /// <returns>The factory to use.</returns>
    internal ITimestampClientFactory Wrap(ITimestampClientFactory factory, TimestampOptions? options) =>
        ChecksPolicy || options?.ExpectedTsaCertificate is not null ? new CheckedFactory(factory, this, options) : factory;

    /// <summary>Checks one timestamp token. Throws a <see cref="SigningException"/> on a FAIL constraint.</summary>
    /// <param name="token">The DER timestamp token.</param>
    /// <param name="expectedTsa">The certificate the token must be signed with, or null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal async Task EnsureAcceptableAsync(byte[] token, X509Certificate2? expectedTsa, CancellationToken cancellationToken)
    {
        var certificates = TimestampValidator.ReadTokenCertificates(token);
        if (certificates is [])
        {
            throw new SigningException("The timestamp does not carry the TSA certificate, which cannot be checked.", SigningErrorReason.TimestampUntrusted);
        }

        var tsa = certificates[0];
        if (expectedTsa is not null && !tsa.RawData.AsSpan().SequenceEqual(expectedTsa.RawData))
        {
            throw new SigningException(
                $"The timestamp is signed by '{tsa.Subject}' ({tsa.Thumbprint}), not by the expected TSA '{expectedTsa.Subject}' ({expectedTsa.Thumbprint}).",
                SigningErrorReason.TimestampUntrusted);
        }

        var genTime = TimestampValidator.ReadGenTime(token) ?? DateTimeOffset.UtcNow;
        var findings = new List<SigningPolicyFinding>();
        if (Level("NotExpired") is var validity and not ConstraintLevel.Ignore
            && (tsa.NotBefore.ToUniversalTime() > genTime || tsa.NotAfter.ToUniversalTime() < genTime))
        {
            findings.Add(new SigningPolicyFinding(Prefix + "NotExpired", validity, SigningErrorReason.TimestampCertificateNotValid,
                $"The TSA certificate '{tsa.Subject}' is not valid at the time of the timestamp, {genTime:yyyy-MM-dd HH:mm:ss} UTC " +
                $"(valid from {tsa.NotBefore.ToUniversalTime():yyyy-MM-dd} to {tsa.NotAfter.ToUniversalTime():yyyy-MM-dd})."));
        }

        var extra = certificates.Skip(1).ToArray();
        var ordered = SignerAcceptance.OrderChain(tsa, extra);
        var trustLevel = Level("ProspectiveCertificateChain");
        if (trustLevel != ConstraintLevel.Ignore || (_trustAnchors.Count > 0 && !CertificateFacts.IsSelfSigned(ordered[^1])))
        {
            var trusted = TrustedChain.Build(tsa, extra, _trustAnchors, genTime, out string? error);
            if (trusted is not null)
            {
                ordered = trusted;
            }
            else
            {
                findings.Add(new SigningPolicyFinding(Prefix + "ProspectiveCertificateChain", trustLevel, SigningErrorReason.TimestampUntrusted,
                    "The TSA certificate is not trusted: " + error));
            }
        }

        var warnings = _warnings ?? new List<SigningWarning>();
        SignerAcceptance.ApplyFindings(findings, warnings, _logger);
        await SignerAcceptance.CheckChainRevocationAsync(
            ordered, Level("NotRevoked"), Level("RevocationDataAvailable"),
            new ChainRevocationFindings(Prefix, "TSA chain", SigningErrorReason.TimestampCertificateRevoked, SigningErrorReason.TimestampRevocationStatusUnknown),
            _revocationChecker, _httpClientProvider, _logger, warnings, cancellationToken).ConfigureAwait(false);
        if (_warnings is null)
        {
            foreach (var warning in warnings)
            {
                _logger.SigningPolicyWarning(warning.Message);
            }
        }
    }

    private sealed class CheckedTimestampClient(ITimestampClient inner, TimestampAcceptance acceptance, X509Certificate2? expectedTsa) : ITimestampClient
    {
        public async Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
        {
            byte[] token = await inner.GetTimestampAsync(dataToTimestamp, hashAlgorithm, cancellationToken).ConfigureAwait(false);
            await acceptance.EnsureAcceptableAsync(token, expectedTsa, cancellationToken).ConfigureAwait(false);
            return token;
        }
    }

    private sealed class CheckedFactory(ITimestampClientFactory inner, TimestampAcceptance acceptance, TimestampOptions? options) : ITimestampClientFactory
    {
        public ITimestampClient Create(string tsaUrl) => acceptance.Wrap(inner.Create(tsaUrl), options);
    }
}
