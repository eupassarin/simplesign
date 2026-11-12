using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Trust at a past time, from <see cref="ValidationOptions.TimedTrustAnchors"/> (trusted lists with a service history):
/// used only when today's anchors do not trust a certificate.
/// </summary>
internal static class TimedTrust
{
    /// <summary>Whether timed anchors are configured.</summary>
    public static bool IsConfigured(ValidationOptions options) => options.TimedTrustAnchors is { Count: > 0 };

    /// <summary>The anchors of every timed provider at <paramref name="at"/>.</summary>
    public static IReadOnlyList<X509Certificate2> AnchorsAt(ValidationOptions options, DateTimeOffset at) =>
        options.TimedTrustAnchors is { Count: > 0 } providers ? [.. providers.SelectMany(p => p.GetTrustAnchors(at))] : [];

    /// <summary>
    /// The time-stamp result with its TSA trusted when today's anchors do not trust it but the anchors of the token's
    /// genTime do (the TSA's service was granted when it issued the token).
    /// </summary>
    public static TimestampTokenValidationResult TrustTsaAtGenTime(
        TimestampTokenValidationResult result, byte[]? token, ValidationOptions options, List<string> warnings)
    {
        if (result is not { IsIntegrityValid: true, IsTsaTrusted: not true, GenTime: { } genTime } || token is null || !IsConfigured(options)
            || TimestampTrust.ChainsTo(token, AnchorsAt(options, genTime)) != true)
        {
            return result;
        }

        warnings.Add(string.Create(CultureInfo.InvariantCulture,
            $"The time-stamp's TSA is trusted by the anchors of its time ({genTime:u}), not by today's (trusted-list service history)."));
        return new TimestampTokenValidationResult { IsIntegrityValid = true, IsTsaTrusted = true, GenTime = genTime };
    }

    /// <summary>
    /// Whether the TSA of <paramref name="token"/> chains to <paramref name="anchors"/> (today's) or, failing that, to the
    /// timed anchors of the token's genTime. Null when nothing can judge it.
    /// </summary>
    public static bool? TokenChains(byte[] token, IEnumerable<X509Certificate2>? anchors, ValidationOptions options)
    {
        bool? today = TimestampTrust.ChainsTo(token, anchors);
        if (today == true || !IsConfigured(options) || TstInfoReader.FromToken(token).GenTime is not { } genTime)
        {
            return today;
        }

        return TimestampTrust.ChainsTo(token, AnchorsAt(options, genTime)) == true ? true : today;
    }

    /// <summary>
    /// Past signature validation (EN 319 102-1 §5.6): whether a later time-stamp (an archive or document time-stamp over
    /// the signature) that is valid and trusted proves that <paramref name="token"/> existed while its TSA's certificate
    /// was valid. The later token's genTime is that proof; the earlier TSA's chain is built at it, with today's anchors
    /// and the timed anchors of that time. On success a warning says so.
    /// </summary>
    /// <param name="genTime">The earlier token's genTime (its integrity already checked).</param>
    /// <param name="token">The earlier token, whose TSA is not trusted today.</param>
    /// <param name="laterToken">The later time-stamp, already checked to cover the earlier one.</param>
    /// <param name="anchors">Today's anchors.</param>
    /// <param name="options">The validation options (timed anchors).</param>
    /// <param name="warnings">Where the warning goes.</param>
    public static bool TrustTsaAtLaterProof(
        DateTimeOffset? genTime, byte[]? token, byte[] laterToken, IEnumerable<X509Certificate2>? anchors, ValidationOptions options, List<string> warnings)
    {
        if (genTime is not { } earlier || token is null || TstInfoReader.FromToken(laterToken).GenTime is not { } proof || proof < earlier
            || TokenChains(laterToken, anchors, options) != true)
        {
            return false;
        }

        IEnumerable<X509Certificate2> anchorsThen = [.. anchors ?? [], .. AnchorsAt(options, proof)];
        if (TimestampTrust.ChainsTo(token, anchorsThen, proof) != true)
        {
            return false;
        }

        warnings.Add(string.Create(CultureInfo.InvariantCulture,
            $"The signature time-stamp's TSA is not trusted today; a later time-stamp ({proof:u}) proves the token existed while its certificate was valid (past signature validation)."));
        return true;
    }

    /// <summary>The warning when the signer's chain reaches the anchors of its proof of existence only.</summary>
    public static string SignerWarning(DateTimeOffset at) => string.Create(CultureInfo.InvariantCulture,
        $"The certificate chain reaches the trust anchors of the signature's proof of existence ({at:u}), not today's (trusted-list service history).");
}
