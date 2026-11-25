using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Signing;

/// <summary>
/// The steps every baseline signer (PAdES, CAdES, XAdES) takes the same way: checking the certificate,
/// calling an external signer, choosing the timestamp client, and reporting the level that was achieved.
/// </summary>
internal static class BaselineSigning
{
    private const string DowngradedMessage =
        "The requested baseline level could not be achieved; the artifact was downgraded.";

    /// <summary>The baseline level an artifact has, given what was found in it.</summary>
    internal static AdesBaselineLevel AchievedLevel(bool hasSignatureTimestamp, bool hasLtvMaterial, bool hasArchiveTimestamp)
    {
        if (!hasSignatureTimestamp)
        {
            return AdesBaselineLevel.Basic;
        }

        if (!hasLtvMaterial)
        {
            return AdesBaselineLevel.Timestamped;
        }

        return hasArchiveTimestamp ? AdesBaselineLevel.Archive : AdesBaselineLevel.LongTerm;
    }

    /// <summary>Records why a level was not reached, followed by the <see cref="SigningWarningCode.LevelDowngraded"/> warning.</summary>
    internal static void AddDowngradeWarnings(List<SigningWarning> warnings, SigningWarningCode code, string message)
    {
        warnings.Add(new SigningWarning(code, message));
        warnings.Add(new SigningWarning(SigningWarningCode.LevelDowngraded, DowngradedMessage));
    }

    /// <summary>
    /// Throws when the profile demands the requested level; otherwise records the downgrade.
    /// </summary>
    internal static void RequireOrDowngrade(
        AdesBaselineProfile profile,
        List<SigningWarning> warnings,
        SigningWarningCode code,
        string message)
    {
        if (profile.FailureBehavior == SigningLevelFailureBehavior.Throw)
        {
            throw new SigningException(message, SigningErrorReason.LevelNotAchievable);
        }

        AddDowngradeWarnings(warnings, code, message);
    }

    /// <summary>
    /// Refuses a profile that may return a lower level on an API that returns only the artifact,
    /// where the caller could not see the downgrade.
    /// </summary>
    internal static void EnsureStrictProfile(AdesBaselineProfile profile)
    {
        if (profile.FailureBehavior == SigningLevelFailureBehavior.ReturnLowerLevel)
        {
            throw new SigningException(
                "The configured baseline profile allows best-effort level downgrades. " +
                "Use SignWithDetailsAsync() so the achieved level and warnings are reported.",
                SigningErrorReason.DowngradeRequiresDetailedResult);
        }
    }

    /// <summary>Throws when the certificate is expired or not yet valid at this moment.</summary>
    internal static void EnsureCertificateValidNow(X509Certificate2 certificate)
    {
        var signingTime = DateTimeOffset.UtcNow;
        if (certificate.NotBefore > signingTime || certificate.NotAfter < signingTime)
        {
            throw new SigningException(
                $"Certificate '{certificate.Subject}' is not valid at {signingTime:yyyy-MM-dd HH:mm:ss} UTC.",
                certificate.NotAfter < signingTime
                    ? SigningErrorReason.CertificateExpired
                    : SigningErrorReason.CertificateNotCurrentlyValid);
        }
    }

    /// <summary>
    /// Whether <paramref name="exception"/> is a refusal of a timestamp by the signing policy or the expected TSA:
    /// <see cref="SigningErrorReason.TimestampUntrusted"/> or a refusal of its TSA certificate (<see cref="IsTimestampCertificateRefusal"/>).
    /// </summary>
    internal static bool IsTimestampRefusal(Exception exception) =>
        exception is SigningException { Reason: SigningErrorReason.TimestampUntrusted } || IsTimestampCertificateRefusal(exception);

    /// <summary>
    /// Whether <paramref name="exception"/> refuses the TSA certificate of a timestamp under the signing policy's
    /// <c>Timestamp/NotExpired</c>, <c>Timestamp/NotRevoked</c> or <c>Timestamp/RevocationDataAvailable</c>.
    /// </summary>
    internal static bool IsTimestampCertificateRefusal(Exception exception) =>
        exception is SigningException
        {
            Reason: SigningErrorReason.TimestampCertificateNotValid or SigningErrorReason.TimestampCertificateRevoked
                or SigningErrorReason.TimestampRevocationStatusUnknown,
        };

    /// <summary>
    /// Whether a refused signature or archive timestamp ends the signing operation, thrown as it is (its reason kept).
    /// A TSA other than the expected one, or one that does not chain to the anchors the policy requires
    /// (<see cref="SigningErrorReason.TimestampUntrusted"/>), always does: the caller chose that TSA. A refused TSA
    /// certificate does when the profile asks for its level (<see cref="SigningLevelFailureBehavior.Throw"/>);
    /// with <see cref="SigningLevelFailureBehavior.ReturnLowerLevel"/> the timestamp is left out and the level is lower.
    /// </summary>
    internal static bool IsFatalTimestampRefusal(Exception exception, AdesBaselineProfile profile) =>
        exception is SigningException { Reason: SigningErrorReason.TimestampUntrusted }
        || (IsTimestampCertificateRefusal(exception) && profile.FailureBehavior == SigningLevelFailureBehavior.Throw);

    /// <summary>
    /// Records a signature or archive timestamp that was left out, followed by the
    /// <see cref="SigningWarningCode.LevelDowngraded"/> warning. A TSA certificate refused by the policy gives
    /// <see cref="SigningWarningCode.SignatureTimestampRefused"/> or <see cref="SigningWarningCode.ArchiveTimestampRefused"/>;
    /// anything else <paramref name="unavailableCode"/>. The warning carries the reason of the failure.
    /// </summary>
    /// <param name="warnings">Where the warnings go.</param>
    /// <param name="unavailableCode"><see cref="SigningWarningCode.SignatureTimestampUnavailable"/> or <see cref="SigningWarningCode.ArchiveTimestampUnavailable"/>.</param>
    /// <param name="message">The message of the first warning.</param>
    /// <param name="exception">What the timestamp step threw.</param>
    internal static void AddTimestampDowngradeWarnings(
        List<SigningWarning> warnings, SigningWarningCode unavailableCode, string message, Exception exception)
    {
        SigningWarningCode code = unavailableCode;
        if (IsTimestampCertificateRefusal(exception))
        {
            code = unavailableCode == SigningWarningCode.ArchiveTimestampUnavailable
                ? SigningWarningCode.ArchiveTimestampRefused
                : SigningWarningCode.SignatureTimestampRefused;
        }

        SigningErrorReason reason = exception is SigningException { Reason: var own } && own != SigningErrorReason.Unspecified
            ? own
            : TimestampException.ReasonOf(exception);
        warnings.Add(new SigningWarning(code, message, reason));
        warnings.Add(new SigningWarning(SigningWarningCode.LevelDowngraded, DowngradedMessage));
    }

    /// <summary>
    /// The client for a TSA: a dedicated one when the options carry credentials, a client certificate
    /// or TCP transport; otherwise the injected factory, or a plain HTTP client.
    /// </summary>
    internal static ITimestampClient CreateTimestampClient(
        TimestampOptions options,
        ITimestampClientFactory? factory,
        IHttpClientProvider httpClientProvider,
        ILogger logger) =>
        options.NeedsDedicatedClient
            ? TimestampClient.Create(options, options.HttpClientProvider ?? httpClientProvider, logger)
            : CreateTimestampClient(options.Endpoint.ToString(), options.HttpClientProvider, factory, httpClientProvider, logger);

    /// <summary>The client for a TSA endpoint: the injected factory when there is one, else a plain HTTP client.</summary>
    internal static ITimestampClient CreateTimestampClient(
        string endpoint,
        IHttpClientProvider? scopedProvider,
        ITimestampClientFactory? factory,
        IHttpClientProvider httpClientProvider,
        ILogger logger) =>
        factory is not null
            ? factory.Create(endpoint)
            : NewTimestampClient(scopedProvider ?? httpClientProvider, endpoint, logger);

    private static TimestampClient NewTimestampClient(IHttpClientProvider provider, string endpoint, ILogger logger) =>
        new(provider.GetClient(), endpoint, logger) { OutboundPolicy = provider.OutboundPolicy ?? OutboundHttpPolicy.Default };

    /// <summary>
    /// Asks the external signer for the signature and checks it with the certificate's public key,
    /// so a wrong key or algorithm fails here and not at validation.
    /// </summary>
    internal static async Task<ReadOnlyMemory<byte>> SignExternallyAsync(
        IExternalSigner signer,
        ExternalSigningRequest request,
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> signature;
        try
        {
            signature = await signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SigningException("External signer failed to produce a signature.",
                SigningErrorReason.ExternalSignerFailure, ex);
        }

        if (signature.Length == 0)
        {
            throw new SigningException(
                "External signer returned an empty signature.",
                SigningErrorReason.ExternalSignerReturnedEmpty);
        }

        if (!CmsSignatureBuilder.VerifyExternalSignature(
                request.DataToSign.Span, signature.Span, certificate, request.HashAlgorithm, request.SignatureAlgorithmOid))
        {
            throw new SigningException(
                "External signer returned a signature that does not verify with the configured certificate.",
                SigningErrorReason.AlgorithmIncompatible);
        }

        return signature;
    }
}
