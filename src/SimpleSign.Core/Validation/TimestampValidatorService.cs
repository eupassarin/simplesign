using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Default implementation of <see cref="ITimestampValidator"/>.</summary>
public sealed class TimestampValidatorService : ITimestampValidator
{
    /// <inheritdoc />
    public bool? Validate(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
        => TimestampValidator.Validate(timestampToken, signatureValueBytes, signingTime, warnings, validateChain, logger);

    /// <inheritdoc />
    public bool? Validate(
        CmsSignedData cmsData,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
        => TimestampValidator.Validate(cmsData, warnings, validateChain, logger);
}
