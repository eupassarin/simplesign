using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Default implementation of <see cref="ITimestampValidator"/>.</summary>
public sealed class TimestampValidatorService : ITimestampValidator
{
    /// <inheritdoc />
    public TimestampTokenValidationResult ValidateWithTrust(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
        => TimestampValidator.ValidateWithTrust(timestampToken, signatureValueBytes,
            signingTime, warnings, validateChain, logger);

    /// <inheritdoc />
    public TimestampTokenValidationResult ValidateWithTrust(
        CmsSignedData cmsData,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        if (cmsData.SignatureTimestampToken is null || cmsData.Signature is null)
        {
            return new TimestampTokenValidationResult();
        }

        return TimestampValidator.ValidateWithTrust(cmsData.SignatureTimestampToken,
            cmsData.Signature, cmsData.SigningTime, warnings, validateChain, logger);
    }

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
