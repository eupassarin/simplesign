using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Validates RFC 3161 timestamp tokens embedded in signatures.</summary>
public interface ITimestampValidator
{
    /// <summary>Reports token integrity and the optional TSA trust decision separately.</summary>
    TimestampTokenValidationResult ValidateWithTrust(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        return new TimestampTokenValidationResult
        {
            IsIntegrityValid = Validate(timestampToken, signatureValueBytes, signingTime, warnings, validateChain, logger)
        };
    }

    /// <summary>Reports CMS signature timestamp integrity and optional TSA trust separately.</summary>
    TimestampTokenValidationResult ValidateWithTrust(
        CmsSignedData cmsData,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null)
    {
        return new TimestampTokenValidationResult
        {
            IsIntegrityValid = Validate(cmsData, warnings, validateChain, logger)
        };
    }

    /// <summary>Validates an RFC 3161 timestamp token against a signature value.</summary>
    bool? Validate(
        byte[] timestampToken,
        byte[] signatureValueBytes,
        DateTimeOffset? signingTime,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null);

    /// <summary>Validates a signature timestamp from parsed CMS data.</summary>
    bool? Validate(
        CmsSignedData cmsData,
        List<string> warnings,
        TimestampValidator.CertificateChainValidatorDelegate? validateChain = null,
        ILogger? logger = null);
}
