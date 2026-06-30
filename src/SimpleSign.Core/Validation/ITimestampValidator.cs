using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Validates RFC 3161 timestamp tokens embedded in signatures.</summary>
public interface ITimestampValidator
{
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
