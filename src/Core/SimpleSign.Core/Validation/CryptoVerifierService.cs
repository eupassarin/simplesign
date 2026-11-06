using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Default implementation of <see cref="ICryptoVerifier"/>.</summary>
public sealed class CryptoVerifierService : ICryptoVerifier
{
    /// <inheritdoc />
    public bool VerifySignature(CmsSignedData cmsData, ILogger? logger = null)
        => CryptoVerifier.VerifySignature(cmsData, logger);

    /// <inheritdoc />
    public void ValidateSigningCertV2(CmsSignedData cmsData, List<string> errors, ILogger? logger = null)
        => CryptoVerifier.ValidateSigningCertV2(cmsData, errors, logger);
}
