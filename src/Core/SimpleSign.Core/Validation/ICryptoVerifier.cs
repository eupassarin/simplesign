using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation;

/// <summary>Cryptographic signature verification and signing-certificate binding validation.</summary>
public interface ICryptoVerifier
{
    /// <summary>Verifies the RSA/ECDSA signature over the signed attributes.</summary>
    bool VerifySignature(CmsSignedData cmsData, ILogger? logger = null);

    /// <summary>Validates signingCertificate (V1/V2) binding against the signer certificate.</summary>
    void ValidateSigningCertV2(CmsSignedData cmsData, List<string> errors, ILogger? logger = null);
}
