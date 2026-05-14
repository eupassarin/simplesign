using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Shared cryptographic utility methods used across signature formats.
/// </summary>
internal static class CryptoUtility
{
    /// <summary>
    /// Detects the appropriate RSA signature padding based on the certificate's signature algorithm.
    /// </summary>
    internal static RSASignaturePadding DetectRsaPadding(X509Certificate2 cert)
    {
        return cert.SignatureAlgorithm.Value == Oids.RsaPss
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;
    }

    /// <summary>
    /// Computes a hash of the given data using the specified algorithm.
    /// </summary>
    internal static byte[] ComputeHash(ReadOnlySpan<byte> data, HashAlgorithmName algorithm) => algorithm switch
    {
        _ when algorithm == HashAlgorithmName.SHA256 => SHA256.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA384 => SHA384.HashData(data),
        _ when algorithm == HashAlgorithmName.SHA512 => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name}' is not supported.")
    };
}
