using SimpleSign.Core.Crypto;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>Standalone timestamps (<c>.tst</c>) from ICP-Brasil accredited ACTs.</summary>
public static class IcpBrasilTimestamp
{
    /// <summary>
    /// Verifies a timestamp token against <paramref name="data"/> and requires the ACT to chain to
    /// a bundled ICP-Brasil AC Raiz (with the bundled intermediates).
    /// </summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <param name="data">The data the token should cover.</param>
    public static TimestampTokenVerification Verify(byte[] token, ReadOnlySpan<byte> data) =>
        TimestampToken.Verify(token, data, IcpBrasilChainValidator.LoadBundledAcRaizCerts(), IcpBrasilChainValidator.LoadBundledIntermediateCerts());

    /// <summary>Verifies a timestamp token against a hash of the data, requiring an ICP-Brasil ACT.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <param name="hash">The hash of the data.</param>
    /// <param name="hashAlgorithm">The algorithm of <paramref name="hash"/>.</param>
    public static TimestampTokenVerification VerifyHash(
        byte[] token, ReadOnlySpan<byte> hash, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) =>
        TimestampToken.VerifyHash(token, hash, hashAlgorithm, IcpBrasilChainValidator.LoadBundledAcRaizCerts(), IcpBrasilChainValidator.LoadBundledIntermediateCerts());
}
