using System.Security.Cryptography;

namespace SimpleSign.Core.Crypto;

/// <summary>RFC 3161 client for timestamp authority (TSA).</summary>
public interface ITimestampClient
{
    /// <summary>Requests a timestamp token for the provided bytes.</summary>
    Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default);
}
