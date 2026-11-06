using System.Security.Cryptography;

namespace SimpleSign.Core.Crypto;

/// <summary>Helper methods for <see cref="HashAlgorithmName"/> parsing and validation.</summary>
public static class HashAlgorithmHelper
{
    /// <summary>Parses a hash algorithm name from a string. Case-insensitive. Returns null for unknown values.</summary>
    public static HashAlgorithmName? TryParse(string? name) => name?.ToUpperInvariant() switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => null
    };
}
