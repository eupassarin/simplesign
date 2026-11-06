using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Crypto;

/// <summary>The result of <see cref="TimestampToken.Verify"/> or <see cref="TimestampToken.VerifyHash"/>.</summary>
public sealed class TimestampTokenVerification
{
    /// <summary>The token's messageImprint matches the data (or hash) given.</summary>
    public bool IsImprintValid { get; init; }

    /// <summary>The TSA's signature over the TSTInfo verifies with the certificate in the token.</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>
    /// The TSA certificate has the critical, exclusive timeStamping EKU and chains to one of the
    /// trust anchors at the generation time; null when no trust anchors were given.
    /// </summary>
    public bool? IsTsaTrusted { get; init; }

    /// <summary>What the token says: generation time, TSA, hash algorithm, policy and serial; null when unreadable.</summary>
    public TimestampInfo? Info { get; init; }

    /// <summary>Why a check failed.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>The imprint and integrity are valid, and the TSA is trusted when trust anchors were given.</summary>
    public bool IsValid => IsImprintValid && IsIntegrityValid && IsTsaTrusted != false;
}

/// <summary>
/// Standalone RFC 3161 timestamps (<c>.tst</c> files): proof that some data, or its hash, existed
/// at a time attested by a TSA, without signing it.
/// </summary>
/// <example>
/// <code>
/// byte[] tst = await TimestampToken.CreateAsync(contract, new TimestampOptions(new Uri(actUrl)));
/// var check = TimestampToken.Verify(tst, contract, trustAnchors: roots);
/// Console.WriteLine($"{check.IsValid} at {check.Info?.GenerationTime}");
/// </code>
/// </example>
public static class TimestampToken
{
    /// <summary>Timestamps <paramref name="data"/>: hashes it locally and sends only the hash to the TSA.</summary>
    /// <param name="data">The data.</param>
    /// <param name="options">The TSA.</param>
    /// <param name="httpClientProvider">HTTP clients; null uses the shared default.</param>
    /// <param name="hashAlgorithm">The imprint algorithm; default SHA-256.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The DER-encoded timestamp token.</returns>
    /// <exception cref="TimestampException">The TSA failed or returned a token that does not cover the data.</exception>
    public static Task<byte[]> CreateAsync(
        ReadOnlyMemory<byte> data,
        TimestampOptions options,
        IHttpClientProvider? httpClientProvider = null,
        HashAlgorithmName? hashAlgorithm = null,
        CancellationToken cancellationToken = default)
    {
        var algorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
        return CreateForHashAsync(CryptoUtility.ComputeHash(data.Span, algorithm), algorithm, options, httpClientProvider, cancellationToken);
    }

    /// <summary>Timestamps a hash computed elsewhere.</summary>
    /// <param name="hash">The hash of the data.</param>
    /// <param name="hashAlgorithm">The algorithm of <paramref name="hash"/>.</param>
    /// <param name="options">The TSA.</param>
    /// <param name="httpClientProvider">HTTP clients; null uses the shared default.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The DER-encoded timestamp token.</returns>
    /// <exception cref="ArgumentException">The hash length does not match the algorithm.</exception>
    /// <exception cref="TimestampException">The TSA failed or returned a token that does not cover the hash.</exception>
    public static Task<byte[]> CreateForHashAsync(
        ReadOnlyMemory<byte> hash,
        HashAlgorithmName hashAlgorithm,
        TimestampOptions options,
        IHttpClientProvider? httpClientProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var client = TimestampClient.Create(options, httpClientProvider ?? new DefaultHttpClientProvider());
        return client.GetTimestampForHashAsync(hash, hashAlgorithm, cancellationToken);
    }

    /// <summary>Verifies a timestamp token against the data it should cover.</summary>
    /// <param name="token">The DER-encoded token (a <c>.tst</c> file).</param>
    /// <param name="data">The data.</param>
    /// <param name="trustAnchors">Roots the TSA must chain to; null skips the trust check.</param>
    /// <param name="extraCertificates">Intermediates to build the TSA chain with, besides those in the token.</param>
    public static TimestampTokenVerification Verify(
        byte[] token,
        ReadOnlySpan<byte> data,
        IReadOnlyList<X509Certificate2>? trustAnchors = null,
        IEnumerable<X509Certificate2>? extraCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        var imprint = TimestampValidator.ReadMessageImprint(token);
        byte[]? hash = imprint is { } i && HashAlgorithm(i.HashOid) is { } algorithm
            ? CryptoUtility.ComputeHash(data, algorithm)
            : null;
        return VerifyCore(token, imprint, hash, imprint?.HashOid, trustAnchors, extraCertificates);
    }

    /// <summary>Verifies a timestamp token against a hash of the data.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <param name="hash">The hash of the data.</param>
    /// <param name="hashAlgorithm">The algorithm of <paramref name="hash"/>; it must be the token's imprint algorithm.</param>
    /// <param name="trustAnchors">Roots the TSA must chain to; null skips the trust check.</param>
    /// <param name="extraCertificates">Intermediates to build the TSA chain with, besides those in the token.</param>
    public static TimestampTokenVerification VerifyHash(
        byte[] token,
        ReadOnlySpan<byte> hash,
        HashAlgorithmName hashAlgorithm,
        IReadOnlyList<X509Certificate2>? trustAnchors = null,
        IEnumerable<X509Certificate2>? extraCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        return VerifyCore(token, TimestampValidator.ReadMessageImprint(token), hash.ToArray(), HashOid(hashAlgorithm), trustAnchors, extraCertificates);
    }

    private static TimestampTokenVerification VerifyCore(
        byte[] token,
        (string HashOid, byte[] Hash)? imprint,
        byte[]? hash,
        string? hashOid,
        IReadOnlyList<X509Certificate2>? trustAnchors,
        IEnumerable<X509Certificate2>? extraCertificates)
    {
        var errors = new List<string>();
        if (imprint is not { } read)
        {
            return new TimestampTokenVerification { Errors = ["The file is not an RFC 3161 timestamp token."] };
        }

        bool imprintValid = hash is not null && read.HashOid == hashOid && CryptographicOperations.FixedTimeEquals(read.Hash, hash);
        if (!imprintValid)
        {
            errors.Add(hash is null
                ? $"The token's hash algorithm ({read.HashOid}) is not supported."
                : "The token does not cover this data: the messageImprint differs.");
        }

        bool integrity = TimestampValidator.VerifyTokenSignature(token, errors);
        var info = TimestampDataExtractor.Extract(token);
        bool? trusted = null;
        if (trustAnchors is not null && integrity)
        {
            trusted = IsTsaTrusted(token, info?.GenerationTime ?? DateTimeOffset.UtcNow, trustAnchors, extraCertificates, errors);
        }

        return new TimestampTokenVerification
        {
            IsImprintValid = imprintValid,
            IsIntegrityValid = integrity,
            IsTsaTrusted = trusted,
            Info = info,
            Errors = errors.AsReadOnly(),
        };
    }

    private static bool IsTsaTrusted(
        byte[] token, DateTimeOffset genTime, IReadOnlyList<X509Certificate2> trustAnchors,
        IEnumerable<X509Certificate2>? extraCertificates, List<string> errors)
    {
        var certificates = TimestampValidator.ReadTokenCertificates(token);
        if (certificates is [])
        {
            errors.Add("The token does not carry the TSA certificate.");
            return false;
        }

        if (!TimestampValidator.HasTimestampingEku(certificates[0], errors))
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = genTime.UtcDateTime;
        chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchors.ToArray());
        chain.ChainPolicy.ExtraStore.AddRange(certificates.Skip(1).Concat(extraCertificates ?? []).ToArray());
        try
        {
            if (chain.Build(certificates[0]))
            {
                return true;
            }

            errors.Add("The TSA certificate does not chain to a trusted root: "
                + string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim())));
        }
        catch (CryptographicException ex)
        {
            errors.Add($"The TSA chain could not be built: {ex.Message}");
        }

        return false;
    }

    private static HashAlgorithmName? HashAlgorithm(string oid) => oid switch
    {
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha1 => HashAlgorithmName.SHA1,
        _ => null,
    };

    private static string? HashOid(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA256" => Oids.Sha256,
        "SHA384" => Oids.Sha384,
        "SHA512" => Oids.Sha512,
        "SHA1" => Oids.Sha1,
        _ => null,
    };
}
