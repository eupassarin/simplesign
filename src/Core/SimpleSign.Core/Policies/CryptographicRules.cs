using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Policies;

/// <summary>A failed cryptographic check.</summary>
/// <param name="Id">The check: <c>AcceptableEncryptionAlgo</c>, <c>MiniPublicKeySize</c>, <c>AcceptableDigestAlgo</c> or <c>AlgoExpirationDate</c>.</param>
/// <param name="Level">The level of the check.</param>
/// <param name="IsExpiry">Whether the algorithm was accepted until a date that has passed (a proof of existence before it would help).</param>
/// <param name="Message">What was found.</param>
internal sealed record CryptoFinding(string Id, ConstraintLevel Level, bool IsExpiry, string Message);

/// <summary>
/// The effective cryptographic constraints of one context of a policy: from its <c>Cryptographic</c> elements (the
/// context's own, then the enclosing ones, then the global one, element by element) or from an
/// ETSI TS 119 322 cryptographic suite.
/// </summary>
internal sealed class CryptographicRules
{
    private sealed record ListRule(ConstraintLevel Level, IReadOnlyList<PolicyAlgorithm> Algorithms);

    private sealed record Expiration(ConstraintLevel Level, ConstraintLevel? LevelAfterUpdate, DateTimeOffset? UpdateDate, IReadOnlyList<(string Name, int? Size, DateTimeOffset? Date)> Entries);

    private ListRule? _encryption;
    private ListRule? _miniKeySize;
    private ListRule? _digest;
    private Expiration? _expiration;

    /// <summary>The overall level; <see cref="ConstraintLevel.Ignore"/> turns every check off.</summary>
    public ConstraintLevel Level { get; private set; } = ConstraintLevel.Ignore;

    /// <summary>Rules that accept everything.</summary>
    public static CryptographicRules None { get; } = new();

    /// <summary>Builds the rules from <c>Cryptographic</c> elements, the most specific first; each part falls back to the next.</summary>
    public static CryptographicRules From(IEnumerable<PolicyNode?> chain)
    {
        var nodes = chain.Where(n => n is not null).Cast<PolicyNode>().ToList();
        var rules = new CryptographicRules
        {
            Level = nodes.Select(n => n.Level).FirstOrDefault(l => l is not null) ?? ConstraintLevel.Ignore,
        };

        PolicyNode? First(string name) => nodes.Select(n => n.Child(name)).FirstOrDefault(c => c is not null);

        ListRule? List(string name) => First(name) is { } node
            ? new ListRule(node.Level ?? rules.Level, node.Algorithms ?? [])
            : null;

        rules._encryption = List("AcceptableEncryptionAlgo");
        rules._miniKeySize = List("MiniPublicKeySize");
        rules._digest = List("AcceptableDigestAlgo");
        if (First("AlgoExpirationDate") is { } expiration)
        {
            string format = expiration.Attributes.TryGetValue("Format", out var f) ? (string)f : "yyyy-MM-dd";
            rules._expiration = new Expiration(
                expiration.Level ?? rules.Level,
                expiration.Attributes.TryGetValue("LevelAfterUpdate", out var after) ? (ConstraintLevel)after : null,
                expiration.Attributes.TryGetValue("UpdateDate", out var update) ? ParseDate((string)update, format) : null,
                [.. (expiration.Algorithms ?? []).Select(a => (a.Name, a.Size, a.Date is null ? (DateTimeOffset?)null : ParseDate(a.Date, format)))]);
        }

        return rules;
    }

    /// <summary>Builds the rules of an ETSI TS 119 322 suite: level FAIL, and WARN for what expires after the suite's issue date.</summary>
    public static CryptographicRules From(CryptographicSuite suite)
    {
        var digests = new List<PolicyAlgorithm>();
        var families = new List<PolicyAlgorithm>();
        var minimums = new Dictionary<string, int>(StringComparer.Ordinal);
        var expirations = new Dictionary<(string, int?), DateTimeOffset?>();

        void Expire(string name, int? size, DateTimeOffset? end)
        {
            // Several entries for the same family and size: the latest end wins, and no end beats any end.
            if (!expirations.TryGetValue((name, size), out var current) || (current is not null && (end is null || end > current)))
            {
                expirations[(name, size)] = end;
            }
        }

        foreach (var algorithm in suite.Algorithms)
        {
            string? oid = algorithm.ObjectIdentifier;
            if (oid is not null && DigestNames.TryGetValue(oid, out string? digest))
            {
                digests.Add(new PolicyAlgorithm(digest));
                foreach (var evaluation in algorithm.Evaluations)
                {
                    Expire(digest, null, evaluation.End);
                }
            }
            else if (oid is not null && SignatureFamilies.TryGetValue(oid, out string? family))
            {
                if (!families.Exists(f => f.Name == family))
                {
                    families.Add(new PolicyAlgorithm(family));
                }

                foreach (var evaluation in algorithm.Evaluations)
                {
                    int? min = evaluation.Parameters.FirstOrDefault(p => p.Name is "moduluslength" or "plength")?.Min;
                    if (min is { } size)
                    {
                        minimums[family] = minimums.TryGetValue(family, out int known) ? Math.Min(known, size) : size;
                    }

                    Expire(family, min, evaluation.End);
                }
            }
        }

        return new CryptographicRules
        {
            Level = ConstraintLevel.Fail,
            _encryption = new ListRule(ConstraintLevel.Fail, families),
            _miniKeySize = new ListRule(ConstraintLevel.Fail, [.. minimums.Select(m => new PolicyAlgorithm(m.Key, m.Value))]),
            _digest = new ListRule(ConstraintLevel.Fail, digests),
            _expiration = new Expiration(
                ConstraintLevel.Fail, ConstraintLevel.Warn, suite.PolicyIssueDate,
                [.. expirations.Select(e => (e.Key.Item1, e.Key.Item2, e.Value))]),
        };
    }

    /// <summary>Checks a digest algorithm used at <paramref name="time"/>.</summary>
    public IEnumerable<CryptoFinding> CheckDigest(string name, DateTimeOffset time)
    {
        if (Level == ConstraintLevel.Ignore)
        {
            yield break;
        }

        if (_digest is { } digest && !digest.Algorithms.Any(a => Same(a.Name, name)))
        {
            yield return new("AcceptableDigestAlgo", digest.Level, false, $"The digest algorithm {name} is not acceptable.");
            yield break;
        }

        if (_expiration is { } expiration)
        {
            var entries = expiration.Entries.Where(e => Same(e.Name, name)).ToList();
            if (entries.Count == 0)
            {
                yield return new("AlgoExpirationDate", expiration.Level, false, $"The policy gives no expiration date for the digest algorithm {name}.");
            }
            else if (!entries.Exists(e => e.Date is null) && entries.Max(e => e.Date) is { } date && time > date)
            {
                yield return Expired(expiration, $"The digest algorithm {name}", date, time);
            }
        }
    }

    /// <summary>Checks a public key algorithm (<c>RSA</c>, <c>RSASSA-PSS</c>, <c>ECDSA</c>…) and size used at <paramref name="time"/>.</summary>
    public IEnumerable<CryptoFinding> CheckKey(string algorithm, int size, DateTimeOffset time)
    {
        if (Level == ConstraintLevel.Ignore)
        {
            yield break;
        }

        if (_encryption is { } encryption && !encryption.Algorithms.Any(a => Same(a.Name, algorithm)))
        {
            yield return new("AcceptableEncryptionAlgo", encryption.Level, false, $"The algorithm {algorithm} is not acceptable.");
            yield break;
        }

        if (_miniKeySize is { } mini && mini.Algorithms.FirstOrDefault(a => Same(a.Name, algorithm))?.Size is { } minimum && size < minimum)
        {
            yield return new("MiniPublicKeySize", mini.Level, false, $"The {algorithm} key has {size} bits; the policy requires at least {minimum}.");
            yield break;
        }

        if (_expiration is { } expiration)
        {
            var entry = expiration.Entries
                .Where(e => Same(e.Name, algorithm) && (e.Size ?? 0) <= size)
                .OrderByDescending(e => e.Size ?? 0)
                .Select(e => ((string Name, int? Size, DateTimeOffset? Date)?)e)
                .FirstOrDefault();
            if (entry is null)
            {
                yield return new("AlgoExpirationDate", expiration.Level, false, $"The policy gives no expiration date for {algorithm} with {size} bits.");
            }
            else if (entry.Value.Date is { } date && time > date)
            {
                yield return Expired(expiration, $"{algorithm} with {size} bits", date, time);
            }
        }
    }

    private static CryptoFinding Expired(Expiration expiration, string what, DateTimeOffset date, DateTimeOffset time)
    {
        var level = expiration.UpdateDate is { } update && date > update && expiration.LevelAfterUpdate is { } after
            ? after
            : expiration.Level;
        return new("AlgoExpirationDate", level, true,
            $"{what} is accepted only until {date:yyyy-MM-dd}, and it is used at {time:yyyy-MM-dd}.");
    }

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    internal static DateTimeOffset ParseDate(string text, string format) =>
        DateTime.TryParseExact(text, format, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exact)
            ? new DateTimeOffset(exact, TimeSpan.Zero)
            : DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    /// <summary>The policy name of a digest algorithm OID (<c>SHA256</c>, <c>SHA3-256</c>…), or the OID itself.</summary>
    public static string DigestName(string oid) => DigestNames.TryGetValue(oid, out string? name) ? name : oid;

    /// <summary>The policy name of a hash algorithm (<c>SHA256</c>, <c>SHA3-256</c>…).</summary>
    public static string DigestName(HashAlgorithmName hash) => hash.Name ?? "";

    /// <summary>The policy name and size of a certificate's public key: <c>RSA</c> 2048, <c>ECDSA</c> 256…; null when unknown.</summary>
    public static (string Algorithm, int Size)? KeyOf(X509Certificate2 certificate, bool pss = false)
    {
        try
        {
            switch (certificate.PublicKey.Oid.Value)
            {
                case Oids.RsaEncryption:
                case Oids.RsaPss:
                    {
                        using var rsa = RSA.Create();
                        rsa.ImportRSAPublicKey(certificate.PublicKey.EncodedKeyValue.RawData, out _);
                        return (pss || certificate.PublicKey.Oid.Value == Oids.RsaPss ? "RSASSA-PSS" : "RSA", rsa.KeySize);
                    }

                case Oids.EcPublicKey:
                    {
                        using var ec = certificate.GetECDsaPublicKey();
                        return ec is null ? null : ("ECDSA", ec.KeySize);
                    }

                case "1.2.840.10040.4.1":
                    {
                        using var dsa = certificate.GetDSAPublicKey();
                        return dsa is null ? null : ("DSA", dsa.KeySize);
                    }

                case "1.3.101.112":
                    return ("EdDSA", 256);
                case "1.3.101.113":
                    return ("EdDSA", 456);
                default:
                    return null;
            }
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>The digest of a certificate's signature algorithm and whether it is RSASSA-PSS; null when unknown.</summary>
    public static (string Digest, bool Pss)? SignatureAlgorithmOf(X509Certificate2 certificate) =>
        certificate.SignatureAlgorithm.Value is { } oid && SignatureDigests.TryGetValue(oid, out string? digest)
            ? (digest, false)
            : certificate.SignatureAlgorithm.Value == Oids.RsaPss ? (PssDigest(certificate), true) : null;

    private static string PssDigest(X509Certificate2 certificate)
    {
        // RSASSA-PSS parameters: SEQUENCE { [0] hashAlgorithm AlgorithmIdentifier DEFAULT sha1, … }.
        try
        {
            var reader = new System.Formats.Asn1.AsnReader(certificate.RawData, System.Formats.Asn1.AsnEncodingRules.DER);
            var cert = reader.ReadSequence();
            cert.ReadSequence(); // tbsCertificate
            var algorithm = cert.ReadSequence();
            algorithm.ReadObjectIdentifier();
            var parameters = algorithm.ReadSequence();
            if (parameters.HasData && parameters.PeekTag().HasSameClassAndValue(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)))
            {
                var hash = parameters.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)).ReadSequence();
                return DigestName(hash.ReadObjectIdentifier());
            }
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
        }

        return "SHA1";
    }

    private static readonly Dictionary<string, string> DigestNames = new(StringComparer.Ordinal)
    {
        ["1.2.840.113549.2.5"] = "MD5",
        ["1.3.14.3.2.26"] = "SHA1",
        ["2.16.840.1.101.3.4.2.4"] = "SHA224",
        ["2.16.840.1.101.3.4.2.1"] = "SHA256",
        ["2.16.840.1.101.3.4.2.2"] = "SHA384",
        ["2.16.840.1.101.3.4.2.3"] = "SHA512",
        ["2.16.840.1.101.3.4.2.7"] = "SHA3-224",
        ["2.16.840.1.101.3.4.2.8"] = "SHA3-256",
        ["2.16.840.1.101.3.4.2.9"] = "SHA3-384",
        ["2.16.840.1.101.3.4.2.10"] = "SHA3-512",
        ["1.3.36.3.2.1"] = "RIPEMD160",
        ["1.0.10118.3.0.55"] = "WHIRLPOOL",
    };

    private static readonly Dictionary<string, string> SignatureFamilies = new(StringComparer.Ordinal)
    {
        ["1.2.840.113549.1.1.4"] = "RSA",
        ["1.2.840.113549.1.1.5"] = "RSA",
        ["1.2.840.113549.1.1.11"] = "RSA",
        ["1.2.840.113549.1.1.12"] = "RSA",
        ["1.2.840.113549.1.1.13"] = "RSA",
        ["1.2.840.113549.1.1.14"] = "RSA",
        ["2.16.840.1.101.3.4.3.13"] = "RSA",
        ["2.16.840.1.101.3.4.3.14"] = "RSA",
        ["2.16.840.1.101.3.4.3.15"] = "RSA",
        ["2.16.840.1.101.3.4.3.16"] = "RSA",
        ["1.2.840.113549.1.1.10"] = "RSASSA-PSS",
        ["1.2.840.10045.4.1"] = "ECDSA",
        ["1.2.840.10045.4.3.1"] = "ECDSA",
        ["1.2.840.10045.4.3.2"] = "ECDSA",
        ["1.2.840.10045.4.3.3"] = "ECDSA",
        ["1.2.840.10045.4.3.4"] = "ECDSA",
        ["2.16.840.1.101.3.4.3.9"] = "ECDSA",
        ["2.16.840.1.101.3.4.3.10"] = "ECDSA",
        ["2.16.840.1.101.3.4.3.11"] = "ECDSA",
        ["2.16.840.1.101.3.4.3.12"] = "ECDSA",
        ["1.2.840.10040.4.3"] = "DSA",
        ["2.16.840.1.101.3.4.3.1"] = "DSA",
        ["2.16.840.1.101.3.4.3.2"] = "DSA",
        ["1.3.101.112"] = "EdDSA",
        ["1.3.101.113"] = "EdDSA",
    };

    private static readonly Dictionary<string, string> SignatureDigests = new(StringComparer.Ordinal)
    {
        ["1.2.840.113549.1.1.4"] = "MD5",
        ["1.2.840.113549.1.1.5"] = "SHA1",
        ["1.2.840.113549.1.1.11"] = "SHA256",
        ["1.2.840.113549.1.1.12"] = "SHA384",
        ["1.2.840.113549.1.1.13"] = "SHA512",
        ["1.2.840.113549.1.1.14"] = "SHA224",
        ["2.16.840.1.101.3.4.3.13"] = "SHA3-224",
        ["2.16.840.1.101.3.4.3.14"] = "SHA3-256",
        ["2.16.840.1.101.3.4.3.15"] = "SHA3-384",
        ["2.16.840.1.101.3.4.3.16"] = "SHA3-512",
        ["1.2.840.10045.4.1"] = "SHA1",
        ["1.2.840.10045.4.3.1"] = "SHA224",
        ["1.2.840.10045.4.3.2"] = "SHA256",
        ["1.2.840.10045.4.3.3"] = "SHA384",
        ["1.2.840.10045.4.3.4"] = "SHA512",
        ["2.16.840.1.101.3.4.3.9"] = "SHA3-224",
        ["2.16.840.1.101.3.4.3.10"] = "SHA3-256",
        ["2.16.840.1.101.3.4.3.11"] = "SHA3-384",
        ["2.16.840.1.101.3.4.3.12"] = "SHA3-512",
        ["1.2.840.10040.4.3"] = "SHA1",
        ["2.16.840.1.101.3.4.3.1"] = "SHA224",
        ["2.16.840.1.101.3.4.3.2"] = "SHA256",
    };
}
