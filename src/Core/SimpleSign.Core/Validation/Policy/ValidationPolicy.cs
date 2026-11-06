using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>How a failed constraint of a <see cref="ValidationPolicy"/> weighs on the result.</summary>
public enum ConstraintLevel
{
    /// <summary>The failure decides the result (INDETERMINATE with the constraint's sub-indication).</summary>
    Fail,

    /// <summary>The failure is reported as a warning; the result is unchanged.</summary>
    Warn,

    /// <summary>The constraint is not evaluated.</summary>
    Ignore,
}

/// <summary>An algorithm the policy accepts, until an optional date.</summary>
/// <param name="Name">The algorithm: <c>SHA256</c>, <c>SHA3-256</c>, <c>SHA1</c>, <c>MD5</c>…</param>
/// <param name="AcceptedUntil">The last moment a signature with it is accepted without proof of an earlier existence; null for no limit.</param>
public sealed record AlgorithmConstraint(string Name, DateTimeOffset? AcceptedUntil = null);

/// <summary>The cryptographic constraints of a validation policy (algorithms and key sizes, ETSI TS 119 312 style).</summary>
public sealed record CryptographicConstraints
{
    /// <summary>The weight of a failure. Default: <see cref="ConstraintLevel.Fail"/>.</summary>
    public ConstraintLevel Level { get; init; } = ConstraintLevel.Fail;

    /// <summary>
    /// The digest algorithms accepted for the signature. An algorithm not listed, or listed with a past
    /// <see cref="AlgorithmConstraint.AcceptedUntil"/> and no proof of existence before it, fails.
    /// </summary>
    public IReadOnlyList<AlgorithmConstraint> DigestAlgorithms { get; init; } =
    [
        new("SHA1", new DateTimeOffset(2012, 8, 1, 0, 0, 0, TimeSpan.Zero)),
        new("SHA224"),
        new("SHA256"), new("SHA384"), new("SHA512"),
        new("SHA3-256"), new("SHA3-384"), new("SHA3-512"),
    ];

    /// <summary>The smallest RSA modulus, in bits, of the signing key. Zero disables the check. Default: 2048.</summary>
    public int MinimumRsaKeySize { get; init; } = 2048;

    /// <summary>The OIDs of the accepted elliptic curves; empty accepts every curve. Default: NIST P-256/384/521 and brainpool r1 256/384/512.</summary>
    public IReadOnlyList<string> EllipticCurves { get; init; } =
    [
        "1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35",
        "1.3.36.3.3.2.8.1.1.7", "1.3.36.3.3.2.8.1.1.11", "1.3.36.3.3.2.8.1.1.13",
    ];
}

/// <summary>The constraints on the signing certificate.</summary>
public sealed record SigningCertificateConstraints
{
    /// <summary>
    /// The weight of a signing certificate without the key usage digitalSignature or nonRepudiation.
    /// Default: <see cref="ConstraintLevel.Warn"/>.
    /// </summary>
    public ConstraintLevel KeyUsage { get; init; } = ConstraintLevel.Warn;
}

/// <summary>
/// The rules a validation applies beyond the format: accepted algorithms and key sizes, constraints on the
/// signing certificate. Loaded from a JSON file at run time, so the policy changes without a rebuild.
/// </summary>
public sealed record ValidationPolicy
{
    /// <summary>The policy of this library: obsolete algorithms fail, key usage is a warning.</summary>
    public static ValidationPolicy Default { get; } = new();

    /// <summary>A name for reports.</summary>
    public string Name { get; init; } = "SimpleSign default";

    /// <summary>The cryptographic constraints.</summary>
    public CryptographicConstraints Cryptographic { get; init; } = new();

    /// <summary>The constraints on the signing certificate.</summary>
    public SigningCertificateConstraints SigningCertificate { get; init; } = new();

    /// <summary>
    /// Reads a policy from JSON. Properties left out keep their default values; names are camelCase and
    /// levels are strings (<c>"fail"</c>, <c>"warn"</c>, <c>"ignore"</c>).
    /// </summary>
    /// <param name="json">The JSON document.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="InvalidDataException">The JSON is not a policy.</exception>
    public static ValidationPolicy FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
            return ValidationPolicyJson.Read(document.RootElement);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            throw new InvalidDataException($"The validation policy is not valid: {ex.Message}", ex);
        }
    }

    /// <summary>Reads a policy from a JSON file.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The policy.</returns>
    public static ValidationPolicy Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromJson(File.ReadAllText(path));
    }

    /// <summary>
    /// Reads a policy from a JSON file after checking its detached CMS signature: the signature must verify,
    /// cover the file's bytes, and be made by <paramref name="trustedSigner"/>. Protects the configuration
    /// against changes by anyone who cannot sign with that certificate.
    /// </summary>
    /// <param name="path">The JSON file.</param>
    /// <param name="signaturePath">The detached CMS signature (DER) of the file.</param>
    /// <param name="trustedSigner">The certificate the policy must be signed with.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="CryptographicException">The signature does not verify, does not cover the file, or is not by the trusted signer.</exception>
    public static ValidationPolicy LoadSigned(string path, string signaturePath, X509Certificate2 trustedSigner)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(signaturePath);
        ArgumentNullException.ThrowIfNull(trustedSigner);
        byte[] content = File.ReadAllBytes(path);
        DetachedSignature.Verify(content, File.ReadAllBytes(signaturePath), trustedSigner, "validation policy");
        return FromJson(System.Text.Encoding.UTF8.GetString(content));
    }

    /// <summary>Writes the policy as indented JSON, in the form <see cref="FromJson"/> reads.</summary>
    /// <returns>The JSON document.</returns>
    public string ToJson() => ValidationPolicyJson.Write(this);
}

/// <summary>Checks a detached CMS signature over a configuration file.</summary>
internal static class DetachedSignature
{
    internal static void Verify(byte[] content, byte[] signature, X509Certificate2 trustedSigner, string what)
    {
        CmsSignedData cms;
        try
        {
            cms = CmsParser.Parse(signature);
        }
        catch (Exception ex) when (ex is System.Formats.Asn1.AsnContentException or CryptographicException or InvalidDataException)
        {
            throw new CryptographicException($"The signature of the {what} cannot be read.", ex);
        }

        if (cms.SignerCertificate is null || !cms.SignerCertificate.RawData.AsSpan().SequenceEqual(trustedSigner.RawData))
        {
            throw new CryptographicException($"The {what} is not signed by the trusted certificate '{trustedSigner.Subject}'.");
        }

        HashAlgorithmName hash = cms.DigestAlgorithmOid switch
        {
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException($"The signature of the {what} uses an unsupported digest algorithm."),
        };

        if (cms.SignedAttrs is null)
        {
            // No signed attributes: the signature is over the content itself (RFC 5652 §5.4).
            if (cms.Signature is null || !VerifyOver(content, cms.Signature, cms.SignerCertificate, hash))
            {
                throw new CryptographicException($"The signature does not cover this {what}: it was changed after it was signed, or the signature is wrong.");
            }

            return;
        }

        if (!CryptoVerifier.VerifySignature(cms))
        {
            throw new CryptographicException($"The signature of the {what} does not verify.");
        }

        if (cms.MessageDigest is null || !CryptographicOperations.FixedTimeEquals(cms.MessageDigest, CryptoUtility.ComputeHash(content, hash)))
        {
            throw new CryptographicException($"The signature does not cover this {what}: it was changed after it was signed.");
        }
    }

    private static bool VerifyOver(byte[] content, byte[] signature, X509Certificate2 signer, HashAlgorithmName hash)
    {
        using var rsa = signer.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.VerifyData(content, signature, hash, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = signer.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyData(content, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
    }
}

/// <summary>Reads and writes <see cref="ValidationPolicy"/> JSON with the DOM, keeping the defaults of absent properties.</summary>
internal static class ValidationPolicyJson
{
    internal static ValidationPolicy Read(JsonElement root)
    {
        var policy = new ValidationPolicy();
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("The policy must be a JSON object.");
        }

        if (root.TryGetProperty("name", out var name))
        {
            policy = policy with { Name = name.GetString() ?? policy.Name };
        }

        if (root.TryGetProperty("cryptographic", out var crypto))
        {
            var c = policy.Cryptographic;
            if (crypto.TryGetProperty("level", out var level))
            {
                c = c with { Level = ReadLevel(level) };
            }

            if (crypto.TryGetProperty("digestAlgorithms", out var digests))
            {
                c = c with
                {
                    DigestAlgorithms = [.. digests.EnumerateArray().Select(d => d.ValueKind == JsonValueKind.String
                        ? new AlgorithmConstraint(d.GetString()!)
                        : new AlgorithmConstraint(
                            d.GetProperty("name").GetString()!,
                            d.TryGetProperty("acceptedUntil", out var until) && until.ValueKind != JsonValueKind.Null
                                ? until.GetDateTimeOffset() : null))],
                };
            }

            if (crypto.TryGetProperty("minimumRsaKeySize", out var rsa))
            {
                c = c with { MinimumRsaKeySize = rsa.GetInt32() };
            }

            if (crypto.TryGetProperty("ellipticCurves", out var curves))
            {
                c = c with { EllipticCurves = [.. curves.EnumerateArray().Select(e => e.GetString()!)] };
            }

            policy = policy with { Cryptographic = c };
        }

        if (root.TryGetProperty("signingCertificate", out var signing) && signing.TryGetProperty("keyUsage", out var keyUsage))
        {
            policy = policy with { SigningCertificate = new SigningCertificateConstraints { KeyUsage = ReadLevel(keyUsage) } };
        }

        return policy;
    }

    internal static string Write(ValidationPolicy policy)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("name", policy.Name);
            writer.WriteStartObject("cryptographic");
            writer.WriteString("level", LevelName(policy.Cryptographic.Level));
            writer.WriteStartArray("digestAlgorithms");
            foreach (var digest in policy.Cryptographic.DigestAlgorithms)
            {
                writer.WriteStartObject();
                writer.WriteString("name", digest.Name);
                if (digest.AcceptedUntil is { } until)
                {
                    writer.WriteString("acceptedUntil", until);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteNumber("minimumRsaKeySize", policy.Cryptographic.MinimumRsaKeySize);
            writer.WriteStartArray("ellipticCurves");
            foreach (string curve in policy.Cryptographic.EllipticCurves)
            {
                writer.WriteStringValue(curve);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteStartObject("signingCertificate");
            writer.WriteString("keyUsage", LevelName(policy.SigningCertificate.KeyUsage));
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private static ConstraintLevel ReadLevel(JsonElement element) =>
        element.GetString()?.ToUpperInvariant() switch
        {
            "FAIL" => ConstraintLevel.Fail,
            "WARN" => ConstraintLevel.Warn,
            "IGNORE" => ConstraintLevel.Ignore,
            var other => throw new FormatException($"Unknown constraint level '{other}'; use fail, warn or ignore."),
        };

    private static string LevelName(ConstraintLevel level) => level switch
    {
        ConstraintLevel.Fail => "fail",
        ConstraintLevel.Warn => "warn",
        _ => "ignore",
    };
}
