using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;

namespace SimpleSign.CAdES;

/// <summary>
/// Creates standalone CAdES digital signatures (ETSI EN 319 122) as detached
/// CMS/PKCS#7 SignedData — no PDF wrapper.
/// </summary>
public static class CadesSigner
{
    /// <summary>
    /// Creates a new fluent builder for signing data with CAdES.
    /// </summary>
    /// <param name="data">The original document bytes to sign. The array is copied; the caller may mutate it afterwards.</param>
    /// <returns>A <see cref="CadesSignerBuilder"/> configured with defaults.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
    public static CadesSignerBuilder Document(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new CadesSignerBuilder(data, logger: null);
    }

    /// <summary>
    /// Co-signature: adds a new signer over the same content to <paramref name="existingSignature"/>
    /// (a .p7s or .p7m). Configure the certificate, policy and level on the returned builder as
    /// for a new signature; the result contains every previous signer plus the new one.
    /// </summary>
    /// <param name="existingSignature">The existing CMS signature.</param>
    /// <param name="data">The signed content; required for a detached .p7s, ignored for an attached .p7m.</param>
    /// <exception cref="ArgumentException">Detached signature without <paramref name="data"/>, or data that the existing signature does not cover.</exception>
    /// <example>
    /// <code>
    /// byte[] both = await CadesSigner.CoSign(firstP7s, document).WithCertificate(second).SignAsync();
    /// </code>
    /// </example>
    public static CadesSignerBuilder CoSign(byte[] existingSignature, byte[]? data = null)
    {
        ArgumentNullException.ThrowIfNull(existingSignature);
        var existing = CmsParser.ParseAll(existingSignature);
        byte[] content = existing.EncapsulatedContent ?? data
            ?? throw new ArgumentException("The signature is detached: pass the signed data.", nameof(data));
        if (existing.EncapsulatedContent is null && existing.Signers is [{ MessageDigest: { } digest } first, ..]
            && !CryptographicOperations.FixedTimeEquals(digest, HashFor(first.DigestAlgorithmOid, content)))
        {
            throw new ArgumentException("The data is not the content signed by the existing signature.", nameof(data));
        }

        return new CadesSignerBuilder(content, logger: null).ForCoSignature(existingSignature, existing.EncapsulatedContent is not null);
    }

    /// <summary>
    /// Countersignature: signs the signature value of signer <paramref name="signerIndex"/> of
    /// <paramref name="existingSignature"/> (RFC 5652 §11.4) and stores it as that signer's
    /// id-countersignature attribute. Configure the certificate on the returned builder.
    /// </summary>
    /// <param name="existingSignature">The existing CMS signature.</param>
    /// <param name="signerIndex">The signer to countersign (order of <see cref="CmsParser.ParseAll"/>).</param>
    /// <exception cref="ArgumentOutOfRangeException">There is no such signer.</exception>
    public static CadesSignerBuilder CounterSign(byte[] existingSignature, int signerIndex = 0)
    {
        ArgumentNullException.ThrowIfNull(existingSignature);
        byte[] signatureValue = CmsComposer.SignatureValue(existingSignature, signerIndex);
        return new CadesSignerBuilder(signatureValue, logger: null).ForCounterSignature(existingSignature, signerIndex);
    }

    /// <summary>The content of an attached CAdES signature (.p7m).</summary>
    /// <param name="attachedSignature">The CMS signature with encapsulated content.</param>
    /// <exception cref="ArgumentException">The signature is detached (no encapsulated content).</exception>
    public static byte[] ExtractContent(byte[] attachedSignature)
    {
        ArgumentNullException.ThrowIfNull(attachedSignature);
        return CmsParser.ParseAll(attachedSignature).EncapsulatedContent
            ?? throw new ArgumentException("The signature is detached: it does not contain the signed content.", nameof(attachedSignature));
    }

    internal static byte[] HashFor(string digestOid, byte[] data) => digestOid switch
    {
        Oids.Sha256 => SHA256.HashData(data),
        Oids.Sha384 => SHA384.HashData(data),
        Oids.Sha512 => SHA512.HashData(data),
        Oids.Sha3_256 => SHA3_256.HashData(data),
        Oids.Sha3_384 => SHA3_384.HashData(data),
        Oids.Sha3_512 => SHA3_512.HashData(data),
#pragma warning disable CA5350 // legacy SHA-1 signatures must still be matched
        Oids.Sha1 => SHA1.HashData(data),
#pragma warning restore CA5350
        _ => throw new NotSupportedException($"Digest algorithm {digestOid} is not supported."),
    };
}
