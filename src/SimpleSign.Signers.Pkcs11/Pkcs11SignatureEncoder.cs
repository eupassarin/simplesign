using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Pkcs11.Interop;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>The key algorithm of a token private key.</summary>
internal enum Pkcs11KeyAlgorithm
{
    /// <summary>RSA (CKK_RSA).</summary>
    Rsa,

    /// <summary>Elliptic curve (CKK_EC).</summary>
    Ec,
}

/// <summary>What to send to the token for one signing request.</summary>
/// <param name="Mechanism">The CKM_* mechanism.</param>
/// <param name="MechanismParameter">The encoded mechanism parameter, or <see langword="null"/>.</param>
/// <param name="Data">The bytes passed to C_Sign (a DigestInfo or a bare hash).</param>
/// <param name="IsEcdsa">Whether the token returns raw ECDSA <c>r||s</c> that must be DER-encoded.</param>
internal sealed record Pkcs11SigningPlan(ulong Mechanism, byte[]? MechanismParameter, byte[] Data, bool IsEcdsa);

/// <summary>
/// Maps an <see cref="ExternalSigningRequest"/> to a PKCS#11 operation. The hash is always
/// computed here with the BCL, so the token only performs the raw key operation through the
/// mechanisms every token supports: CKM_RSA_PKCS, CKM_RSA_PKCS_PSS and CKM_ECDSA.
/// </summary>
internal static class Pkcs11SignatureEncoder
{
    private const string EcPublicKey = "1.2.840.10045.2.1";

    /// <summary>Builds the PKCS#11 operation for a request.</summary>
    /// <exception cref="NotSupportedException">The algorithm is not supported or does not match the key.</exception>
    internal static Pkcs11SigningPlan Prepare(ExternalSigningRequest request, Pkcs11KeyAlgorithm keyAlgorithm, CkLayout layout)
    {
        ArgumentNullException.ThrowIfNull(request);
        byte[] hash = CmsSignatureBuilder.ComputeHash(request.DataToSign.Span, request.HashAlgorithm);
        string oid = request.SignatureAlgorithmOid;

        if (IsRsaPkcs1(oid))
        {
            RequireKey(keyAlgorithm, Pkcs11KeyAlgorithm.Rsa, oid);
            return new Pkcs11SigningPlan(CkConstants.CkmRsaPkcs, null, BuildDigestInfo(request.HashAlgorithm, hash), IsEcdsa: false);
        }

        if (oid == Oids.RsaPss)
        {
            RequireKey(keyAlgorithm, Pkcs11KeyAlgorithm.Rsa, oid);
            var pss = request.RsaPssParameters;
            var hashAlgorithm = pss?.HashAlgorithm ?? request.HashAlgorithm;
            var mgfHash = pss?.MaskGenerationHashAlgorithm ?? hashAlgorithm;
            int saltLength = pss?.SaltLength ?? hash.Length;

            byte[] parameter = EncodePssParameters(layout, HashMechanism(hashAlgorithm), Mgf(mgfHash), (ulong)saltLength);
            return new Pkcs11SigningPlan(CkConstants.CkmRsaPkcsPss, parameter, hash, IsEcdsa: false);
        }

        if (IsEcdsa(oid))
        {
            RequireKey(keyAlgorithm, Pkcs11KeyAlgorithm.Ec, oid);
            return new Pkcs11SigningPlan(CkConstants.CkmEcdsa, null, hash, IsEcdsa: true);
        }

        throw new NotSupportedException($"Signature algorithm '{oid}' is not supported by the PKCS#11 signer.");
    }

    /// <summary>Encodes a DigestInfo (RFC 8017 §9.2): SEQUENCE { AlgorithmIdentifier, OCTET STRING }.</summary>
    internal static byte[] BuildDigestInfo(HashAlgorithmName hashAlgorithm, byte[] hash)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(DigestOid(hashAlgorithm));
                writer.WriteNull();
            }

            writer.WriteOctetString(hash);
        }

        return writer.Encode();
    }

    /// <summary>Converts a raw PKCS#11 ECDSA signature (<c>r||s</c>) to DER <c>SEQUENCE { r, s }</c> (RFC 3279).</summary>
    /// <exception cref="CryptographicException">The raw signature has an odd or zero length.</exception>
    internal static byte[] EcdsaRawToDer(byte[] raw)
    {
        if (raw.Length == 0 || raw.Length % 2 != 0)
        {
            throw new CryptographicException($"The token returned a malformed ECDSA signature ({raw.Length} bytes).");
        }

        int half = raw.Length / 2;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(TrimLeadingZeros(raw.AsSpan(0, half)));
            writer.WriteIntegerUnsigned(TrimLeadingZeros(raw.AsSpan(half, half)));
        }

        return writer.Encode();
    }

    /// <summary>Encodes CK_RSA_PKCS_PSS_PARAMS for a layout.</summary>
    internal static byte[] EncodePssParameters(CkLayout layout, ulong hashMechanism, ulong mgf, ulong saltLength)
    {
        byte[] encoded = new byte[layout.PssParamsSize];
        WriteULong(encoded, 0, layout.ULongSize, hashMechanism);
        WriteULong(encoded, layout.ULongSize, layout.ULongSize, mgf);
        WriteULong(encoded, 2 * layout.ULongSize, layout.ULongSize, saltLength);
        return encoded;
    }

    private static bool IsRsaPkcs1(string oid) => oid is Oids.RsaEncryption or Oids.RsaSha1
        or Oids.RsaSha256 or Oids.RsaSha384 or Oids.RsaSha512
        or Oids.RsaSha3_256 or Oids.RsaSha3_384 or Oids.RsaSha3_512;

    private static bool IsEcdsa(string oid) => oid is EcPublicKey
        or Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512
        or Oids.EcdsaSha3_256 or Oids.EcdsaSha3_384 or Oids.EcdsaSha3_512;

    private static void RequireKey(Pkcs11KeyAlgorithm actual, Pkcs11KeyAlgorithm expected, string oid)
    {
        if (actual != expected)
        {
            throw new NotSupportedException(
                $"Signature algorithm '{oid}' needs an {expected} key, but the token key is {actual}.");
        }
    }

    private static string DigestOid(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA1" => Oids.Sha1,
        "SHA256" => Oids.Sha256,
        "SHA384" => Oids.Sha384,
        "SHA512" => Oids.Sha512,
        "SHA3-256" => Oids.Sha3_256,
        "SHA3-384" => Oids.Sha3_384,
        "SHA3-512" => Oids.Sha3_512,
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported by the PKCS#11 signer."),
    };

    private static ulong HashMechanism(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA1" => CkConstants.CkmSha1,
        "SHA256" => CkConstants.CkmSha256,
        "SHA384" => CkConstants.CkmSha384,
        "SHA512" => CkConstants.CkmSha512,
        _ => throw new NotSupportedException($"RSASSA-PSS with '{hashAlgorithm.Name}' is not supported by the PKCS#11 signer."),
    };

    private static ulong Mgf(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA1" => CkConstants.CkgMgf1Sha1,
        "SHA256" => CkConstants.CkgMgf1Sha256,
        "SHA384" => CkConstants.CkgMgf1Sha384,
        "SHA512" => CkConstants.CkgMgf1Sha512,
        _ => throw new NotSupportedException($"MGF1 with '{hashAlgorithm.Name}' is not supported by the PKCS#11 signer."),
    };

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }

    private static void WriteULong(byte[] buffer, int offset, int size, ulong value)
    {
        for (int i = 0; i < size; i++)
        {
            buffer[offset + i] = (byte)(value >> (8 * i));
        }
    }
}
