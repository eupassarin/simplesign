using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>Builds and verifies the ETSI EN 319 122-1 archiveTimestampV3 input.</summary>
internal static class CadesArchiveTimestampV3
{
    private sealed record UnsignedAttribute(string Oid, byte[] EncodedOid, IReadOnlyList<byte[]> Values);

    private sealed record Components(
        byte[] EncodedContentType,
        IReadOnlyList<byte[]> Certificates,
        IReadOnlyList<byte[]> RevocationInformation,
        IReadOnlyList<UnsignedAttribute> UnsignedAttributes,
        IReadOnlyList<byte[]> EncodedSignerCores);

    private sealed record HashIndex(string HashAlgorithmOid, IReadOnlyList<byte[]> Certificates,
        IReadOnlyList<byte[]> RevocationInformation, IReadOnlyList<byte[]> UnsignedAttributes);

    /// <summary>
    /// Creates the value of the ETSI <c>ATSHashIndexV3</c> attribute. The returned value is placed in the
    /// archive timestamp token's unsigned attributes, not in the document signer information.
    /// </summary>
    internal static byte[] CreateHashIndex(byte[] cms, HashAlgorithmName hashAlgorithm)
    {
        Components components = Parse(cms);
        return CreateHashIndex(components, hashAlgorithm, archiveTokenToExclude: null);
    }

    /// <summary>Builds the preimage whose digest is the archive timestamp message imprint.</summary>
    internal static byte[] CreateMessageImprintInput(
        byte[] cms,
        ReadOnlySpan<byte> signedData,
        HashAlgorithmName hashAlgorithm,
        byte[] hashIndex)
    {
        Components components = Parse(cms);
        byte[] signedDataHash = CmsSignatureBuilder.ComputeHash(signedData, hashAlgorithm);
        return Concatenate(
            components.EncodedContentType,
            signedDataHash,
            Concatenate([.. components.EncodedSignerCores]),
            hashIndex);
    }

    /// <summary>
    /// Adds the hash index to a RFC 3161 timestamp token. ETSI EN 319 122-1 places the index in the token's
    /// unsigned attributes; it must not be embedded in the signed document's unsigned attributes.
    /// </summary>
    internal static byte[] AddHashIndexToTimestampToken(byte[] timestampToken, byte[] hashIndex) =>
        CmsSignatureBuilder.AddUnsignedAttributes(timestampToken, [CmsAttribute.Raw(Oids.AtsHashIndexV3, hashIndex)]);

    internal static bool Validate(
        byte[] cms,
        ReadOnlySpan<byte> signedData,
        List<string> warnings)
    {
        try
        {
            Components document = Parse(cms);
            byte[]? archiveToken = document.UnsignedAttributes
                .Where(attribute => attribute.Oid == Oids.ArchiveTimeStampV3)
                .SelectMany(attribute => attribute.Values)
                .LastOrDefault();
            if (archiveToken is null)
            {
                warnings.Add("CAdES-B-LTA: archiveTimestampV3 is missing.");
                return false;
            }

            if (!TimestampValidator.VerifyTokenSignature(archiveToken))
            {
                warnings.Add("CAdES-B-LTA: archive timestamp token CMS signature is invalid.");
                return false;
            }

            Components timestamp = Parse(archiveToken);
            byte[]? hashIndex = timestamp.UnsignedAttributes
                .Where(attribute => attribute.Oid == Oids.AtsHashIndexV3)
                .SelectMany(attribute => attribute.Values)
                .SingleOrDefault();
            if (hashIndex is null)
            {
                warnings.Add("CAdES-B-LTA: archive timestamp token has no ATSHashIndexV3.");
                return false;
            }

            HashAlgorithmName hashAlgorithm = ReadHashAlgorithm(hashIndex);
            byte[] expectedIndex = CreateHashIndex(document, hashAlgorithm, archiveToken);
            if (!HashIndexesMatch(expectedIndex, hashIndex))
            {
                HashIndex expected = ReadHashIndex(expectedIndex);
                HashIndex actual = ReadHashIndex(hashIndex);
                warnings.Add("CAdES-B-LTA: ATSHashIndexV3 does not cover the required signature material " +
                    $"(expected certificates/revocation/attributes {expected.Certificates.Count}/{expected.RevocationInformation.Count}/{expected.UnsignedAttributes.Count}; " +
                    $"received {actual.Certificates.Count}/{actual.RevocationInformation.Count}/{actual.UnsignedAttributes.Count}; " +
                    $"mismatch {DescribeHashIndexMismatch(expected, actual)}).");
                return false;
            }

            byte[] input = CreateMessageImprintInput(cms, signedData, hashAlgorithm, hashIndex);
            TimestampClient.ValidateTimestampToken(archiveToken, input, hashAlgorithm);
            return true;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or TimestampException or
            InvalidOperationException or NotSupportedException)
        {
            warnings.Add($"CAdES-B-LTA: archiveTimestampV3 validation failed: {ex.Message}");
            return false;
        }
    }

    private static byte[] CreateHashIndex(
        Components components,
        HashAlgorithmName hashAlgorithm,
        byte[]? archiveTokenToExclude)
    {
        string hashOid = CmsSignatureBuilder.GetDigestOid(hashAlgorithm);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // ATSHashIndexV3 mandates an explicit AlgorithmIdentifier.
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(hashOid);
            }

            WriteHashes(writer, components.Certificates.Select(value => CmsSignatureBuilder.ComputeHash(value, hashAlgorithm)));
            WriteHashes(writer, components.RevocationInformation.Select(value => CmsSignatureBuilder.ComputeHash(value, hashAlgorithm)));
            WriteHashes(writer, components.UnsignedAttributes
                .Where(attribute => attribute.Oid != Oids.ArchiveTimeStampV3 ||
                    archiveTokenToExclude is null || !attribute.Values.Any(value =>
                        CryptographicOperations.FixedTimeEquals(value, archiveTokenToExclude)))
                .SelectMany(attribute => attribute.Values.Select(value =>
                    CmsSignatureBuilder.ComputeHash(Concatenate(attribute.EncodedOid, value), hashAlgorithm))));
        }

        return writer.Encode();
    }

    private static Components Parse(byte[] cms)
    {
        var contentReader = new AsnReader(cms, AsnEncodingRules.DER);
        var contentInfo = contentReader.ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != Oids.SignedData)
        {
            throw new AsnContentException("CMS content is not SignedData.");
        }

        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadEncodedValue();
        var encapContentInfo = signedData.ReadSequence();
        byte[] encodedContentType = encapContentInfo.ReadEncodedValue().ToArray();
        while (encapContentInfo.HasData)
        {
            _ = encapContentInfo.ReadEncodedValue();
        }

        var certificates = new List<byte[]>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certificateSet = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certificateSet.HasData)
            {
                certificates.Add(certificateSet.ReadEncodedValue().ToArray());
            }
        }

        var revocationInformation = new List<byte[]>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
        {
            var revocationSet = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (revocationSet.HasData)
            {
                revocationInformation.Add(revocationSet.ReadEncodedValue().ToArray());
            }
        }

        var signerInfos = signedData.ReadSetOf();
        if (!signerInfos.HasData)
        {
            throw new AsnContentException("CMS SignedData has no SignerInfo.");
        }

        var signerCores = new List<byte[]>();
        var unsignedAttributes = new List<UnsignedAttribute>();
        while (signerInfos.HasData)
        {
            var signerInfo = signerInfos.ReadSequence();
            var signerCore = new List<byte[]>
            {
                signerInfo.ReadEncodedValue().ToArray(),
                signerInfo.ReadEncodedValue().ToArray(),
                signerInfo.ReadEncodedValue().ToArray(),
            };
            if (signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                signerCore.Add(signerInfo.ReadEncodedValue().ToArray());
            }

            signerCore.Add(signerInfo.ReadEncodedValue().ToArray());
            signerCore.Add(signerInfo.ReadEncodedValue().ToArray());
            signerCores.Add(Concatenate([.. signerCore]));

            if (signerInfo.HasData && signerInfo.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                var attributes = signerInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                while (attributes.HasData)
                {
                    var attribute = attributes.ReadSequence();
                    byte[] encodedOid = attribute.ReadEncodedValue().ToArray();
                    string oid = new AsnReader(encodedOid, AsnEncodingRules.DER).ReadObjectIdentifier();
                    var values = attribute.ReadSetOf();
                    var encodedValues = new List<byte[]>();
                    while (values.HasData)
                    {
                        encodedValues.Add(values.ReadEncodedValue().ToArray());
                    }

                    unsignedAttributes.Add(new UnsignedAttribute(oid, encodedOid, encodedValues));
                }
            }
        }

        return new Components(encodedContentType, certificates, revocationInformation, unsignedAttributes, signerCores);
    }

    private static HashAlgorithmName ReadHashAlgorithm(byte[] hashIndex)
    {
        string oid = ReadHashIndex(hashIndex).HashAlgorithmOid;

        return oid switch
        {
            Oids.Sha256 => HashAlgorithmName.SHA256,
            Oids.Sha384 => HashAlgorithmName.SHA384,
            Oids.Sha512 => HashAlgorithmName.SHA512,
            Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
            Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
            Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
            _ => throw new AsnContentException($"Unsupported ATSHashIndexV3 digest '{oid}'."),
        };
    }

    private static bool HashIndexesMatch(byte[] expected, byte[] actual)
    {
        HashIndex expectedIndex = ReadHashIndex(expected);
        HashIndex actualIndex = ReadHashIndex(actual);
        return expectedIndex.HashAlgorithmOid == actualIndex.HashAlgorithmOid &&
            HashListsMatch(expectedIndex.Certificates, actualIndex.Certificates) &&
            HashListsMatch(expectedIndex.RevocationInformation, actualIndex.RevocationInformation) &&
            HashListsMatch(expectedIndex.UnsignedAttributes, actualIndex.UnsignedAttributes);
    }

    private static HashIndex ReadHashIndex(byte[] encoded)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var index = reader.ReadSequence();
        var algorithm = index.ReadSequence();
        string oid = algorithm.ReadObjectIdentifier();
        while (algorithm.HasData)
        {
            _ = algorithm.ReadEncodedValue();
        }

        return new HashIndex(oid, ReadHashList(index), ReadHashList(index), ReadHashList(index));
    }

    private static IReadOnlyList<byte[]> ReadHashList(AsnReader reader)
    {
        var sequence = reader.ReadSequence();
        var hashes = new List<byte[]>();
        while (sequence.HasData)
        {
            hashes.Add(sequence.ReadOctetString());
        }

        return hashes;
    }

    private static bool HashListsMatch(IReadOnlyList<byte[]> expected, IReadOnlyList<byte[]> actual)
    {
        if (expected.Count != actual.Count)
        {
            return false;
        }

        var unmatched = actual.Select(value => (byte[])value.Clone()).ToList();
        foreach (byte[] expectedValue in expected)
        {
            int match = unmatched.FindIndex(value => CryptographicOperations.FixedTimeEquals(expectedValue, value));
            if (match < 0)
            {
                return false;
            }

            unmatched.RemoveAt(match);
        }

        return true;
    }

    private static string DescribeHashIndexMismatch(HashIndex expected, HashIndex actual)
    {
        if (expected.HashAlgorithmOid != actual.HashAlgorithmOid)
        {
            return "algorithm";
        }
        if (!HashListsMatch(expected.Certificates, actual.Certificates))
        {
            return "certificates";
        }
        if (!HashListsMatch(expected.RevocationInformation, actual.RevocationInformation))
        {
            return "revocation";
        }

        return "unsigned attributes";
    }

    private static void WriteHashes(AsnWriter writer, IEnumerable<byte[]> hashes)
    {
        using (writer.PushSequence())
        {
            foreach (var hash in hashes)
            {
                writer.WriteOctetString(hash);
            }
        }
    }

    private static byte[] Concatenate(params byte[][] values)
    {
        int length = values.Sum(value => value.Length);
        var result = new byte[length];
        int offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }

        return result;
    }
}
