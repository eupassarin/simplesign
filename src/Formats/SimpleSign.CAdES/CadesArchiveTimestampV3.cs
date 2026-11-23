using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>
/// Builds and verifies the ETSI EN 319 122-1 archiveTimestampV3 input. An archive-time-stamp-v3 is about one SignerInfo
/// (§5.5.3): its message imprint covers that SignerInfo's fields and its ATS-hash-index-v3 lists that SignerInfo's
/// unsigned attributes, with the certificates and revocation values of the whole SignedData. Every method takes the
/// index of that SignerInfo in the SignedData.
/// </summary>
internal static class CadesArchiveTimestampV3
{
    private sealed record UnsignedAttribute(string Oid, byte[] EncodedOid, IReadOnlyList<byte[]> Values);

    /// <summary>The fields of a SignerInfo the message imprint covers, and its unsigned attributes.</summary>
    private sealed record Signer(byte[] EncodedCore, IReadOnlyList<UnsignedAttribute> UnsignedAttributes);

    private sealed record Components(
        byte[] EncodedContentType,
        IReadOnlyList<byte[]> Certificates,
        IReadOnlyList<byte[]> RevocationInformation,
        IReadOnlyList<Signer> Signers)
    {
        /// <summary>The SignerInfo at <paramref name="index"/>.</summary>
        public Signer SignerAt(int index) => index >= 0 && index < Signers.Count
            ? Signers[index]
            : throw new AsnContentException($"CMS SignedData has no SignerInfo {index} (it has {Signers.Count}).");
    }

    private sealed record HashIndex(string HashAlgorithmOid, IReadOnlyList<byte[]> Certificates,
        IReadOnlyList<byte[]> RevocationInformation, IReadOnlyList<byte[]> UnsignedAttributes);

    /// <summary>
    /// Creates the value of the ETSI <c>ATSHashIndexV3</c> attribute. The returned value is placed in the
    /// archive timestamp token's unsigned attributes, not in the document signer information.
    /// </summary>
    internal static byte[] CreateHashIndex(byte[] cms, HashAlgorithmName hashAlgorithm, int signerIndex = 0)
    {
        Components components = Parse(cms);
        return CreateHashIndex(components, components.SignerAt(signerIndex), hashAlgorithm, archiveTokenToExclude: null);
    }

    /// <summary>Builds the preimage whose digest is the archive timestamp message imprint.</summary>
    internal static byte[] CreateMessageImprintInput(
        byte[] cms,
        ReadOnlySpan<byte> signedData,
        HashAlgorithmName hashAlgorithm,
        byte[] hashIndex,
        int signerIndex = 0)
    {
        Components components = Parse(cms);
        byte[] signedDataHash = CmsSignatureBuilder.ComputeHash(signedData, hashAlgorithm);
        return Concatenate(
            components.EncodedContentType,
            signedDataHash,
            components.SignerAt(signerIndex).EncodedCore,
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
        List<string> warnings,
        int signerIndex = 0)
    {
        try
        {
            Components document = Parse(cms);
            Signer signer = document.SignerAt(signerIndex);
            byte[]? archiveToken = signer.UnsignedAttributes
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
            byte[]? hashIndex = timestamp.SignerAt(0).UnsignedAttributes
                .Where(attribute => attribute.Oid == Oids.AtsHashIndexV3)
                .SelectMany(attribute => attribute.Values)
                .SingleOrDefault();
            if (hashIndex is null)
            {
                warnings.Add("CAdES-B-LTA: archive timestamp token has no ATSHashIndexV3.");
                return false;
            }

            HashAlgorithmName hashAlgorithm = ReadHashAlgorithm(hashIndex);
            // The index lists what the signature held when the archive time-stamp was made (§5.5.3). Each value it lists
            // must still be there; a value added since (a co-signer's certificate, later validation data) is allowed and
            // is simply not covered by this time-stamp.
            byte[] presentIndex = CreateHashIndex(document, signer, hashAlgorithm, archiveToken);
            if (!IndexedValuesPresent(presentIndex, hashIndex))
            {
                HashIndex present = ReadHashIndex(presentIndex);
                HashIndex listed = ReadHashIndex(hashIndex);
                warnings.Add("CAdES-B-LTA: ATSHashIndexV3 lists signature material that is no longer present " +
                    $"(present certificates/revocation/attributes {present.Certificates.Count}/{present.RevocationInformation.Count}/{present.UnsignedAttributes.Count}; " +
                    $"listed {listed.Certificates.Count}/{listed.RevocationInformation.Count}/{listed.UnsignedAttributes.Count}; " +
                    $"missing {DescribeMissing(present, listed)}).");
                return false;
            }

            byte[] input = CreateMessageImprintInput(cms, signedData, hashAlgorithm, hashIndex, signerIndex);
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
        Signer signer,
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
            // Only the unsigned attributes of the SignerInfo being archived: a co-signer's are not part of this signature.
            WriteHashes(writer, signer.UnsignedAttributes
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

        // Co-signed SignedData keeps its SignerInfos in signing order (CmsComposer), which need not be DER order.
        var signerInfos = signedData.ReadSetOf(skipSortOrderValidation: true);
        if (!signerInfos.HasData)
        {
            throw new AsnContentException("CMS SignedData has no SignerInfo.");
        }

        var signers = new List<Signer>();
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
            var unsignedAttributes = new List<UnsignedAttribute>();
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

            signers.Add(new Signer(Concatenate([.. signerCore]), unsignedAttributes));
        }

        return new Components(encodedContentType, certificates, revocationInformation, signers);
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

    /// <summary>Whether every digest <paramref name="listed"/> holds is among the digests of what is <paramref name="present"/>.</summary>
    private static bool IndexedValuesPresent(byte[] present, byte[] listed)
    {
        HashIndex presentIndex = ReadHashIndex(present);
        HashIndex listedIndex = ReadHashIndex(listed);
        return presentIndex.HashAlgorithmOid == listedIndex.HashAlgorithmOid &&
            AllPresent(presentIndex.Certificates, listedIndex.Certificates) &&
            AllPresent(presentIndex.RevocationInformation, listedIndex.RevocationInformation) &&
            AllPresent(presentIndex.UnsignedAttributes, listedIndex.UnsignedAttributes);
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

    private static bool AllPresent(IReadOnlyList<byte[]> present, IReadOnlyList<byte[]> listed) =>
        listed.All(digest => present.Any(value => CryptographicOperations.FixedTimeEquals(digest, value)));

    private static string DescribeMissing(HashIndex present, HashIndex listed)
    {
        if (present.HashAlgorithmOid != listed.HashAlgorithmOid)
        {
            return "algorithm";
        }
        if (!AllPresent(present.Certificates, listed.Certificates))
        {
            return "certificates";
        }
        if (!AllPresent(present.RevocationInformation, listed.RevocationInformation))
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
