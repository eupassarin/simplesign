using System.Formats.Asn1;
using SimpleSign.Core.Constants;

namespace SimpleSign.CAdES;

/// <summary>Reads the certificate and revocation sets of the root CMS SignedData.</summary>
internal sealed record CadesValidationMaterial(
    IReadOnlyList<byte[]> Certificates,
    IReadOnlyList<byte[]> Crls,
    IReadOnlyList<byte[]> OcspResponses,
    bool HasRevocationSet)
{
    private const string OcspResponseOid = "1.3.6.1.5.5.7.16.2";

    internal static CadesValidationMaterial Read(byte[] cmsBytes)
    {
        var reader = new AsnReader(cmsBytes, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != Oids.SignedData)
        {
            throw new AsnContentException("CMS content is not SignedData.");
        }

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadEncodedValue(); // digestAlgorithms
        _ = signedData.ReadEncodedValue(); // encapContentInfo

        var certificates = new List<byte[]>();
        if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certificateSet = signedData.ReadSetOf(skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certificateSet.HasData)
            {
                certificates.Add(certificateSet.ReadEncodedValue().ToArray());
            }
        }

        var crls = new List<byte[]>();
        var ocspResponses = new List<byte[]>();
        bool hasRevocationSet = signedData.HasData
            && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true);
        if (hasRevocationSet)
        {
            var revocations = signedData.ReadSetOf(skipSortOrderValidation: true,
                new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (revocations.HasData)
            {
                if (revocations.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, true))
                {
                    var other = revocations.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                    if (other.ReadObjectIdentifier() == OcspResponseOid)
                    {
                        ocspResponses.Add(other.ReadEncodedValue().ToArray());
                    }
                }
                else
                {
                    crls.Add(revocations.ReadEncodedValue().ToArray());
                }
            }
        }

        return new CadesValidationMaterial(certificates, crls, ocspResponses, hasRevocationSet);
    }
}
