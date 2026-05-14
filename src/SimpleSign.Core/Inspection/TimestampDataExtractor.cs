using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using SimpleSign.Core.Crypto;

namespace SimpleSign.Core.Inspection;

/// <summary>
/// Extracts structured timestamp data from RFC 3161 timestamp tokens.
/// No validation is performed — this is purely a data extraction utility.
/// </summary>
internal static class TimestampDataExtractor
{
    /// <summary>
    /// Extracts <see cref="TimestampInfo"/> from raw RFC 3161 timestamp token bytes.
    /// Returns null if the token cannot be parsed.
    /// </summary>
    internal static TimestampInfo? Extract(byte[] tokenBytes)
    {
        try
        {
            var tstInfoBytes = ExtractTstInfo(tokenBytes);
            if (tstInfoBytes is null)
            {
                return null;
            }

            using var tsaCert = ExtractTsaCertificate(tokenBytes);
            var (genTime, hashOid, policyOid, serialNumber) = ParseTstInfo(tstInfoBytes);

            return new TimestampInfo
            {
                GenerationTime = genTime,
                TsaCertificate = tsaCert is not null ? CertificateInfo.From(tsaCert) : null,
                HashAlgorithm = AlgorithmInfo.FromOid(hashOid),
                PolicyOid = policyOid,
                SerialNumber = serialNumber,
                RawToken = tokenBytes
            };
        }
        catch
        {
            return null;
        }
    }

    private static byte[]? ExtractTstInfo(byte[] timestampToken)
    {
        var tokenReader = new AsnReader(timestampToken, AsnEncodingRules.BER);
        var contentInfo = tokenReader.ReadSequence();
        _ = contentInfo.ReadObjectIdentifier(); // OID signedData

        var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedData = wrapper.ReadSequence();
        _ = signedData.ReadInteger(); // version
        _ = signedData.ReadSetOf();   // digestAlgorithms

        var encap = signedData.ReadSequence();
        _ = encap.ReadObjectIdentifier(); // id-ct-TSTInfo

        if (!encap.HasData)
        {
            return null;
        }

        var tstInfoWrapper = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        return tstInfoWrapper.ReadOctetString();
    }

    private static X509Certificate2? ExtractTsaCertificate(byte[] timestampToken)
    {
        try
        {
            var tokenReader = new AsnReader(timestampToken, AsnEncodingRules.BER);
            var contentInfo = tokenReader.ReadSequence();
            _ = contentInfo.ReadObjectIdentifier();
            var wrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var signedData = wrapper.ReadSequence();
            _ = signedData.ReadInteger();  // version
            _ = signedData.ReadSetOf();    // digestAlgorithms
            _ = signedData.ReadEncodedValue(); // encapContentInfo

            if (signedData.HasData && signedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                var certsWrapper = signedData.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                if (certsWrapper.HasData)
                {
                    return CertificateLoader.LoadCertificate(certsWrapper.ReadEncodedValue().ToArray());
                }
            }
        }
        catch (CryptographicException) { /* unable to load cert */ }
        catch (AsnContentException) { /* malformed ASN.1 */ }

        return null;
    }

    private static (DateTimeOffset genTime, string hashOid, string? policyOid, string? serialNumber) ParseTstInfo(byte[] tstInfoBytes)
    {
        var reader = new AsnReader(tstInfoBytes, AsnEncodingRules.BER).ReadSequence();

        _ = reader.ReadInteger(); // version
        string policyOid = reader.ReadObjectIdentifier();

        // messageImprint: { hashAlgorithm, hashedMessage }
        var msgImprint = reader.ReadSequence();
        var algSeq = msgImprint.ReadSequence();
        string hashOid = algSeq.ReadObjectIdentifier();
        _ = msgImprint.ReadOctetString(); // hashedMessage (not needed for introspection)

        // serialNumber (INTEGER)
        string? serialNumber = null;
        if (reader.HasData)
        {
            try
            {
                var serialBytes = reader.ReadInteger();
                serialNumber = Convert.ToHexString(serialBytes.ToByteArray());
            }
            catch { /* optional field */ }
        }

        // genTime (GeneralizedTime)
        DateTimeOffset genTime = default;
        if (reader.HasData)
        {
            try
            {
                genTime = reader.ReadGeneralizedTime();
            }
            catch { /* parsing failure */ }
        }

        return (genTime, hashOid, policyOid, serialNumber);
    }
}
