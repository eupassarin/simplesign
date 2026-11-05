using System.Formats.Asn1;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Crypto;

/// <summary>
/// Combines CMS SignedData structures (RFC 5652): adds a parallel signer (co-signature) or a
/// countersignature to an existing signature. The new signer is produced separately as a complete
/// one-signer SignedData (so policy, timestamp and LTV attributes come from the normal signing
/// path); its SignerInfo, certificates and digest algorithm are then merged in.
/// </summary>
internal static class CmsComposer
{
    private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag CrlsTag = new(TagClass.ContextSpecific, 1, true);
    private static readonly Asn1Tag UnsignedAttrsTag = new(TagClass.ContextSpecific, 1, true);

    /// <summary>The parts of a SignedData, as encoded values.</summary>
    private sealed record Parts(
        int Version,
        List<byte[]> DigestAlgorithms,
        byte[] EncapContentInfo,
        List<byte[]> Certificates,
        List<byte[]> Crls,
        List<byte[]> SignerInfos);

    /// <summary>Adds the (single) signer of <paramref name="newSignerCms"/> to <paramref name="existingCms"/>.</summary>
    /// <exception cref="ArgumentException">The two signatures do not cover the same content type / content.</exception>
    internal static byte[] AddSigner(byte[] existingCms, byte[] newSignerCms)
    {
        var target = Read(existingCms);
        var source = Read(newSignerCms);
        if (!SameContentType(target.EncapContentInfo, source.EncapContentInfo))
        {
            throw new ArgumentException("The new signature does not have the same encapsulated content type.", nameof(newSignerCms));
        }

        if (source.SignerInfos.Count != 1)
        {
            throw new ArgumentException("The new signature must have exactly one signer.", nameof(newSignerCms));
        }

        target.SignerInfos.Add(source.SignerInfos[0]);
        Merge(target.DigestAlgorithms, source.DigestAlgorithms);
        Merge(target.Certificates, source.Certificates);
        Merge(target.Crls, source.Crls);
        return Write(target with { Version = Math.Max(target.Version, source.Version) });
    }

    /// <summary>
    /// Adds the (single) signer of <paramref name="counterSignerCms"/> as an id-countersignature
    /// unsigned attribute of signer <paramref name="signerIndex"/> of <paramref name="existingCms"/>.
    /// </summary>
    internal static byte[] AddCounterSignature(byte[] existingCms, int signerIndex, byte[] counterSignerCms)
    {
        var target = Read(existingCms);
        var source = Read(counterSignerCms);
        if (signerIndex < 0 || signerIndex >= target.SignerInfos.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(signerIndex), $"The signature has {target.SignerInfos.Count} signer(s).");
        }

        if (source.SignerInfos.Count != 1)
        {
            throw new ArgumentException("The countersignature must have exactly one signer.", nameof(counterSignerCms));
        }

        target.SignerInfos[signerIndex] = AppendUnsignedAttribute(target.SignerInfos[signerIndex], Oids.CounterSignature, source.SignerInfos[0]);
        Merge(target.Certificates, source.Certificates);
        Merge(target.Crls, source.Crls);
        return Write(target);
    }

    /// <summary>The encoded signature value of signer <paramref name="signerIndex"/> (what a countersignature signs).</summary>
    internal static byte[] SignatureValue(byte[] cms, int signerIndex)
    {
        var parts = Read(cms);
        if (signerIndex < 0 || signerIndex >= parts.SignerInfos.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(signerIndex), $"The signature has {parts.SignerInfos.Count} signer(s).");
        }

        var si = new AsnReader(parts.SignerInfos[signerIndex], AsnEncodingRules.BER).ReadSequence();
        _ = si.ReadInteger();       // version
        _ = si.ReadEncodedValue();  // sid
        _ = si.ReadEncodedValue();  // digestAlgorithm
        if (si.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            _ = si.ReadEncodedValue(); // signedAttrs
        }

        _ = si.ReadEncodedValue();  // signatureAlgorithm
        return si.ReadOctetString();
    }

    private static Parts Read(byte[] cms)
    {
        var contentInfo = new AsnReader(cms, AsnEncodingRules.BER).ReadSequence();
        if (contentInfo.ReadObjectIdentifier() != Oids.SignedData)
        {
            throw new ArgumentException("Not a CMS SignedData.", nameof(cms));
        }

        var sd = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        int version = (int)sd.ReadInteger();
        var digestAlgorithms = ReadSet(sd.ReadSetOf(skipSortOrderValidation: true));
        byte[] encap = sd.ReadEncodedValue().ToArray();
        var certificates = sd.HasData && sd.PeekTag() == CertificatesTag ? ReadSet(sd.ReadSetOf(true, CertificatesTag)) : [];
        var crls = sd.HasData && sd.PeekTag() == CrlsTag ? ReadSet(sd.ReadSetOf(true, CrlsTag)) : [];
        var signerInfos = ReadSet(sd.ReadSetOf(skipSortOrderValidation: true));
        return new Parts(version, digestAlgorithms, encap, certificates, crls, signerInfos);
    }

    private static List<byte[]> ReadSet(AsnReader set)
    {
        var values = new List<byte[]>();
        while (set.HasData)
        {
            values.Add(set.ReadEncodedValue().ToArray());
        }

        return values;
    }

    private static byte[] Write(Parts parts)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteObjectIdentifier(Oids.SignedData);
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (w.PushSequence())
                {
                    w.WriteInteger(parts.Version);
                    WriteSet(w, parts.DigestAlgorithms, null);
                    w.WriteEncodedValue(parts.EncapContentInfo);
                    if (parts.Certificates.Count > 0)
                    {
                        WriteSet(w, parts.Certificates, CertificatesTag);
                    }

                    if (parts.Crls.Count > 0)
                    {
                        WriteSet(w, parts.Crls, CrlsTag);
                    }

                    // SignerInfos keep their order: DER would sort the SET OF and renumber the signers.
                    WriteSetInOrder(w, parts.SignerInfos);
                }
            }
        }

        return w.Encode();
    }

    private static void WriteSet(AsnWriter w, List<byte[]> values, Asn1Tag? tag)
    {
        using (w.PushSetOf(tag))
        {
            foreach (byte[] value in values)
            {
                w.WriteEncodedValue(value);
            }
        }
    }

    /// <summary>Writes a SET OF without reordering its elements (BER-valid; signer order is meaningful to callers).</summary>
    private static void WriteSetInOrder(AsnWriter w, List<byte[]> values)
    {
        var inner = new AsnWriter(AsnEncodingRules.BER);
        using (inner.PushSetOf())
        {
            foreach (byte[] value in values)
            {
                inner.WriteEncodedValue(value);
            }
        }

        w.WriteEncodedValue(inner.Encode());
    }

    private static byte[] AppendUnsignedAttribute(byte[] signerInfo, string oid, byte[] value)
    {
        var si = new AsnReader(signerInfo, AsnEncodingRules.BER).ReadSequence();
        var fields = new List<byte[]>();
        var attributes = new List<byte[]>();
        while (si.HasData)
        {
            if (si.PeekTag() == UnsignedAttrsTag)
            {
                attributes = ReadSet(si.ReadSetOf(true, UnsignedAttrsTag));
            }
            else
            {
                fields.Add(si.ReadEncodedValue().ToArray());
            }
        }

        // An existing attribute of the same type gets the new value appended (countersignatures accumulate).
        int existing = attributes.FindIndex(a => new AsnReader(a, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier() == oid);
        var attr = new AsnWriter(AsnEncodingRules.DER);
        using (attr.PushSequence())
        {
            attr.WriteObjectIdentifier(oid);
            using (attr.PushSetOf())
            {
                if (existing >= 0)
                {
                    var old = new AsnReader(attributes[existing], AsnEncodingRules.BER).ReadSequence();
                    _ = old.ReadObjectIdentifier();
                    var values = old.ReadSetOf(skipSortOrderValidation: true);
                    while (values.HasData)
                    {
                        attr.WriteEncodedValue(values.ReadEncodedValue().Span);
                    }
                }

                attr.WriteEncodedValue(value);
            }
        }

        if (existing >= 0)
        {
            attributes[existing] = attr.Encode();
        }
        else
        {
            attributes.Add(attr.Encode());
        }

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (byte[] field in fields)
            {
                w.WriteEncodedValue(field);
            }

            WriteSet(w, attributes, UnsignedAttrsTag);
        }

        return w.Encode();
    }

    private static void Merge(List<byte[]> target, List<byte[]> source)
    {
        foreach (byte[] value in source)
        {
            if (!target.Any(t => t.AsSpan().SequenceEqual(value)))
            {
                target.Add(value);
            }
        }
    }

    private static bool SameContentType(byte[] a, byte[] b)
    {
        static string Type(byte[] encap) => new AsnReader(encap, AsnEncodingRules.BER).ReadSequence().ReadObjectIdentifier();
        return Type(a) == Type(b);
    }
}
