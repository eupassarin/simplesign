using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

/// <summary>
/// A countersignature placed in the document with an empty ds:SignatureValue, and the canonical
/// SignedInfo its key has to sign.
/// </summary>
internal sealed record XadesCounterSignaturePreparation(byte[] PreparedXml, byte[] SignedInfoCanonical, string SignatureId);

internal static partial class XadesSignatureBuilder
{
    /// <summary>The Id given to the ds:SignatureValue of a signature, which is what a countersignature references.</summary>
    internal static string SignatureValueId(string signatureId) => signatureId + "-SignatureValue";

    /// <summary>Signs a canonical SignedInfo with the certificate's private key.</summary>
    internal static byte[] SignCanonicalSignedInfo(
        byte[] signedInfoCanonical, HashAlgorithmName hashAlgorithm, string signatureAlgorithmOid, X509Certificate2 certificate) =>
        SignHash(HashData(hashAlgorithm, signedInfoCanonical), hashAlgorithm, signatureAlgorithmOid, certificate);

    /// <summary>
    /// Builds an enveloped countersignature (ETSI EN 319 132-1 §5.2.7.2): a XAdES signature inside the
    /// CounterSignature unsigned property of the countersigned signature, whose first ds:Reference
    /// points to that signature's ds:SignatureValue and is typed
    /// <c>http://uri.etsi.org/01903#CountersignedSignature</c>. The ds:SignatureValue of the
    /// countersignature is left empty for <see cref="CompleteCounterSignature"/>.
    /// </summary>
    internal static XadesCounterSignaturePreparation PrepareCounterSignature(
        byte[] signedXml,
        string? targetSignatureId,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        CommitmentType? commitmentType,
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
        string signatureAlgorithmOid,
        XadesSignerRoles? signerRoles,
        SignatureProductionPlace? productionPlace,
        string canonicalization)
    {
        var doc = LoadDocument(signedXml);
        var ns = CreateNamespaceManager(doc);
        XmlElement target = ResolveCounterSignatureTarget(doc, ns, targetSignatureId);
        if (target.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement targetValue)
        {
            throw new SigningException("The signature to countersign has no ds:SignatureValue.", SigningErrorReason.Unspecified);
        }

        string targetValueId = EnsureSignatureValueId(target, targetValue, ns);
        string signatureId = XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8];
        string signedPropertiesId = XadesUris.SignedPropertiesIdPrefix + Guid.NewGuid().ToString("N")[..8];

        // Put the countersignature in its final place first: the digests and the canonical
        // SignedInfo are then computed with the ancestors they will really have.
        var counterSignature = doc.CreateElement("CounterSignature", XadesUris.XadesNamespace);
        var signature = doc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        signature.SetAttribute("Id", signatureId);
        counterSignature.AppendChild(signature);
        EnsureUnsignedSignatureProperties(doc, target, ns).AppendChild(counterSignature);

        var signedProperties = CreateSignedProperties(
            doc, certificate, hashAlgorithm, signingTime, signedPropertiesId, commitmentType, signaturePolicy,
            signingCertificateForm, signerRoles, dataObjectFormat: null, productionPlace, dataObjectsTimeStamp: null, additionalReferences: null, signsDocument: false);
        var propertiesObject = doc.CreateElement("Object", XmlDSigUrls.DsNamespace);
        propertiesObject.AppendChild(CreateQualifyingProperties(doc, signatureId, signedProperties));
        signature.AppendChild(propertiesObject);

        byte[] targetValueDigest = HashData(hashAlgorithm, CanonicalizeElement(targetValue, canonicalization));
        byte[] signedPropertiesDigest = HashData(hashAlgorithm, CanonicalizeElement(signedProperties, canonicalization));

        var signedInfo = doc.CreateElement("SignedInfo", XmlDSigUrls.DsNamespace);
        var canonicalizationMethod = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        canonicalizationMethod.SetAttribute("Algorithm", canonicalization);
        signedInfo.AppendChild(canonicalizationMethod);
        var signatureMethod = doc.CreateElement("SignatureMethod", XmlDSigUrls.DsNamespace);
        signatureMethod.SetAttribute("Algorithm", GetSignatureMethodUri(signatureAlgorithmOid, hashAlgorithm));
        signedInfo.AppendChild(signatureMethod);
        var valueReference = CreateDocRef(doc, "#" + targetValueId, hashAlgorithm, enveloped: false, targetValueDigest, canonicalization);
        valueReference.SetAttribute("Type", XadesUris.CountersignedSignatureType);
        signedInfo.AppendChild(valueReference);
        signedInfo.AppendChild(CreateDocRef(doc, "#" + signedPropertiesId, hashAlgorithm,
            enveloped: false, signedPropertiesDigest, canonicalization, signedPropsType: true));
        signature.PrependChild(signedInfo);

        var signatureValue = doc.CreateElement("SignatureValue", XmlDSigUrls.DsNamespace);
        signatureValue.SetAttribute("Id", SignatureValueId(signatureId));
        signature.InsertAfter(signatureValue, signedInfo);

        var keyInfo = doc.CreateElement("KeyInfo", XmlDSigUrls.DsNamespace);
        var x509Data = doc.CreateElement("X509Data", XmlDSigUrls.DsNamespace);
        foreach (var keyCertificate in new[] { certificate }.Concat(extraCertificates ?? []))
        {
            var x509Certificate = doc.CreateElement("X509Certificate", XmlDSigUrls.DsNamespace);
            x509Certificate.InnerText = Convert.ToBase64String(keyCertificate.RawData);
            x509Data.AppendChild(x509Certificate);
        }

        keyInfo.AppendChild(x509Data);
        signature.InsertAfter(keyInfo, signatureValue);

        byte[] signedInfoCanonical = CanonicalizeElement(signedInfo, canonicalization);
        using var ms = new MemoryStream();
        doc.Save(ms);
        return new XadesCounterSignaturePreparation(ms.ToArray(), signedInfoCanonical, signatureId);
    }

    /// <summary>Writes the signature value into a countersignature made by <see cref="PrepareCounterSignature"/>.</summary>
    internal static byte[] CompleteCounterSignature(byte[] preparedXml, string signatureId, byte[] signatureValue) =>
        SetSignatureValue(preparedXml, signatureId, signatureValue);

    /// <summary>
    /// The octets ds:SignatureValue holds for a raw signature made by a key held elsewhere. Such a signer
    /// returns ECDSA as an ASN.1 DER SEQUENCE { r, s } (the <see cref="IExternalSigner"/> contract), while
    /// XMLDSig writes r and s as two fixed-length integers one after the other (W3C XMLDSig Core 1.1 §6.4.3).
    /// An RSA signature is already in its XMLDSig form.
    /// </summary>
    /// <param name="rawSignature">The signature, already verified against <paramref name="certificate"/>.</param>
    /// <param name="certificate">The signer certificate.</param>
    internal static byte[] XmlSignatureValue(byte[] rawSignature, X509Certificate2 certificate)
    {
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is null)
        {
            return rawSignature;
        }

        int fieldSize = (ecdsa.KeySize + 7) / 8;
        var reader = new AsnReader(rawSignature, AsnEncodingRules.DER);
        AsnReader sequence = reader.ReadSequence();
        ReadOnlySpan<byte> r = sequence.ReadIntegerBytes().Span.TrimStart((byte)0);
        ReadOnlySpan<byte> s = sequence.ReadIntegerBytes().Span.TrimStart((byte)0);
        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        if (r.Length > fieldSize || s.Length > fieldSize)
        {
            throw new SigningException(
                "The ECDSA signature does not fit the curve of the signing certificate.",
                SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        }

        byte[] value = new byte[fieldSize * 2];
        r.CopyTo(value.AsSpan(fieldSize - r.Length));
        s.CopyTo(value.AsSpan((fieldSize * 2) - s.Length));
        return value;
    }

    /// <summary>
    /// Writes the signature value into the ds:Signature with the given Id of a document assembled with an
    /// empty ds:SignatureValue: a countersignature, or a signature prepared in the first of two phases.
    /// </summary>
    internal static byte[] SetSignatureValue(byte[] preparedXml, string signatureId, byte[] signatureValue)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(preparedXml));
        var ns = CreateNamespaceManager(doc);
        var value = (XmlElement)ResolveSignature(doc, ns, signatureId).SelectSingleNode("ds:SignatureValue", ns)!;
        value.InnerText = Convert.ToBase64String(signatureValue);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// The signature to countersign: the one with the given Id, or the only signature of the
    /// document. Countersignatures themselves are not targets: changing one that an archive
    /// time-stamp of its parent already covers would break that time-stamp.
    /// </summary>
    private static XmlElement ResolveCounterSignatureTarget(XmlDocument doc, XmlNamespaceManager ns, string? signatureId)
    {
        var signatures = doc.SelectNodes("//ds:Signature[not(parent::xades:CounterSignature)]", ns)!.OfType<XmlElement>().ToList();
        if (signatures.Count == 0)
        {
            throw new SigningException("The document has no signature to countersign.", SigningErrorReason.Unspecified);
        }

        if (string.IsNullOrWhiteSpace(signatureId))
        {
            return signatures.Count == 1
                ? signatures[0]
                : throw new SigningException(
                    "The document has several signatures: give the Id of the one to countersign.", SigningErrorReason.Unspecified);
        }

        return signatures.FirstOrDefault(s => string.Equals(s.GetAttribute("Id"), signatureId, StringComparison.Ordinal))
            ?? throw new SigningException(
                $"Signature '{signatureId}' was not found among the signatures of the document (a countersignature cannot be countersigned).",
                SigningErrorReason.Unspecified);
    }

    /// <summary>
    /// The Id of the ds:SignatureValue to reference. A value without an Id receives one, unless a
    /// time-stamp already covers the element: the Id would change what the time-stamp protects.
    /// </summary>
    private static string EnsureSignatureValueId(XmlElement target, XmlElement targetValue, XmlNamespaceManager ns)
    {
        string id = targetValue.GetAttribute("Id");
        if (id.Length > 0)
        {
            return id;
        }

        const string unsigned = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";
        if (target.SelectSingleNode(
                unsigned + "xades:SignatureTimeStamp | " + unsigned + "xades:SigAndRefsTimeStamp | " + unsigned + "xades141:SigAndRefsTimeStampV2 | " +
                unsigned + "xades:ArchiveTimeStamp | " + unsigned + "xades141:ArchiveTimeStamp", ns) is not null)
        {
            throw new SigningException(
                "The signature to countersign has no Id on ds:SignatureValue and already carries time-stamps over it: " +
                "adding the Id a countersignature needs would invalidate them.",
                SigningErrorReason.Unspecified);
        }

        string targetId = target.GetAttribute("Id");
        id = SignatureValueId(targetId.Length > 0 ? targetId : XadesUris.SignatureIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        targetValue.SetAttribute("Id", id);
        return id;
    }
}
