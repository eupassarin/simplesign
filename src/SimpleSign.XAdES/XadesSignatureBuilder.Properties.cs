using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    /// <summary>
    /// Writes SignaturePolicyIdentifier/SignaturePolicyId. With the policy hash (as ICP-Brasil and
    /// other policies publish it), the identifier is written as an OID URN (Qualifier="OIDAsURN")
    /// and SigPolicyHash carries that hash. Without it, the legacy form is kept: the plain OID and,
    /// when a URI is set, a digest of the OID string.
    /// </summary>
    private static XmlElement CreateSignaturePolicyIdentifier(
        XmlDocument doc, SignaturePolicyReference policy, HashAlgorithmName hashAlgorithm)
    {
        var spElement = doc.CreateElement("SignaturePolicyIdentifier", XadesUris.XadesNamespace);
        var spIdElement = doc.CreateElement("SignaturePolicyId", XadesUris.XadesNamespace);
        var spOidElement = doc.CreateElement("SigPolicyId", XadesUris.XadesNamespace);
        var idElement = doc.CreateElement("Identifier", XadesUris.XadesNamespace);
        bool hasHash = !policy.Hash.IsEmpty;
        if (hasHash)
        {
            idElement.SetAttribute("Qualifier", "OIDAsURN");
            idElement.InnerText = "urn:oid:" + policy.Oid;
        }
        else
        {
            idElement.InnerText = policy.Oid;
        }

        spOidElement.AppendChild(idElement);
        spIdElement.AppendChild(spOidElement);

        if (hasHash || policy.Uri is not null)
        {
            var spHashElement = doc.CreateElement("SigPolicyHash", XadesUris.XadesNamespace);
            var dmElement = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
            var dvElement = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
            if (hasHash)
            {
                dmElement.SetAttribute("Algorithm", GetDigestMethod(PolicyHashAlgorithm(policy.HashAlgorithmOid)));
                dvElement.InnerText = Convert.ToBase64String(policy.Hash.Span);
            }
            else
            {
                dmElement.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
                dvElement.InnerText = Convert.ToBase64String(HashData(hashAlgorithm, Encoding.UTF8.GetBytes(policy.Oid)));
            }

            spHashElement.AppendChild(dmElement);
            spHashElement.AppendChild(dvElement);
            spIdElement.AppendChild(spHashElement);
        }

        if (policy.Uri is not null)
        {
            var spLocElement = doc.CreateElement("SigPolicyQualifiers", XadesUris.XadesNamespace);
            var spLocQual = doc.CreateElement("SigPolicyQualifier", XadesUris.XadesNamespace);
            var spRef = doc.CreateElement("SPURI", XadesUris.XadesNamespace);
            spRef.InnerText = policy.Uri;
            spLocQual.AppendChild(spRef);
            spLocElement.AppendChild(spLocQual);
            spIdElement.AppendChild(spLocElement);
        }

        spElement.AppendChild(spIdElement);
        return spElement;
    }

    private static HashAlgorithmName PolicyHashAlgorithm(string? oid) => oid switch
    {
        Oids.Sha1 => HashAlgorithmName.SHA1,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        null or Oids.Sha256 => HashAlgorithmName.SHA256,
        _ => throw new SigningException($"Unsupported signature policy hash algorithm {oid}.", SigningErrorReason.AlgorithmIncompatible),
    };

    private static XmlElement CreateSignedProperties(
        XmlDocument doc,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        DateTimeOffset signingTime,
        string signedPropertiesId,
        string signatureId,
        CommitmentType? commitmentType,
        SignaturePolicyReference? signaturePolicy,
        XadesSigningCertificateForm signingCertificateForm,
        IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat)
    {
        var signedProps = doc.CreateElement("SignedProperties", XadesUris.XadesNamespace);
        signedProps.SetAttribute("Id", signedPropertiesId);

        // SignedSignatureProperties — per ETSI EN 319 132-1 §5.2.2
        var signedSigProps = doc.CreateElement("SignedSignatureProperties", XadesUris.XadesNamespace);

        var stElement = doc.CreateElement("SigningTime", XadesUris.XadesNamespace);
        stElement.InnerText = signingTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        signedSigProps.AppendChild(stElement);

        signedSigProps.AppendChild(signingCertificateForm == XadesSigningCertificateForm.V1
            ? CreateSigningCertificateV1(doc, certificate, hashAlgorithm)
            : CreateSigningCertificateV2(doc, certificate, hashAlgorithm));

        // SignaturePolicyIdentifier — child of SignedSignatureProperties per §5.2.2
        if (signaturePolicy is not null)
        {
            signedSigProps.AppendChild(CreateSignaturePolicyIdentifier(doc, signaturePolicy, hashAlgorithm));
        }

        // SignerRole — child of SignedSignatureProperties per §5.2.2
        if (signerRoles is not null && signerRoles.Count > 0)
        {
            var srElement = doc.CreateElement("SignerRole", XadesUris.XadesNamespace);
            var claimedRoles = doc.CreateElement("ClaimedRoles", XadesUris.XadesNamespace);
            foreach (var role in signerRoles)
            {
                if (string.IsNullOrWhiteSpace(role))
                {
                    continue;
                }
                var crElement = doc.CreateElement("ClaimedRole", XadesUris.XadesNamespace);
                crElement.InnerText = role;
                claimedRoles.AppendChild(crElement);
            }
            if (claimedRoles.HasChildNodes)
            {
                srElement.AppendChild(claimedRoles);
                signedSigProps.AppendChild(srElement);
            }
        }

        signedProps.AppendChild(signedSigProps);

        // SignedDataObjectProperties — per ETSI EN 319 132-1 §5.2.3
        if (commitmentType.HasValue || dataObjectFormat is not null)
        {
            var signedDataObjProps = doc.CreateElement("SignedDataObjectProperties", XadesUris.XadesNamespace);

            // DataObjectFormat before CommitmentTypeIndication per §5.2.3 ordering
            if (dataObjectFormat is not null)
            {
                var dofElement = doc.CreateElement("DataObjectFormat", XadesUris.XadesNamespace);
                if (!string.IsNullOrEmpty(dataObjectFormat.ObjectReference))
                {
                    dofElement.SetAttribute("ObjectReference", dataObjectFormat.ObjectReference);
                }
                if (dataObjectFormat.MimeType is not null)
                {
                    var mtElement = doc.CreateElement("MimeType", XadesUris.XadesNamespace);
                    mtElement.InnerText = dataObjectFormat.MimeType;
                    dofElement.AppendChild(mtElement);
                }
                signedDataObjProps.AppendChild(dofElement);
            }

            if (commitmentType.HasValue)
            {
                var ctElement = doc.CreateElement("CommitmentTypeIndication", XadesUris.XadesNamespace);
                var ctvElement = doc.CreateElement("CommitmentTypeId", XadesUris.XadesNamespace);
                var idElement = doc.CreateElement("Identifier", XadesUris.XadesNamespace);

                string ctOid = commitmentType.Value switch
                {
                    CommitmentType.ProofOfOrigin => Oids.ProofOfOrigin,
                    CommitmentType.ProofOfReceipt => Oids.ProofOfReceipt,
                    CommitmentType.ProofOfDelivery => Oids.ProofOfDelivery,
                    CommitmentType.ProofOfSender => Oids.ProofOfSender,
                    CommitmentType.ProofOfApproval => Oids.ProofOfApproval,
                    CommitmentType.ProofOfCreation => Oids.ProofOfCreation,
                    _ => throw new ArgumentOutOfRangeException(nameof(commitmentType))
                };

                idElement.InnerText = ctOid;
                ctvElement.AppendChild(idElement);
                ctElement.AppendChild(ctvElement);
                signedDataObjProps.AppendChild(ctElement);
            }

            signedProps.AppendChild(signedDataObjProps);
        }

        return signedProps;
    }

    /// <summary>
    /// XAdES 1.3.2 SigningCertificate (v1): CertDigest and IssuerSerial (issuer DN and decimal
    /// serial), the form the ICP-Brasil XML signature policies mandate.
    /// </summary>
    private static XmlElement CreateSigningCertificateV1(
        XmlDocument doc,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm)
    {
        var signingCertificate = doc.CreateElement("SigningCertificate", XadesUris.XadesNamespace);
        var certElement = doc.CreateElement("Cert", XadesUris.XadesNamespace);

        var certDigest = doc.CreateElement("CertDigest", XadesUris.XadesNamespace);
        var dmElement = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
        dmElement.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
        var dvElement = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
        dvElement.InnerText = Convert.ToBase64String(CryptoUtility.ComputeHash(certificate.RawData, hashAlgorithm));
        certDigest.AppendChild(dmElement);
        certDigest.AppendChild(dvElement);

        var issuerSerial = doc.CreateElement("IssuerSerial", XadesUris.XadesNamespace);
        var issuerName = doc.CreateElement("X509IssuerName", XmlDSigUrls.DsNamespace);
        issuerName.InnerText = certificate.IssuerName.Name;
        var serialNumber = doc.CreateElement("X509SerialNumber", XmlDSigUrls.DsNamespace);
        serialNumber.InnerText = new System.Numerics.BigInteger(certificate.GetSerialNumber(), isUnsigned: true)
            .ToString(CultureInfo.InvariantCulture);
        issuerSerial.AppendChild(issuerName);
        issuerSerial.AppendChild(serialNumber);

        certElement.AppendChild(certDigest);
        certElement.AppendChild(issuerSerial);
        signingCertificate.AppendChild(certElement);
        return signingCertificate;
    }

    private static XmlElement CreateSigningCertificateV2(
        XmlDocument doc,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm)
    {
        var scv2 = doc.CreateElement("SigningCertificateV2", XadesUris.XadesNamespace);

        var certElement = doc.CreateElement("Cert", XadesUris.XadesNamespace);

        var certDigest = doc.CreateElement("CertDigest", XadesUris.XadesNamespace);
        var dmElement = doc.CreateElement("DigestMethod", XmlDSigUrls.DsNamespace);
        dmElement.SetAttribute("Algorithm", GetDigestMethod(hashAlgorithm));
        var dvElement = doc.CreateElement("DigestValue", XmlDSigUrls.DsNamespace);
        byte[] certHash = CryptoUtility.ComputeHash(certificate.RawData, hashAlgorithm);
        dvElement.InnerText = Convert.ToBase64String(certHash);
        certDigest.AppendChild(dmElement);
        certDigest.AppendChild(dvElement);

        var issuerSerial = doc.CreateElement("IssuerSerialV2", XadesUris.XadesNamespace);
        issuerSerial.InnerText = Convert.ToBase64String(EncodeIssuerSerialV2(certificate));

        certElement.AppendChild(certDigest);
        certElement.AppendChild(issuerSerial);
        scv2.AppendChild(certElement);

        return scv2;
    }

    private static byte[] EncodeIssuerSerialV2(X509Certificate2 certificate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();

        // IssuerSerial.issuer is GeneralNames, whose only entry for an X.509
        // certificate must be the issuer DN in the directoryName choice.
        writer.PushSequence();
        var directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true);
        writer.PushSequence(directoryNameTag);
        writer.WriteEncodedValue(certificate.IssuerName.RawData);
        writer.PopSequence(directoryNameTag);
        writer.PopSequence();

        var serial = certificate.GetSerialNumber();
        Array.Reverse(serial);
        writer.WriteIntegerUnsigned(serial);
        writer.PopSequence();
        return writer.Encode();
    }

    private static XmlElement CreateQualifyingProperties(
        XmlDocument doc,
        string signatureId,
        XmlElement signedProperties)
    {
        var qp = doc.CreateElement("QualifyingProperties", XadesUris.XadesNamespace);
        qp.SetAttribute("Target", "#" + signatureId);
        qp.AppendChild(signedProperties);
        return qp;
    }

    private static XmlElement EnsureUnsignedSignatureProperties(
        XmlDocument doc,
        XmlElement signature,
        XmlNamespaceManager ns)
    {
        // Ensure QualifyingProperties/UnsignedProperties exists
        if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", ns) is not XmlElement unsignedProps)
        {
            if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties", ns) is not XmlElement qp)
            {
                qp = doc.CreateElement("QualifyingProperties", XadesUris.XadesNamespace);
                qp.SetAttribute("Target", "#" + signature.GetAttribute("Id"));
                var obj = doc.CreateElement("Object", XmlDSigUrls.DsNamespace);
                obj.AppendChild(qp);
                signature.AppendChild(obj);
            }

            unsignedProps = doc.CreateElement("UnsignedProperties", XadesUris.XadesNamespace);
            qp.AppendChild(unsignedProps);
        }

        // Ensure UnsignedProperties/UnsignedSignatureProperties exists (ETSI EN 319 132-1 §5.3)
        if (unsignedProps.SelectSingleNode(
                "xades:UnsignedSignatureProperties", ns) is not XmlElement usp)
        {
            usp = doc.CreateElement("UnsignedSignatureProperties", XadesUris.XadesNamespace);
            unsignedProps.AppendChild(usp);
        }

        return usp;
    }
}
