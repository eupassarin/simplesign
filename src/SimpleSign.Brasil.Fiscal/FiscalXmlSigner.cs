using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Fiscal;

/// <summary>
/// Signs Brazilian fiscal XML (NF-e, NFC-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf) with
/// an enveloped XMLDSig signature as the layouts require: the element named by the profile
/// (by its Id) or the whole document, enveloped-signature + C14N transforms, RSA with the
/// profile's hash, and the signer certificate in KeyInfo. The XML is not reformatted: send it
/// exactly as returned, since any change after signing breaks the signature.
/// </summary>
/// <example>
/// <code>
/// byte[] signed = FiscalXmlSigner.Sign(nfeXml, FiscalDocumentProfile.NFe, eCnpjCertificate);
/// </code>
/// </example>
public static class FiscalXmlSigner
{
    /// <summary>Signs the single element the profile designates (or the one with <paramref name="elementId"/>).</summary>
    /// <param name="xml">The XML document (UTF-8).</param>
    /// <param name="profile">The layout profile, e.g. <see cref="FiscalDocumentProfile.NFe"/>.</param>
    /// <param name="certificate">The ICP-Brasil certificate (e-CNPJ/e-CPF) with its RSA private key.</param>
    /// <param name="elementId">The Id of the element to sign, when the document has more than one.</param>
    /// <returns>The signed XML.</returns>
    /// <exception cref="ArgumentException">No element, or several elements and no <paramref name="elementId"/>.</exception>
    public static byte[] Sign(byte[] xml, FiscalDocumentProfile profile, X509Certificate2 certificate, string? elementId = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using RSA rsa = certificate.GetRSAPrivateKey()
            ?? throw new ArgumentException("The certificate has no RSA private key.", nameof(certificate));
        return SignCore(xml, profile, certificate, elementId, all: false,
            (data, hash) => rsa.SignData(data, hash, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// Signs every element the profile designates that is not signed yet — e.g. each NF-e of an
    /// <c>enviNFe</c> batch, or each event of a batch.
    /// </summary>
    /// <param name="xml">The XML document (UTF-8).</param>
    /// <param name="profile">The layout profile.</param>
    /// <param name="certificate">The ICP-Brasil certificate with its RSA private key.</param>
    /// <returns>The signed XML.</returns>
    public static byte[] SignAll(byte[] xml, FiscalDocumentProfile profile, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using RSA rsa = certificate.GetRSAPrivateKey()
            ?? throw new ArgumentException("The certificate has no RSA private key.", nameof(certificate));
        return SignCore(xml, profile, certificate, elementId: null, all: true,
            (data, hash) => rsa.SignData(data, hash, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// Signs with an external key (A3 token through PKCS#11, cloud signer, HSM): the signer
    /// receives the canonicalized SignedInfo (<see cref="ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo"/>).
    /// </summary>
    /// <param name="xml">The XML document (UTF-8).</param>
    /// <param name="profile">The layout profile.</param>
    /// <param name="certificate">The signer certificate (public part).</param>
    /// <param name="signer">The external signer holding the private key.</param>
    /// <param name="elementId">The Id of the element to sign, when the document has more than one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<byte[]> SignAsync(
        byte[] xml, FiscalDocumentProfile profile, X509Certificate2 certificate, IExternalSigner signer,
        string? elementId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(profile);

        // Canonicalize first, then sign asynchronously, then finish the document.
        var pending = Prepare(xml, profile, elementId, all: false);
        foreach (var signature in pending.Signatures)
        {
            var request = new ExternalSigningRequest(
                signature.CanonicalSignedInfo, profile.HashAlgorithm, XmlDsig.RsaSignatureOid(profile.HashAlgorithm),
                ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
            var value = await signer.SignAsync(request, cancellationToken).ConfigureAwait(false);
            Complete(signature, value.ToArray(), certificate);
        }

        return XmlDsig.Save(pending.Document);
    }

    private static byte[] SignCore(
        byte[] xml, FiscalDocumentProfile profile, X509Certificate2 certificate, string? elementId, bool all,
        Func<byte[], HashAlgorithmName, byte[]> sign)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var pending = Prepare(xml, profile, elementId, all);
        foreach (var signature in pending.Signatures)
        {
            Complete(signature, sign(signature.CanonicalSignedInfo, profile.HashAlgorithm), certificate);
        }

        return XmlDsig.Save(pending.Document);
    }

    private sealed record PendingSignature(XmlElement Signature, byte[] CanonicalSignedInfo);

    private sealed record Prepared(XmlDocument Document, List<PendingSignature> Signatures);

    private static Prepared Prepare(byte[] xml, FiscalDocumentProfile profile, string? elementId, bool all)
    {
        ArgumentNullException.ThrowIfNull(xml);
        var doc = XmlDsig.Load(xml);
        var targets = FindTargets(doc, profile);
        if (elementId is not null)
        {
            targets = [.. targets.Where(t => t.GetAttribute(profile.IdAttribute ?? "Id") == elementId)];
        }
        else if (all && targets.Count > 0)
        {
            targets = [.. targets.Where(t => !IsSigned(doc, profile, t))];
            if (targets.Count == 0)
            {
                return new Prepared(doc, []); // everything is already signed
            }
        }

        if (targets.Count == 0)
        {
            throw new ArgumentException(
                $"No {profile.SignedElement ?? "document"} element to sign{(elementId is null ? string.Empty : $" with Id '{elementId}'")}.", nameof(xml));
        }

        if (!all && targets.Count > 1)
        {
            throw new ArgumentException(
                $"The document has {targets.Count} {profile.SignedElement} elements: pass elementId or use SignAll.", nameof(xml));
        }

        var pending = new List<PendingSignature>();
        foreach (var target in targets)
        {
            pending.Add(Insert(doc, profile, target));
        }

        return new Prepared(doc, pending);
    }

    internal static List<XmlElement> FindTargets(XmlDocument doc, FiscalDocumentProfile profile)
    {
        var root = doc.DocumentElement ?? throw new ArgumentException("The XML has no root element.");
        if (profile.SignedElement is null)
        {
            return [root];
        }

        return [.. root.SelectNodes("descendant-or-self::*")!.Cast<XmlElement>()
            .Where(e => (profile.SignedElement == "*" || e.LocalName == profile.SignedElement)
                && e.NamespaceURI != XmlDSigUrls.DsNamespace
                && profile.IdAttribute is not null
                && !string.IsNullOrEmpty(e.GetAttribute(profile.IdAttribute)))];
    }

    private static bool IsSigned(XmlDocument doc, FiscalDocumentProfile profile, XmlElement target)
    {
        string uri = profile.IdAttribute is null ? string.Empty : "#" + target.GetAttribute(profile.IdAttribute);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        return doc.SelectNodes("//ds:Signature/ds:SignedInfo/ds:Reference", ns)!
            .Cast<XmlElement>().Any(r => r.GetAttribute("URI") == uri);
    }

    private static PendingSignature Insert(XmlDocument doc, FiscalDocumentProfile profile, XmlElement target)
    {
        string uri = profile.IdAttribute is null ? string.Empty : "#" + target.GetAttribute(profile.IdAttribute);
        byte[] digest = XmlDsig.Hash(profile.HashAlgorithm, XmlDsig.Canonicalize(target, profile.CanonicalizationMethod));

        var signature = doc.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        var signedInfo = Append(signature, "SignedInfo");
        Append(signedInfo, "CanonicalizationMethod").SetAttribute("Algorithm", profile.CanonicalizationMethod);
        Append(signedInfo, "SignatureMethod").SetAttribute("Algorithm", XmlDsig.RsaSignatureUri(profile.HashAlgorithm));
        var reference = Append(signedInfo, "Reference");
        reference.SetAttribute("URI", uri);
        var transforms = Append(reference, "Transforms");
        Append(transforms, "Transform").SetAttribute("Algorithm", XmlDSigUrls.EnvelopedSignatureTransform);
        Append(transforms, "Transform").SetAttribute("Algorithm", profile.CanonicalizationMethod);
        Append(reference, "DigestMethod").SetAttribute("Algorithm", XmlDsig.DigestUri(profile.HashAlgorithm));
        Append(reference, "DigestValue").InnerText = Convert.ToBase64String(digest);

        if (profile.Placement == FiscalSignaturePlacement.LastChildOfRoot)
        {
            doc.DocumentElement!.AppendChild(signature);
        }
        else
        {
            target.ParentNode!.InsertAfter(signature, target);
        }

        // SignedInfo is canonicalized where it sits (inherited namespaces included).
        return new PendingSignature(signature, XmlDsig.Canonicalize(signedInfo, profile.CanonicalizationMethod));
    }

    private static void Complete(PendingSignature pending, byte[] signatureValue, X509Certificate2 certificate)
    {
        Append(pending.Signature, "SignatureValue").InnerText = Convert.ToBase64String(signatureValue);
        var keyInfo = Append(pending.Signature, "KeyInfo");
        var x509Data = Append(keyInfo, "X509Data");
        Append(x509Data, "X509Certificate").InnerText = Convert.ToBase64String(certificate.RawData);
    }

    private static XmlElement Append(XmlElement parent, string name)
    {
        var element = parent.OwnerDocument.CreateElement(name, XmlDSigUrls.DsNamespace);
        parent.AppendChild(element);
        return element;
    }
}
