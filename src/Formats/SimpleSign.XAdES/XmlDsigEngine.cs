using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;

namespace SimpleSign.XAdES;

/// <summary>What a plain XML-DSig signature signs: an element by its Id attribute, or the whole document.</summary>
/// <param name="ElementName">Local name of the signed element (any namespace); <c>*</c> = any element carrying
/// <paramref name="IdAttribute"/>; null = the whole document (<c>URI=""</c>).</param>
/// <param name="IdAttribute">Name of the attribute the reference points to (<c>Id</c>, <c>id</c>…); null with the whole document.</param>
internal sealed record XmlDsigTarget(string? ElementName, string? IdAttribute)
{
    /// <summary>The whole document.</summary>
    internal static XmlDsigTarget Document { get; } = new(null, null);

    /// <summary>Whether the signature covers the whole document (<c>URI=""</c>).</summary>
    internal bool IsDocument => ElementName is null;

    /// <summary>The Reference URI that points to <paramref name="element"/>.</summary>
    internal string ReferenceUri(XmlElement element) => IsDocument ? string.Empty : "#" + element.GetAttribute(IdAttribute!);
}

/// <summary>A signature inserted in the document whose SignatureValue is still to be written.</summary>
/// <param name="Signature">The ds:Signature, in its place, holding only SignedInfo.</param>
/// <param name="CanonicalSignedInfo">The canonical SignedInfo: the bytes the key signs.</param>
/// <param name="ReferenceUri">The URI of its only Reference.</param>
internal sealed record XmlDsigPendingSignature(XmlElement Signature, byte[] CanonicalSignedInfo, string ReferenceUri);

/// <summary>
/// The building blocks of a plain enveloped XML-DSig signature (W3C XML Signature 1.0, no XAdES properties): one
/// Reference to an element by Id (or to the document), the enveloped-signature and canonicalization transforms, the
/// signature placed after the element or at the end of the root, and the signer certificate in KeyInfo. This is the
/// form the Brazilian fiscal layouts (NF-e, CT-e, MDF-e, NFS-e, eSocial, EFD-Reinf) require.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal static class XmlDsigEngine
{
    /// <summary>The attributes an Id reference may name, as the validator resolves them.</summary>
    private static readonly string[] s_idAttributes = ["Id", "id", "ID"];

    /// <summary>Reads XML keeping its whitespace, with DTDs prohibited and no external resolution.</summary>
    /// <exception cref="ArgumentException">The XML is not well-formed or has no root element.</exception>
    internal static XmlDocument Load(byte[] xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var stream = new MemoryStream(xml, writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            document.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new ArgumentException($"The XML cannot be read: {ex.Message}", nameof(xml), ex);
        }

        return document.DocumentElement is null
            ? throw new ArgumentException("The XML has no root element.", nameof(xml))
            : document;
    }

    /// <summary>Writes the document back without reformatting it (UTF-8, no BOM; the declaration kept when it had one).</summary>
    internal static byte[] Save(XmlDocument document)
    {
        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            OmitXmlDeclaration = document.FirstChild is not XmlDeclaration,
            Indent = false,
        };
        using (var writer = XmlWriter.Create(stream, settings))
        {
            document.Save(writer);
        }

        return stream.ToArray();
    }

    /// <summary>The elements of the document the target designates, in document order.</summary>
    internal static List<XmlElement> FindTargets(XmlDocument document, XmlDsigTarget target)
    {
        var root = document.DocumentElement!;
        if (target.IsDocument)
        {
            return [root];
        }

        return [.. root.SelectNodes("descendant-or-self::*")!.Cast<XmlElement>()
            .Where(e => (target.ElementName == "*" || e.LocalName == target.ElementName)
                && e.NamespaceURI != XmlDSigUrls.DsNamespace
                && !string.IsNullOrEmpty(e.GetAttribute(target.IdAttribute!)))];
    }

    /// <summary>Whether a ds:Signature of the document already references <paramref name="uri"/>.</summary>
    internal static bool IsSigned(XmlDocument document, string uri) =>
        document.SelectNodes("//ds:Signature/ds:SignedInfo/ds:Reference", Namespaces(document))!
            .Cast<XmlElement>().Any(r => r.GetAttribute("URI") == uri);

    /// <summary>The elements whose Id (<c>Id</c>, <c>id</c> or <c>ID</c>) is <paramref name="id"/>.</summary>
    internal static List<XmlElement> ElementsWithId(XmlDocument document, string id) =>
        [.. document.SelectNodes("//*")!.Cast<XmlElement>().Where(e => s_idAttributes.Any(a => e.GetAttribute(a) == id))];

    /// <summary>
    /// Inserts a ds:Signature holding the SignedInfo of <paramref name="element"/> where the placement says, and returns
    /// it with the canonical SignedInfo (canonicalized where it stands, its inherited namespaces included).
    /// </summary>
    /// <exception cref="ArgumentException">The element's Id is not unique in the document.</exception>
    internal static XmlDsigPendingSignature Insert(
        XmlDocument document, XmlDsigTarget target, XmlElement element, XmlDsigPlacement placement,
        HashAlgorithmName hashAlgorithm, string signatureMethodUri, string canonicalization)
    {
        string uri = target.ReferenceUri(element);
        if (!target.IsDocument && ElementsWithId(document, uri[1..]).Count != 1)
        {
            throw new ArgumentException(
                $"More than one element has the Id '{uri[1..]}': the reference would be ambiguous.", nameof(document));
        }

        // The digest is taken before the signature is in the document: that is what the enveloped transform leaves.
        byte[] digest = Hash(hashAlgorithm, CanonicalizeReferenced(document, target, element, canonicalization, excluded: null));

        var signature = document.CreateElement("Signature", XmlDSigUrls.DsNamespace);
        var signedInfo = Append(signature, "SignedInfo");
        Append(signedInfo, "CanonicalizationMethod").SetAttribute("Algorithm", canonicalization);
        Append(signedInfo, "SignatureMethod").SetAttribute("Algorithm", signatureMethodUri);
        var reference = Append(signedInfo, "Reference");
        reference.SetAttribute("URI", uri);
        var transforms = Append(reference, "Transforms");
        Append(transforms, "Transform").SetAttribute("Algorithm", XmlDSigUrls.EnvelopedSignatureTransform);
        Append(transforms, "Transform").SetAttribute("Algorithm", canonicalization);
        Append(reference, "DigestMethod").SetAttribute("Algorithm", XmlDSigUrls.GetDigestUri(hashAlgorithm));
        Append(reference, "DigestValue").InnerText = Convert.ToBase64String(digest);

        if (placement == XmlDsigPlacement.LastChildOfRoot || target.IsDocument)
        {
            document.DocumentElement!.AppendChild(signature);
        }
        else
        {
            element.ParentNode!.InsertAfter(signature, element);
        }

        return new XmlDsigPendingSignature(signature, CanonicalSignedInfo(signedInfo, canonicalization), uri);
    }

    /// <summary>Writes the SignatureValue and the KeyInfo (the signer certificate only) of a pending signature.</summary>
    internal static void Complete(XmlElement signature, byte[] signatureValue, X509Certificate2 certificate)
    {
        Append(signature, "SignatureValue").InnerText = Convert.ToBase64String(signatureValue);
        var keyInfo = Append(signature, "KeyInfo");
        var x509Data = Append(keyInfo, "X509Data");
        Append(x509Data, "X509Certificate").InnerText = Convert.ToBase64String(certificate.RawData);
    }

    /// <summary>The canonical SignedInfo as it stands in the document.</summary>
    internal static byte[] CanonicalSignedInfo(XmlElement signedInfo, string canonicalization) =>
        XadesSignatureBuilder.CanonicalizeElement(signedInfo, canonicalization);

    /// <summary>
    /// The canonical octets of what a Reference covers: <paramref name="element"/> (or the whole document), with
    /// <paramref name="excluded"/> left out when it lies inside it (the enveloped-signature transform).
    /// </summary>
    internal static byte[] CanonicalizeReferenced(
        XmlDocument document, XmlDsigTarget target, XmlElement element, string canonicalization, XmlElement? excluded)
    {
        XmlNode? parent = null;
        XmlNode? next = null;
        if (excluded is not null && IsWithin(excluded, target.IsDocument ? document.DocumentElement! : element))
        {
            parent = excluded.ParentNode!;
            next = excluded.NextSibling;
            parent.RemoveChild(excluded);
        }

        try
        {
            return target.IsDocument
                ? XadesSignatureBuilder.CanonicalizeXml(document, canonicalization)
                : XadesSignatureBuilder.CanonicalizeElement(element, canonicalization);
        }
        finally
        {
            parent?.InsertBefore(excluded!, next);
        }
    }

    /// <summary>The digest of <paramref name="data"/>; SHA-1 is the one the SEFAZ layouts mandate.</summary>
    internal static byte[] Hash(HashAlgorithmName algorithm, byte[] data)
    {
        if (algorithm == HashAlgorithmName.SHA1)
        {
#pragma warning disable CA5350 // SHA-1 is mandated by the SEFAZ layouts (NF-e, CT-e, MDF-e); the signing policy allows it or not
            return SHA1.HashData(data);
#pragma warning restore CA5350
        }

        return SimpleSign.Core.Crypto.CmsSignatureBuilder.ComputeHash(data, algorithm);
    }

    /// <summary>The <c>ds</c> prefix bound to the XML-DSig namespace.</summary>
    internal static XmlNamespaceManager Namespaces(XmlDocument document)
    {
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        return ns;
    }

    /// <summary>The canonicalization algorithms a plain XML-DSig signature may name.</summary>
    internal static bool IsCanonicalization(string algorithm) =>
        algorithm is XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments or XmlDSigUrls.ExcC14N or XmlDSigUrls.ExcC14NWithComments;

    private static bool IsWithin(XmlNode node, XmlNode ancestor)
    {
        for (XmlNode? current = node; current is not null; current = current.ParentNode)
        {
            if (ReferenceEquals(current, ancestor))
            {
                return true;
            }
        }

        return false;
    }

    private static XmlElement Append(XmlElement parent, string name)
    {
        var element = parent.OwnerDocument.CreateElement(name, XmlDSigUrls.DsNamespace);
        parent.AppendChild(element);
        return element;
    }
}
