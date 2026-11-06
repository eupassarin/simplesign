using System.Security.Cryptography;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

internal static partial class XadesSignatureBuilder
{
    internal static byte[] EmbedArchiveTimeStamp(byte[] signedXml, byte[] tsToken) =>
        EmbedArchiveTimeStamp(signedXml, tsToken, signatureId: null);

    /// <summary>Embeds an archive timestamp in the signature identified by <paramref name="signatureId"/>.</summary>
    internal static byte[] EmbedArchiveTimeStamp(byte[] signedXml, byte[] tsToken, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);

        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        var unsignedProps = EnsureUnsignedSignatureProperties(doc, signature, ns);

        var atsElement = doc.CreateElement("ArchiveTimeStamp", XadesUris.Xades141Namespace);
        atsElement.SetAttribute("Id", XadesUris.ArchiveTimeStampIdPrefix + Guid.NewGuid().ToString("N")[..8]);
        var canonicalizationMethod = doc.CreateElement("CanonicalizationMethod", XmlDSigUrls.DsNamespace);
        canonicalizationMethod.SetAttribute("Algorithm", XmlDSigUrls.ExcC14N);
        atsElement.AppendChild(canonicalizationMethod);
        // xades141:ArchiveTimeStamp is of type xades:XAdESTimeStampType (ETSI EN 319 132-1 §5.5.2.1), so its
        // children are in the XAdES v1.3.2 namespace. Other validators do not find the token otherwise.
        var encElement = doc.CreateElement("EncapsulatedTimeStamp", XadesUris.XadesNamespace);
        encElement.InnerText = Convert.ToBase64String(tsToken);
        atsElement.AppendChild(encElement);
        unsignedProps.AppendChild(atsElement);

        using var ms = new MemoryStream();
        doc.Save(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Builds the ArchiveTimeStamp input specified by ETSI EN 319 132-1 §5.5.2.2 or §5.5.2.3.
    /// </summary>
    /// <remarks>
    /// The current ArchiveTimeStamp must already be present in the signature so that this method can
    /// delimit the preceding unsigned properties. The ArchiveTimeStamp itself is deliberately excluded.
    /// </remarks>
    internal static byte[] CreateArchiveTimeStampInput(
        byte[] signedXml,
        byte[]? detachedData = null,
        string? signatureId = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature = ResolveSignature(doc, ns, signatureId);

        XmlElement archiveTimeStamp = FindLatestArchiveTimeStamp(signature, ns)
            ?? throw new InvalidOperationException("ArchiveTimeStamp element not found.");
        string canonicalizationAlgorithm = ValidateArchiveCanonicalization(archiveTimeStamp, ns);

        var octets = new List<byte[]>();
        var references = signature.SelectNodes("ds:SignedInfo/ds:Reference", ns);
        if (references is not null)
        {
            foreach (XmlElement reference in references)
            {
                string uri = reference.GetAttribute("URI");
                octets.Add(ProcessArchiveReference(doc, reference, uri, detachedData, canonicalizationAlgorithm));
            }
        }

        if (signature.SelectSingleNode("ds:SignedInfo", ns) is not XmlElement signedInfo ||
            signature.SelectSingleNode("ds:SignatureValue", ns) is not XmlElement signatureValue)
        {
            throw new InvalidOperationException("Signature is missing SignedInfo or SignatureValue.");
        }

        octets.Add(CanonicalizeElement(signedInfo, canonicalizationAlgorithm));
        octets.Add(CanonicalizeElement(signatureValue, canonicalizationAlgorithm));
        if (signature.SelectSingleNode("ds:KeyInfo", ns) is XmlElement keyInfo)
        {
            octets.Add(CanonicalizeElement(keyInfo, canonicalizationAlgorithm));
        }

        if (archiveTimeStamp.SelectSingleNode("xades:Include | xades141:Include", ns) is not null)
        {
            AppendDistributedUnsignedProperties(
                octets,
                doc,
                archiveTimeStamp,
                ns,
                canonicalizationAlgorithm);
        }
        else
        {
            AppendPrecedingUnsignedProperties(octets, signature, archiveTimeStamp, ns, canonicalizationAlgorithm);
        }

        AppendUnreferencedObjects(octets, signature, ns, canonicalizationAlgorithm);
        return Concatenate(octets);
    }

    /// <summary>Extracts the most recent archive timestamp token from a signed XAdES document.</summary>
    internal static byte[]? ExtractArchiveTimeStamp(byte[] signedXml, string? signatureId = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.Load(new MemoryStream(signedXml));
        var ns = CreateNamespaceManager(doc);
        XmlElement signature;
        try
        {
            signature = ResolveSignature(doc, ns, signatureId);
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        if (FindLatestArchiveTimeStamp(signature, ns) is not XmlElement archiveTimeStamp)
        {
            return null;
        }

        // The v1.4.1 form is read too: older SimpleSign versions wrote it.
        XmlNode? encapsulated = archiveTimeStamp.SelectSingleNode("xades:EncapsulatedTimeStamp", ns) ??
            archiveTimeStamp.SelectSingleNode("xades141:EncapsulatedTimeStamp", ns);
        return encapsulated is null ? null : Convert.FromBase64String(encapsulated.InnerText.Trim());
    }

    /// <summary>Verifies the archive timestamp message imprint against the ETSI-defined preimage.</summary>
    internal static bool ValidateArchiveTimeStamp(
        byte[] signedXml,
        byte[]? detachedData,
        List<string> warnings,
        string? signatureId = null)
    {
        try
        {
            byte[]? token = ExtractArchiveTimeStamp(signedXml, signatureId);
            if (token is null)
            {
                warnings.Add("XAdES-B-LTA: ArchiveTimeStamp does not contain an EncapsulatedTimeStamp.");
                return false;
            }

            if (!TimestampValidator.VerifyTokenSignature(token))
            {
                warnings.Add("XAdES-B-LTA: ArchiveTimeStamp token CMS signature is invalid.");
                return false;
            }

            CmsSignedData timestamp = CmsParser.Parse(token);
            HashAlgorithmName hashAlgorithm = GetTimestampHashAlgorithm(timestamp.TstMessageImprintHashAlgOid);
            byte[] input = CreateArchiveTimeStampInput(signedXml, detachedData, signatureId);
            TimestampClient.ValidateTimestampToken(token, input, hashAlgorithm);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or FormatException or CryptographicException or
            InvalidOperationException or TimestampException or NotSupportedException)
        {
            warnings.Add($"XAdES-B-LTA: ArchiveTimeStamp validation failed: {ex.Message}");
            return false;
        }
    }

    private static XmlNamespaceManager CreateNamespaceManager(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        return ns;
    }

    private static XmlElement? FindLatestArchiveTimeStamp(XmlElement signature, XmlNamespaceManager ns)
    {
        XmlNodeList? nodes = signature.SelectNodes(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
            "xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp | " +
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/" +
            "xades:UnsignedSignatureProperties/xades:ArchiveTimeStamp", ns);
        return nodes is { Count: > 0 } ? nodes[nodes.Count - 1] as XmlElement : null;
    }

    private static XmlElement ResolveSignature(
        XmlDocument doc,
        XmlNamespaceManager ns,
        string? signatureId)
    {
        XmlNodeList? signatures = doc.SelectNodes("//ds:Signature", ns);
        if (signatures is null || signatures.Count == 0)
        {
            throw new InvalidOperationException("Signature element not found.");
        }

        if (!string.IsNullOrWhiteSpace(signatureId))
        {
            foreach (XmlElement candidate in signatures)
            {
                if (string.Equals(candidate.GetAttribute("Id"), signatureId, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }

            throw new InvalidOperationException($"Signature '{signatureId}' was not found.");
        }

        if (signatures.Count != 1 || signatures[0] is not XmlElement signature)
        {
            throw new NotSupportedException(
                "An ArchiveTimeStamp operation on a multi-signature document must identify the target signature.");
        }

        return signature;
    }

    private static string ValidateArchiveCanonicalization(XmlElement archiveTimeStamp, XmlNamespaceManager ns)
    {
        if (archiveTimeStamp.SelectSingleNode("ds:CanonicalizationMethod", ns) is not XmlElement method)
        {
            throw new NotSupportedException("ArchiveTimeStamp must declare its canonicalization algorithm.");
        }

        string algorithm = method.GetAttribute("Algorithm");
        if (algorithm is not XmlDSigUrls.ExcC14N and not XmlDSigUrls.ExcC14NWithComments and
            not XmlDSigUrls.C14N and not XmlDSigUrls.C14NWithComments)
        {
            throw new NotSupportedException($"Unsupported ArchiveTimeStamp canonicalization algorithm '{algorithm}'.");
        }

        return algorithm;
    }

    private static byte[] ProcessArchiveReference(
        XmlDocument doc,
        XmlElement reference,
        string uri,
        byte[]? detachedData,
        string canonicalizationAlgorithm)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(doc);
        string referenceCanonicalizationAlgorithm = GetReferenceCanonicalizationAlgorithm(
            reference,
            ns,
            canonicalizationAlgorithm);

        if (uri.Length == 0)
        {
            var clone = (XmlDocument)doc.CloneNode(true);
            return ApplyReferenceTransforms(clone, clone.DocumentElement!, reference, referenceCanonicalizationAlgorithm);
        }

        if (uri.StartsWith('#'))
        {
            XmlElement target = FindElementByBareNameId(doc, uri, "Archive reference");

            return ApplyReferenceTransforms(doc, target, reference, referenceCanonicalizationAlgorithm);
        }

        if (detachedData is null)
        {
            throw new InvalidOperationException("Detached data is required to validate an external archive reference.");
        }

        if (HasTransform(reference, XmlDSigUrls.Base64Transform, ns))
        {
            return Convert.FromBase64String(Encoding.UTF8.GetString(detachedData).Trim());
        }

        XmlNodeList? detachedTransforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (detachedTransforms is null || detachedTransforms.Count == 0)
        {
            // An external XMLDSig reference without transforms produces the resource octets as-is.
            return detachedData;
        }

        var detachedDocument = new XmlDocument { PreserveWhitespace = true };
        detachedDocument.Load(new MemoryStream(detachedData));
        return ApplyReferenceTransforms(
            detachedDocument,
            detachedDocument.DocumentElement!,
            reference,
            referenceCanonicalizationAlgorithm);
    }

    private static void AppendPrecedingUnsignedProperties(
        List<byte[]> octets,
        XmlElement signature,
        XmlElement archiveTimeStamp,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        if (signature.SelectSingleNode(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties", ns)
            is not XmlElement unsignedProperties)
        {
            throw new InvalidOperationException("ArchiveTimeStamp has no UnsignedSignatureProperties parent.");
        }

        foreach (XmlNode node in unsignedProperties.ChildNodes)
        {
            if (ReferenceEquals(node, archiveTimeStamp))
            {
                break;
            }

            if (node is XmlElement property)
            {
                // EN 319 132-1 covers every preceding unsigned signature property, including
                // TimeStampValidationData, in document order.
                octets.Add(CanonicalizeElement(property, canonicalizationAlgorithm));
            }
        }
    }

    /// <summary>
    /// Appends the explicitly listed unsigned qualifying properties for the distributed
    /// ArchiveTimeStamp construction in ETSI EN 319 132-1 §5.5.2.3.
    /// </summary>
    /// <remarks>
    /// The generic XAdES Include processing model removes comments from the referenced node set
    /// before canonicalization. This implementation deliberately supports only same-document,
    /// bare-name references: resolving an external URI would introduce network and document-base
    /// semantics into archive validation and must be supplied by a future explicit resolver API.
    /// </remarks>
    private static void AppendDistributedUnsignedProperties(
        List<byte[]> octets,
        XmlDocument document,
        XmlElement archiveTimeStamp,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        XmlNodeList? includes = archiveTimeStamp.SelectNodes("xades:Include | xades141:Include", ns);
        if (includes is null || includes.Count == 0)
        {
            throw new InvalidOperationException("Distributed ArchiveTimeStamp has no Include elements.");
        }

        var includedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (XmlElement include in includes)
        {
            string uri = include.GetAttribute("URI");
            XmlElement property = FindElementByBareNameId(document, uri, "ArchiveTimeStamp Include");
            string id = GetElementId(property);
            if (!includedIds.Add(id))
            {
                throw new InvalidOperationException($"ArchiveTimeStamp Include '{uri}' is duplicated.");
            }

            if (!IsUnsignedSignatureQualifyingProperty(property) || ReferenceEquals(property, archiveTimeStamp))
            {
                throw new InvalidOperationException(
                    $"ArchiveTimeStamp Include '{uri}' must reference an unsigned signature qualifying property.");
            }

            if (include.HasAttribute("referencedData"))
            {
                throw new NotSupportedException(
                    "ArchiveTimeStamp Include referencedData is valid only for ds:Reference targets, " +
                    "which ETSI forbids for a distributed ArchiveTimeStamp.");
            }

            octets.Add(CanonicalizeElementWithoutComments(property, canonicalizationAlgorithm));
        }
    }

    private static XmlElement FindElementByBareNameId(XmlDocument document, string uri, string referenceKind)
    {
        if (string.IsNullOrWhiteSpace(uri) || uri[0] != '#' || uri.Length == 1 || uri.IndexOf('#', 1) >= 0)
        {
            throw new NotSupportedException(
                $"{referenceKind} URI '{uri}' must be a same-document bare-name reference.");
        }

        string id = Uri.UnescapeDataString(uri[1..]);
        XmlNodeList? elements = document.SelectNodes("//*");
        if (elements is not null)
        {
            foreach (XmlElement candidate in elements.OfType<XmlElement>())
            {
                if (string.Equals(GetElementId(candidate), id, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }
        }

        throw new InvalidOperationException($"{referenceKind} target '{uri}' was not found.");
    }

    private static string GetElementId(XmlElement element)
    {
        string id = element.GetAttribute("Id");
        return id.Length != 0 ? id : element.GetAttribute("id", "http://www.w3.org/XML/1998/namespace");
    }

    private static bool IsUnsignedSignatureQualifyingProperty(XmlElement element) =>
        element.ParentNode is XmlElement parent &&
        parent.LocalName == "UnsignedSignatureProperties" &&
        parent.NamespaceURI == XadesUris.XadesNamespace;

    private static void AppendUnreferencedObjects(
        List<byte[]> octets,
        XmlElement signature,
        XmlNamespaceManager ns,
        string canonicalizationAlgorithm)
    {
        XmlNodeList? objects = signature.SelectNodes("ds:Object", ns);
        if (objects is null)
        {
            return;
        }

        foreach (XmlElement element in objects)
        {
            if (element.SelectSingleNode("xades:QualifyingProperties", ns) is not null)
            {
                continue;
            }

            // EN 319 132-1 includes every ds:Object other than QualifyingProperties.
            // Reference status only changed the pre-v1.4.1 construction.
            octets.Add(CanonicalizeElement(element, canonicalizationAlgorithm));
        }
    }

    private static byte[] ApplyReferenceTransforms(
        XmlDocument owner,
        XmlElement target,
        XmlElement reference,
        string canonicalizationAlgorithm)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(owner);
        ValidateSupportedReferenceTransforms(reference, ns);
        if (HasTransform(reference, XmlDSigUrls.Base64Transform, ns))
        {
            return Convert.FromBase64String(target.InnerText.Trim());
        }

        XmlDocument working = new() { PreserveWhitespace = true };
        working.AppendChild(working.ImportNode(target, true));
        if (HasTransform(reference, XmlDSigUrls.EnvelopedSignatureTransform, ns) ||
            HasSignatureExclusionXPath(reference, ns))
        {
            RemoveSignatureElements(working);
        }

        return CanonicalizeXml(working, canonicalizationAlgorithm);
    }

    private static bool HasTransform(XmlElement reference, string algorithm, XmlNamespaceManager ns) =>
        reference.SelectSingleNode($"ds:Transforms/ds:Transform[@Algorithm='{algorithm}']", ns) is not null;

    /// <summary>
    /// Rejects reference transforms whose archive-time-stamp processing is not implemented.
    /// </summary>
    /// <remarks>
    /// Archive validation must never silently omit a transform from the XMLDSig reference
    /// pipeline. The supported subset covers the enveloped XAdES topology produced by this
    /// library and the externally supplied ETSI vectors: base64, enveloped-signature,
    /// the signature-exclusion XPath, and XML canonicalization variants.
    /// </remarks>
    private static void ValidateSupportedReferenceTransforms(XmlElement reference, XmlNamespaceManager ns)
    {
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null || transforms.Count == 0)
        {
            return;
        }

        bool hasBase64 = false;
        foreach (XmlElement transform in transforms)
        {
            string algorithm = transform.GetAttribute("Algorithm");
            if (algorithm == XmlDSigUrls.Base64Transform)
            {
                hasBase64 = true;
                continue;
            }

            if (algorithm is XmlDSigUrls.EnvelopedSignatureTransform or XmlDSigUrls.ExcC14N or
                XmlDSigUrls.ExcC14NWithComments or XmlDSigUrls.C14N or XmlDSigUrls.C14NWithComments)
            {
                continue;
            }

            if (algorithm == XmlDSigUrls.XPathTransform &&
                transform.SelectSingleNode("ds:XPath", ns)?.InnerText.Trim() ==
                    "not(ancestor-or-self::ds:Signature)")
            {
                continue;
            }

            throw new NotSupportedException($"Unsupported XMLDSig archive reference transform '{algorithm}'.");
        }

        if (hasBase64 && transforms.Count != 1)
        {
            throw new NotSupportedException(
                "The base64 XMLDSig archive reference transform is supported only as the sole transform.");
        }
    }

    private static string GetReferenceCanonicalizationAlgorithm(
        XmlElement reference,
        XmlNamespaceManager ns,
        string archiveCanonicalizationAlgorithm)
    {
        ValidateSupportedReferenceTransforms(reference, ns);
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null || transforms.Count == 0)
        {
            return archiveCanonicalizationAlgorithm;
        }

        string? referenceCanonicalizationAlgorithm = null;
        for (int index = 0; index < transforms.Count; index++)
        {
            var transform = (XmlElement)transforms[index]!;
            string algorithm = transform.GetAttribute("Algorithm");
            if (algorithm is not XmlDSigUrls.ExcC14N and not XmlDSigUrls.ExcC14NWithComments and
                not XmlDSigUrls.C14N and not XmlDSigUrls.C14NWithComments)
            {
                continue;
            }

            if (index != transforms.Count - 1)
            {
                throw new NotSupportedException(
                    "An XMLDSig canonicalization transform must be the final archive reference transform.");
            }

            referenceCanonicalizationAlgorithm = algorithm;
        }

        return referenceCanonicalizationAlgorithm ?? archiveCanonicalizationAlgorithm;
    }

    private static bool HasSignatureExclusionXPath(XmlElement reference, XmlNamespaceManager ns)
    {
        XmlNodeList? transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns);
        if (transforms is null)
        {
            return false;
        }

        foreach (XmlElement transform in transforms)
        {
            if (transform.GetAttribute("Algorithm") == XmlDSigUrls.XPathTransform &&
                transform.SelectSingleNode("ds:XPath", ns)?.InnerText.Trim() == "not(ancestor-or-self::ds:Signature)")
            {
                return true;
            }
        }

        return false;
    }

    private static void RemoveSignatureElements(XmlDocument document)
    {
        XmlNamespaceManager ns = CreateNamespaceManager(document);
        XmlNodeList? signatures = document.SelectNodes("//ds:Signature", ns);
        if (signatures is null)
        {
            return;
        }

        for (int i = signatures.Count - 1; i >= 0; i--)
        {
            XmlNode signature = signatures[i]!;
            signature.ParentNode!.RemoveChild(signature);
        }
    }

    private static byte[] CanonicalizeElement(XmlElement element, string canonicalizationAlgorithm = XmlDSigUrls.ExcC14N)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.AppendChild(document.ImportNode(element, true));
        return CanonicalizeXml(document, canonicalizationAlgorithm);
    }

    private static byte[] CanonicalizeElementWithoutComments(XmlElement element, string canonicalizationAlgorithm)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.AppendChild(document.ImportNode(element, true));
        RemoveCommentNodes(document);
        return CanonicalizeXml(document, canonicalizationAlgorithm);
    }

    private static void RemoveCommentNodes(XmlNode node)
    {
        for (int index = node.ChildNodes.Count - 1; index >= 0; index--)
        {
            XmlNode child = node.ChildNodes[index]!;
            if (child.NodeType == XmlNodeType.Comment)
            {
                node.RemoveChild(child);
                continue;
            }

            RemoveCommentNodes(child);
        }
    }

    private static HashAlgorithmName GetTimestampHashAlgorithm(string? hashAlgorithmOid) => hashAlgorithmOid switch
    {
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => throw new NotSupportedException($"ArchiveTimeStamp uses unsupported digest '{hashAlgorithmOid}'.")
    };

    private static byte[] Concatenate(IReadOnlyList<byte[]> values)
    {
        int length = values.Sum(value => value.Length);
        var output = new byte[length];
        int offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }

        return output;
    }
}
