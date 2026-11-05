using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using SimpleSign.Core.Constants;

namespace SimpleSign.Brasil.Fiscal;

/// <summary>XMLDSig building blocks shared by <see cref="FiscalXmlSigner"/> and <see cref="FiscalXmlValidator"/>.</summary>
internal static class XmlDsig
{
    internal const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

    internal static XmlDocument Load(byte[] xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using var stream = new MemoryStream(xml);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        doc.Load(reader);
        return doc;
    }

    internal static byte[] Save(XmlDocument doc)
    {
        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            OmitXmlDeclaration = doc.FirstChild is not XmlDeclaration,
            Indent = false,
        };
        using (var writer = XmlWriter.Create(stream, settings))
        {
            doc.Save(writer);
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Canonicalizes <paramref name="element"/> as a node-set in its document context: the
    /// namespace declarations of its ancestors are carried over (inclusive C14N renders them),
    /// and, for the enveloped-signature transform, <paramref name="excludedSignature"/> is removed.
    /// </summary>
    internal static byte[] Canonicalize(XmlElement element, string algorithm, XmlElement? excludedSignature = null)
    {
        // Namespaces in scope from the ancestors, nearest first: explicit xmlns attributes and the
        // implicit declarations of DOM-created elements (which carry no xmlns attribute).
        var scope = new Dictionary<string, string>(StringComparer.Ordinal);
        for (XmlNode? ancestor = element.ParentNode; ancestor is XmlElement parent; ancestor = parent.ParentNode)
        {
            foreach (XmlAttribute attribute in parent.Attributes)
            {
                if (attribute.NamespaceURI == XmlnsNamespace)
                {
                    scope.TryAdd(attribute.Prefix == "xmlns" ? attribute.LocalName : string.Empty, attribute.Value);
                }
            }

            scope.TryAdd(parent.Prefix, parent.NamespaceURI);
        }

        // Re-parse the subtree so its own namespace declarations become explicit attributes.
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using (var reader = XmlReader.Create(new StringReader(element.OuterXml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
        {
            doc.Load(reader);
        }

        var clone = doc.DocumentElement!;
        foreach (var (prefix, uri) in scope)
        {
            string name = prefix.Length == 0 ? "xmlns" : "xmlns:" + prefix;
            if (uri.Length == 0 || clone.HasAttribute(name) || (prefix.Length == 0 && clone.Prefix.Length == 0))
            {
                continue; // not in scope, redeclared, or the element defines its own default namespace
            }

            var declaration = doc.CreateAttribute(prefix.Length == 0 ? string.Empty : "xmlns", prefix.Length == 0 ? "xmlns" : prefix, XmlnsNamespace);
            declaration.Value = uri;
            clone.Attributes.Append(declaration);
        }

        if (excludedSignature is not null)
        {
            RemoveEquivalentSignature(clone, excludedSignature);
        }

        Transform transform = algorithm switch
        {
            XmlDSigUrls.C14N => new XmlDsigC14NTransform(),
            XmlDSigUrls.C14NWithComments => new XmlDsigC14NTransform(includeComments: true),
            XmlDSigUrls.ExcC14N => new XmlDsigExcC14NTransform(),
            XmlDSigUrls.ExcC14NWithComments => new XmlDsigExcC14NTransform(includeComments: true),
            _ => throw new NotSupportedException($"Unsupported canonicalization algorithm '{algorithm}'."),
        };
        transform.LoadInput(doc);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    /// <summary>Removes, from the cloned tree, the ds:Signature that is the clone of <paramref name="signature"/>.</summary>
    private static void RemoveEquivalentSignature(XmlElement clone, XmlElement signature)
    {
        string? signatureValue = signature["SignatureValue", XmlDSigUrls.DsNamespace]?.InnerText;
        var ns = new XmlNamespaceManager(clone.OwnerDocument.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        foreach (XmlElement candidate in clone.SelectNodes("descendant-or-self::ds:Signature", ns)!.Cast<XmlElement>().ToList())
        {
            if (candidate["SignatureValue", XmlDSigUrls.DsNamespace]?.InnerText == signatureValue)
            {
                candidate.ParentNode!.RemoveChild(candidate);
            }
        }
    }

    internal static byte[] Hash(HashAlgorithmName algorithm, byte[] data) =>
        algorithm.Name switch
        {
#pragma warning disable CA5350 // SHA-1 is mandated by the SEFAZ layouts (NF-e, CT-e, MDF-e)
            "SHA1" => SHA1.HashData(data),
#pragma warning restore CA5350
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported."),
        };

    internal static string DigestUri(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA1" => XmlDSigUrls.Sha1Digest,
        "SHA256" => XmlDSigUrls.Sha256Digest,
        "SHA384" => XmlDSigUrls.Sha384Digest,
        "SHA512" => XmlDSigUrls.Sha512Digest,
        _ => throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported."),
    };

    internal static string RsaSignatureUri(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA1" => XmlDSigUrls.RsaSha1,
        "SHA256" => XmlDSigUrls.RsaSha256,
        "SHA384" => XmlDSigUrls.RsaSha384,
        "SHA512" => XmlDSigUrls.RsaSha512,
        _ => throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported."),
    };

    internal static HashAlgorithmName? FromDigestUri(string? uri) => uri switch
    {
        XmlDSigUrls.Sha1Digest => HashAlgorithmName.SHA1,
        XmlDSigUrls.Sha256Digest => HashAlgorithmName.SHA256,
        XmlDSigUrls.Sha384Digest => HashAlgorithmName.SHA384,
        XmlDSigUrls.Sha512Digest => HashAlgorithmName.SHA512,
        _ => null,
    };

    internal static HashAlgorithmName? FromRsaSignatureUri(string? uri) => uri switch
    {
        XmlDSigUrls.RsaSha1 => HashAlgorithmName.SHA1,
        XmlDSigUrls.RsaSha256 => HashAlgorithmName.SHA256,
        XmlDSigUrls.RsaSha384 => HashAlgorithmName.SHA384,
        XmlDSigUrls.RsaSha512 => HashAlgorithmName.SHA512,
        _ => null,
    };

    internal static string RsaSignatureOid(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA1" => Oids.RsaSha1,
        "SHA256" => Oids.RsaSha256,
        "SHA384" => Oids.RsaSha384,
        "SHA512" => Oids.RsaSha512,
        _ => throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported."),
    };
}
