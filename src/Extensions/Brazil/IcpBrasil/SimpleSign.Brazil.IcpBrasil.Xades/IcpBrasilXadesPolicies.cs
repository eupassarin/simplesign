using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SimpleSign.Brazil.IcpBrasil.Xades;

/// <summary>The ITI's list of XAdES signature policies (<c>LPA_XAdES.xml</c>).</summary>
public static class IcpBrasilXadesPolicies
{
    /// <summary>
    /// Downloads <c>LPA_XAdES.xml</c> from the ITI and updates the XAdES entries of
    /// <see cref="IcpBrasilSignaturePolicies"/>:
    /// <list type="number">
    /// <item>its enveloped XML signature must verify and be made by the ITI, chaining to an ICP-Brasil AC Raiz (not revoked);</item>
    /// <item>known policies take the LPA's signing period and revocation date;</item>
    /// <item>new policies are downloaded, accepted only if the PA file matches the digest in the LPA, and parsed.</item>
    /// </list>
    /// On failure the current catalog is kept.
    /// </summary>
    /// <param name="httpClient">HTTP client for the ITI repository, LCRs and AIA.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The LPA that was applied.</returns>
    /// <exception cref="CryptographicException">The LPA signature or a PA digest does not verify.</exception>
    /// <exception cref="HttpRequestException">A download failed.</exception>
    public static Task<IcpBrasilLpa> RefreshAsync(HttpClient httpClient, CancellationToken cancellationToken = default) =>
        RefreshAsync(httpClient, chainValidator: null, cancellationToken);

    internal static async Task<IcpBrasilLpa> RefreshAsync(
        HttpClient httpClient, IcpBrasilChainValidator? chainValidator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        byte[] lpaBytes = await IcpBrasilSignaturePolicies.DownloadFromRepositoryAsync(httpClient, "LPA_XAdES.xml", cancellationToken).ConfigureAwait(false);
        var (signer, certificates) = VerifyXmlSignature(lpaBytes);
        await IcpBrasilSignaturePolicies.VerifyLpaSignerAsync(signer, certificates, null, httpClient, chainValidator, cancellationToken).ConfigureAwait(false);
        var lpa = IcpBrasilLpa.ParseXml(lpaBytes);
        await IcpBrasilSignaturePolicies.ApplyLpaAsync(lpa, httpClient, xml: true, "LPA_XAdES.xml", cancellationToken).ConfigureAwait(false);
        return lpa;
    }

    private const string WholeDocumentXPath = "not(ancestor-or-self::ds:Signature)";

    /// <summary>
    /// Verifies the enveloped XML signature of an XML LPA with the certificate in its KeyInfo and
    /// returns that certificate. Only the shape the ITI uses is accepted (fail closed): inclusive
    /// C14N of SignedInfo, RSA PKCS#1 v1.5 with SHA-256/512, a reference to the whole document
    /// through the XPath <c>not(ancestor-or-self::ds:Signature)</c>, and optional <c>#id</c>
    /// references to elements of the signature itself (its KeyInfo).
    /// </summary>
    /// <remarks>
    /// SignedXml cannot verify the ITI's LPA: it signs KeyInfo with an enveloped-signature
    /// transform that its signer applied as a no-op, while .NET removes the whole subtree. The
    /// digests are therefore computed here, from the same canonicalization transforms.
    /// </remarks>
    internal static (X509Certificate2 Signer, IReadOnlyList<X509Certificate2> Certificates) VerifyXmlSignature(byte[] lpa)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var stream = new MemoryStream(lpa);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new CryptographicException("The LPA is not well-formed XML.", ex);
        }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        var signatures = doc.SelectNodes("//ds:Signature", ns);
        if (signatures?.Count != 1 || signatures[0] is not XmlElement signature || signature.ParentNode != doc.DocumentElement
            || signature.SelectSingleNode("ds:SignedInfo", ns) is not XmlElement signedInfo)
        {
            throw new CryptographicException("The LPA must carry exactly one enveloped XML signature.");
        }

        // Content inside the signature is outside the document digest: refuse anything but XMLDSig
        // there, so no unsigned list entries can be smuggled in (signature wrapping).
        if (signature.SelectSingleNode($".//*[namespace-uri() != '{SignedXml.XmlDsigNamespaceUrl}']") is not null)
        {
            throw new CryptographicException("The LPA signature contains elements outside the XML-DSig namespace.");
        }

        var certificates = (signature.SelectNodes("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)?.OfType<XmlElement>() ?? [])
            .Select(e => LoadCertificate(Convert.FromBase64String(e.InnerText.Trim())))
            .ToList();
        if (certificates.Count == 0)
        {
            throw new CryptographicException("The LPA signature carries no certificate.");
        }

        bool coversDocument = false;
        foreach (XmlElement reference in signedInfo.SelectNodes("ds:Reference", ns)!.OfType<XmlElement>())
        {
            string uri = reference.GetAttribute("URI");
            var transforms = reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.OfType<XmlElement>().ToList();
            XmlNodeList nodes;
            if (uri.Length == 0)
            {
                if (transforms is not [{ } xpath] || xpath.GetAttribute("Algorithm") != SignedXml.XmlDsigXPathTransformUrl
                    || xpath.SelectSingleNode("ds:XPath", ns)?.InnerText.Trim() != WholeDocumentXPath)
                {
                    throw new CryptographicException("The LPA signature uses an unexpected transform on the document reference.");
                }

                nodes = doc.SelectNodes($"(//. | //@* | //namespace::*)[{WholeDocumentXPath}]", ns)!;
                coversDocument = true;
            }
            else
            {
                if (!uri.StartsWith('#') || transforms.Any(t => t.GetAttribute("Algorithm") != SignedXml.XmlDsigEnvelopedSignatureTransformUrl)
                    || signature.SelectSingleNode($".//*[@Id='{uri[1..].Replace("'", "", StringComparison.Ordinal)}']") is not XmlElement target)
                {
                    throw new CryptographicException($"The LPA signature has an unexpected reference {uri}.");
                }

                nodes = target.SelectNodes("descendant-or-self::node()[not(self::comment())] | descendant-or-self::*/@* | descendant-or-self::*/namespace::*")!;
            }

            byte[] expected = Convert.FromBase64String(reference.SelectSingleNode("ds:DigestValue", ns)?.InnerText.Trim() ?? "");
            byte[] actual = Digest(reference.SelectSingleNode("ds:DigestMethod", ns) as XmlElement, Canonicalize(new XmlDsigC14NTransform(), nodes));
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                throw new CryptographicException($"The LPA reference {(uri.Length == 0 ? "to the document" : uri)} does not match its digest.");
            }
        }

        if (!coversDocument)
        {
            throw new CryptographicException("The LPA signature does not cover the whole document.");
        }

        string? c14n = (signedInfo.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm");
        Transform signedInfoTransform = c14n switch
        {
            SignedXml.XmlDsigC14NTransformUrl => new XmlDsigC14NTransform(),
            SignedXml.XmlDsigC14NWithCommentsTransformUrl => new XmlDsigC14NWithCommentsTransform(),
            _ => throw new CryptographicException($"The LPA signature uses an unexpected canonicalization {c14n}."),
        };
        byte[] signedBytes = Canonicalize(signedInfoTransform,
            signedInfo.SelectNodes("descendant-or-self::node() | descendant-or-self::*/@* | descendant-or-self::*/namespace::*")!);
        HashAlgorithmName hash = (signedInfo.SelectSingleNode("ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm") switch
        {
            SignedXml.XmlDsigRSASHA256Url => HashAlgorithmName.SHA256,
            SignedXml.XmlDsigRSASHA512Url => HashAlgorithmName.SHA512,
            var other => throw new CryptographicException($"The LPA signature uses an unexpected algorithm {other}."),
        };
        byte[] signatureValue = Convert.FromBase64String(signature.SelectSingleNode("ds:SignatureValue", ns)?.InnerText.Trim() ?? "");
        var signer = certificates.FirstOrDefault(c =>
        {
            using var rsa = c.GetRSAPublicKey();
            return rsa is not null && rsa.VerifyData(signedBytes, signatureValue, hash, RSASignaturePadding.Pkcs1);
        }) ?? throw new CryptographicException("The LPA XML signature does not verify.");
        return (signer, certificates);
    }

    private static byte[] Canonicalize(Transform transform, XmlNodeList nodes)
    {
        transform.LoadInput(nodes);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static byte[] Digest(XmlElement? method, byte[] data) => method?.GetAttribute("Algorithm") switch
    {
        SignedXml.XmlDsigSHA256Url => SHA256.HashData(data),
        SignedXml.XmlDsigSHA512Url => SHA512.HashData(data),
        var other => throw new CryptographicException($"The LPA signature uses an unexpected digest {other}."),
    };

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif
}
