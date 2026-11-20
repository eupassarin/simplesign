using System.Security.Cryptography;
using System.Xml;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.TestBench.Runs;

/// <summary>A signed file the Augment tab is about to raise.</summary>
public sealed record AugmentDescribeRequest(string FileId);

/// <summary>What the Augment tab shows about a signed file before raising it: its format and the ICP-Brasil policy it declares.</summary>
/// <param name="Format">pades, cades or xades.</param>
/// <param name="IcpPolicy">The ICP-Brasil policy the (first) signature declares, or null when it declares none.</param>
public sealed record AugmentFacts(string Format, IcpPolicyFacts? IcpPolicy);

/// <summary>
/// The ICP-Brasil policy a signature declares, and what augmenting it does for that policy. The policy is a signed
/// attribute: augmenting never changes it, it can only add what the declared policy requires.
/// </summary>
/// <param name="Name">AD-RB, AD-RT, AD-RV, AD-RC or AD-RA.</param>
/// <param name="Oid">The policy OID in the signature.</param>
/// <param name="Version">The policy version (2.3…), or null.</param>
/// <param name="Format">PAdES, CAdES or XAdES: the format the OID names.</param>
/// <param name="HasSignatureTimestamp">Whether the signature carries a signature time-stamp (the unsigned attribute, not a document time-stamp).</param>
/// <param name="Recommended">The level that brings what the policy requires and the augmenter can add (BT, BLTA), or null.</param>
/// <param name="Notes">What augmenting does for the policy, as codes the UI words: <see cref="AugmentFactsReader"/>.</param>
public sealed record IcpPolicyFacts(string Name, string Oid, string? Version, string Format, bool HasSignatureTimestamp, string? Recommended, IReadOnlyList<string> Notes);

/// <summary>
/// Reads the ICP-Brasil policy a signed file declares (DOC-ICP-15.03) and says what the format's augmenter can do for
/// it. Note codes:
/// <list type="bullet">
/// <item><c>missingSignatureTimestamp</c>: a PAdES AD-RT/AD-RC/AD-RA without the signature time-stamp, which only the signer adds.</item>
/// <item><c>addsSignatureTimestamp</c>: a CAdES/XAdES AD-RT or above without it: B-T adds it.</item>
/// <item><c>needsArchive</c>: PAdES AD-RC/AD-RA need a DSS with VRI and a later document time-stamp: B-LTA adds both.</item>
/// <item><c>pbadArtifacts</c>: PAdES AD-RA also needs the PA and LPA artifacts in the DSS, which the augmenter does not add.</item>
/// <item><c>cadesReferences</c>: CAdES AD-RV/AD-RC need the complete references (and their time-stamp), which the augmenter does not add.</item>
/// <item><c>cadesArchiveV2</c>: CAdES AD-RA needs archive-time-stamp v2; the augmenter adds v3.</item>
/// </list>
/// </summary>
internal static class AugmentFactsReader
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>The facts of <paramref name="content"/>; a file that cannot be read gives no policy.</summary>
    public static async Task<AugmentFacts> DescribeAsync(byte[] content, CancellationToken cancellationToken = default)
    {
        string format = Validation.FormatDetector.Detect(content);
        (string? oid, bool timestamp) = format switch
        {
            RunFormats.Pades => await ReadPdfAsync(content, cancellationToken).ConfigureAwait(false),
            RunFormats.Cades => ReadCms(content),
            _ => ReadXml(content),
        };
        return new AugmentFacts(format, IcpBrasilPolicyInfo.TryParse(oid, out var info) ? Facts(info, timestamp) : null);
    }

    /// <summary>What augmenting does for <paramref name="info"/>, given whether the signature has its time-stamp.</summary>
    internal static IcpPolicyFacts Facts(IcpBrasilPolicyInfo info, bool hasSignatureTimestamp)
    {
        var notes = new List<string>();
        string? recommended = null;
        bool needsTimestamp = info.Policy != IcpBrasilPolicy.AdRb && !hasSignatureTimestamp;
        if (info.Format == IcpBrasilPolicyFormat.Pades)
        {
            if (needsTimestamp)
            {
                notes.Add("missingSignatureTimestamp");
            }

            if (info.Policy is IcpBrasilPolicy.AdRc or IcpBrasilPolicy.AdRa)
            {
                notes.Add("needsArchive");
                recommended = needsTimestamp ? null : "BLTA";
            }

            if (info.Policy == IcpBrasilPolicy.AdRa)
            {
                notes.Add("pbadArtifacts");
            }
        }
        else
        {
            if (needsTimestamp)
            {
                notes.Add("addsSignatureTimestamp");
                recommended = "BT";
            }

            if (info.Format == IcpBrasilPolicyFormat.Cades && info.Policy is IcpBrasilPolicy.AdRv or IcpBrasilPolicy.AdRc)
            {
                notes.Add("cadesReferences");
            }

            if (info.Format == IcpBrasilPolicyFormat.Cades && info.Policy == IcpBrasilPolicy.AdRa)
            {
                notes.Add("cadesArchiveV2");
            }
        }

        return new IcpPolicyFacts(Name(info.Policy), info.Oid, info.Version, FormatName(info.Format), hasSignatureTimestamp, recommended, notes);
    }

    private static async Task<(string? Oid, bool Timestamp)> ReadPdfAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new MemoryStream(pdf, writable: false);
            var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var signatures = inspection.Signatures.Where(s => !s.IsDocumentTimestamp).ToList();
            var signature = signatures.FirstOrDefault(s => IcpBrasilPolicyInfo.TryParse(s.SignaturePolicyOid, out _)) ?? signatures.FirstOrDefault();
            return (signature?.SignaturePolicyOid, signature?.Timestamp is not null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, false);
        }
    }

    private static (string? Oid, bool Timestamp) ReadCms(byte[] cms)
    {
        try
        {
            var signature = CmsParser.Parse(cms);
            return (signature.SignedAttrs is { } attrs ? CmsAttribute.ReadSignaturePolicy(attrs)?.Oid : null, signature.SignatureTimestampToken is not null);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException)
        {
            return (null, false);
        }
    }

    private static (string? Oid, bool Timestamp) ReadXml(byte[] xml)
    {
        try
        {
            var document = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            using (var stream = new MemoryStream(xml, writable: false))
            using (var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            {
                document.Load(reader);
            }

            var ns = new XmlNamespaceManager(document.NameTable);
            ns.AddNamespace("ds", DsNamespace);
            ns.AddNamespace("xades", XadesNamespace);
            if (document.SelectSingleNode("//ds:Signature", ns) is not XmlElement signature)
            {
                return (null, false);
            }

            string? oid = signature.SelectSingleNode(".//xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier", ns)?.InnerText.Trim();
            if (oid?.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase) == true)
            {
                oid = oid["urn:oid:".Length..];
            }

            return (oid, signature.SelectSingleNode(".//xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", ns) is not null);
        }
        catch (XmlException)
        {
            return (null, false);
        }
    }

    private static string Name(IcpBrasilPolicy policy) => policy switch
    {
        IcpBrasilPolicy.AdRb => "AD-RB",
        IcpBrasilPolicy.AdRt => "AD-RT",
        IcpBrasilPolicy.AdRv => "AD-RV",
        IcpBrasilPolicy.AdRc => "AD-RC",
        _ => "AD-RA",
    };

    private static string FormatName(IcpBrasilPolicyFormat format) => format switch
    {
        IcpBrasilPolicyFormat.Cades => "CAdES",
        IcpBrasilPolicyFormat.Xades => "XAdES",
        _ => "PAdES",
    };
}
