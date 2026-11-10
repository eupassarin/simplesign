using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using SimpleSign.Core.Validation;

namespace SimpleSign.TestBench.Reports;

/// <summary>
/// One signature as the library reported it (<c>ToReportEntry()</c>), with the certificates found next to it (the
/// certificates embedded in the file), from which the report writes the signer's chain.
/// </summary>
public sealed record ReportSource(SignatureReportEntry Entry, IReadOnlyList<X509Certificate2> Certificates);

/// <summary>
/// The JSON report of a SimpleSign validation: the library's simple report (<see cref="ValidationReports.ToSimpleJson"/>,
/// what <c>simplesign validate --simple-report</c> writes), with what the TestBench adds to each signature so the report
/// viewer can explain it: every constraint result of the policy (<c>constraints</c>) and the signer's chain
/// (<c>certificates</c>).
/// </summary>
internal static class SimpleSignReport
{
    /// <summary>The <c>generator</c> of the report: tells it apart from a DSS report.</summary>
    public const string Generator = "SimpleSign TestBench";

    /// <summary>The report of <paramref name="sources"/>, as indented JSON.</summary>
    /// <param name="sources">The signatures, in document order.</param>
    /// <param name="document">The name of the validated file.</param>
    /// <param name="pool">More certificates to build chains from (the file's own, the trusted roots).</param>
    /// <param name="validationTime">The validation time; now when null.</param>
    public static string Build(IReadOnlyList<ReportSource> sources, string? document, IReadOnlyList<X509Certificate2> pool, DateTimeOffset? validationTime = null)
    {
        var root = JsonNode.Parse(ValidationReports.ToSimpleJson(sources.Select(s => s.Entry), validationTime))!.AsObject();
        root.Insert(0, "generator", Generator);
        if (document is not null)
        {
            root.Insert(1, "document", document);
        }

        var signatures = root["signatures"]!.AsArray();
        for (int i = 0; i < sources.Count && i < signatures.Count; i++)
        {
            var source = sources[i];
            var signature = signatures[i]!.AsObject();
            IReadOnlyList<X509Certificate2> known = [.. source.Certificates, .. pool];
            signature["certificates"] = new JsonArray([.. Chain(source.Entry.SignerCertificate, known).Select(Certificate)]);
            signature["constraints"] = new JsonArray([.. source.Entry.Constraints.Select(Constraint)]);
            Describe(signature["timestamps"]?.AsArray(), [.. source.Entry.ValidationObjects.Where(o => o.Type == ValidationObjectType.Timestamp)], known);
            Describe(signature["revocationData"]?.AsArray(), [.. source.Entry.ValidationObjects.Where(o => o.Type != ValidationObjectType.Timestamp)], known);
        }

        return root.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Adds to each timestamp or revocation entry of the simple report (written in the order of <paramref name="objects"/>)
    /// what its DER says: the TSA of a timestamp; the issuer, dates, certificate and status of a CRL or OCSP response.
    /// </summary>
    private static void Describe(JsonArray? entries, IReadOnlyList<ValidationObjectEntry> objects, IReadOnlyList<X509Certificate2> known)
    {
        for (int j = 0; entries is not null && j < entries.Count && j < objects.Count; j++)
        {
            var entry = entries[j]!.AsObject();
            var o = objects[j];
            if (o.Type == ValidationObjectType.Timestamp)
            {
                if (ValidationObjectFacts.TimestampSigner(o.Data) is { } tsa)
                {
                    entry["producedBy"] = tsa.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                }

                continue;
            }

            if ((o.Type == ValidationObjectType.Crl ? ValidationObjectFacts.Crl(o.Data) : ValidationObjectFacts.Ocsp(o.Data)) is not { } facts)
            {
                continue;
            }

            Set(entry, "issuer", facts.Issuer);
            Set(entry, "producedAt", Time(facts.ProducedAt));
            Set(entry, "thisUpdate", Time(facts.ThisUpdate));
            Set(entry, "nextUpdate", Time(facts.NextUpdate));
            Set(entry, "status", facts.Status);
            if (facts.Serial is { } serial && known.FirstOrDefault(c => new System.Numerics.BigInteger(c.SerialNumberBytes.Span, isUnsigned: true, isBigEndian: true) == serial) is { } about)
            {
                entry["certificate"] = about.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            }
        }

        static void Set(JsonObject entry, string name, string? value)
        {
            if (value is not null)
            {
                entry[name] = value;
            }
        }
    }

    private static string? Time(DateTimeOffset? time) =>
        time?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>
    /// The chain of <paramref name="signer"/> as far as <paramref name="pool"/> goes: each certificate followed by the one
    /// that issued it (by name, and by signature when several have that name), up to a self-signed one.
    /// </summary>
    internal static IReadOnlyList<X509Certificate2> Chain(X509Certificate2? signer, IReadOnlyList<X509Certificate2> pool)
    {
        if (signer is null)
        {
            return [];
        }

        var chain = new List<X509Certificate2> { signer };
        var current = signer;
        while (!SelfSigned(current) && chain.Count < 10)
        {
            var issuer = pool.Where(c => c.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData)
                    && !chain.Any(seen => seen.RawData.AsSpan().SequenceEqual(c.RawData)))
                .OrderByDescending(c => Signs(c, current))
                .FirstOrDefault();
            if (issuer is null)
            {
                break;
            }

            chain.Add(issuer);
            current = issuer;
        }

        return chain;
    }

    /// <summary>The certificates a CMS signature or an XML signature carries (none for anything else).</summary>
    internal static IReadOnlyList<X509Certificate2> CertificatesIn(byte[] content)
    {
        if (content.Length > 0 && content[0] == 0x30)
        {
            try
            {
                return Core.Crypto.CmsParser.ParseAll(content).Certificates;
            }
            catch (Exception ex) when (ex is CryptographicException or System.Formats.Asn1.AsnContentException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
            {
                return [];
            }
        }

        if (content.AsSpan().IndexOf("X509Certificate"u8) < 0)
        {
            return [];
        }

        var found = new List<X509Certificate2>();
        try
        {
            var xml = new XmlDocument { XmlResolver = null };
            using (var reader = XmlReader.Create(new MemoryStream(content), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            {
                xml.Load(reader);
            }

            foreach (XmlElement element in xml.GetElementsByTagName("X509Certificate", "http://www.w3.org/2000/09/xmldsig#").OfType<XmlElement>()
                         .Concat(xml.GetElementsByTagName("EncapsulatedX509Certificate", "http://uri.etsi.org/01903/v1.3.2#").OfType<XmlElement>()))
            {
                try
                {
                    found.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(element.InnerText.Trim())));
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                {
                    // Not a certificate: left out of the chain.
                }
            }
        }
        catch (XmlException)
        {
            return [];
        }

        return found;
    }

    private static bool SelfSigned(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);

    /// <summary>Whether <paramref name="issuer"/>'s key verifies <paramref name="certificate"/> (RSA and ECDSA).</summary>
    private static bool Signs(X509Certificate2 issuer, X509Certificate2 certificate)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(issuer);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            chain.ChainPolicy.VerificationTime = certificate.NotBefore.AddSeconds(1);
            return chain.Build(certificate) || chain.ChainElements.Count > 1 && chain.ChainElements[1].Certificate.RawData.AsSpan().SequenceEqual(issuer.RawData);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static JsonObject Certificate(X509Certificate2 c) => new()
    {
        ["subject"] = c.Subject,
        ["issuer"] = c.Issuer,
        ["serialNumber"] = c.SerialNumber,
        ["notBefore"] = c.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        ["notAfter"] = c.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        ["selfSigned"] = SelfSigned(c),
        ["sha256"] = Convert.ToHexString(SHA256.HashData(c.RawData)),
    };

    private static JsonObject Constraint(ValidationConstraintResult c)
    {
        var node = new JsonObject
        {
            ["id"] = c.Id,
            ["status"] = c.Status.ToString(),
            ["message"] = c.Message,
        };
        if (c.SubIndication is { } sub)
        {
            node["subIndication"] = sub.ToEtsiName();
        }

        return node;
    }

    /// <summary>A file name for the report of <paramref name="fileName"/>.</summary>
    public static string FileName(string? fileName) =>
        new StringBuilder(Path.GetFileNameWithoutExtension(fileName is { Length: > 0 } ? fileName : "signature")).Append(".simplesign-report.json").ToString();
}
