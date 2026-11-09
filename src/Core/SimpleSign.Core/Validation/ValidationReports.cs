using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using SimpleSign.Core.Policies;

namespace SimpleSign.Core.Validation;

/// <summary>One signature (or timestamp) of a validation, in the terms the reports need; any format gives one.</summary>
public sealed record SignatureReportEntry
{
    /// <summary>An identifier of the signature in its document: the PDF field name, <c>signer-1</c>, the XML Id…</summary>
    public required string Id { get; init; }

    /// <summary>The format: <c>PAdES</c>, <c>CAdES</c>, <c>XAdES</c>, or <c>Document timestamp</c>.</summary>
    public string? Format { get; init; }

    /// <summary>The indication.</summary>
    public SignatureIndication Indication { get; init; }

    /// <summary>The sub-indication, or null.</summary>
    public SignatureSubIndication? SubIndication { get; init; }

    /// <summary>The checks of the validation.</summary>
    public IReadOnlyList<ValidationConstraintResult> Constraints { get; init; } = [];

    /// <summary>The signing certificate, or null.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>The signing time the signature claims, or null.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>The earliest time the signature is proven to exist (a trusted signature timestamp), or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }

    /// <summary>The validation policy applied.</summary>
    public AppliedPolicy? Policy { get; init; }

    /// <summary>The errors.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>The warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}

/// <summary>
/// Writes the reports of a validation: the signature validation report of ETSI TS 119 102-2 (XML, namespace
/// <c>http://uri.etsi.org/19102/v1.2.1#</c>, with the ETSI indication URIs), and a simple report (JSON) with one
/// entry per signature.
/// </summary>
public static class ValidationReports
{
    /// <summary>The namespace of the ETSI TS 119 102-2 report.</summary>
    public const string EtsiNamespace = "http://uri.etsi.org/19102/v1.2.1#";

    private const string Etsi = "urn:etsi:019102:";

    /// <summary>The ETSI TS 119 102-2 signature validation report of <paramref name="signatures"/>.</summary>
    /// <param name="signatures">The signatures, from <c>ToReportEntry()</c> on the validation results.</param>
    /// <param name="level">The validation level used; it gives the validation process (Basic, LTVM, LTA).</param>
    /// <param name="validationTime">The validation time; now when null.</param>
    /// <returns>The XML document.</returns>
    public static string ToEtsiXml(IEnumerable<SignatureReportEntry> signatures, ValidationLevel level = ValidationLevel.ArchivalData, DateTimeOffset? validationTime = null)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        var list = signatures.ToList();
        var time = (validationTime ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var certificates = new Dictionary<string, X509Certificate2>(StringComparer.Ordinal);

        using var stream = new MemoryStream();
        var settings = new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false) };
        using (var writer = XmlWriter.Create(stream, settings))
        {
            writer.WriteStartDocument();
            writer.WriteStartElement("ValidationReport", EtsiNamespace);
            foreach (var signature in list)
            {
                WriteSignature(writer, signature, level, time, certificates);
            }

            if (certificates.Count > 0)
            {
                writer.WriteStartElement("SignatureValidationObjects", EtsiNamespace);
                foreach (var (id, certificate) in certificates)
                {
                    writer.WriteStartElement("ValidationObject", EtsiNamespace);
                    writer.WriteAttributeString("id", id);
                    writer.WriteElementString("ObjectType", EtsiNamespace, Etsi + "validationObject:certificate");
                    writer.WriteStartElement("ValidationObjectRepresentation", EtsiNamespace);
                    writer.WriteElementString("base64", EtsiNamespace, Convert.ToBase64String(certificate.RawData));
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                }

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
            writer.WriteEndDocument();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteSignature(
        XmlWriter writer, SignatureReportEntry signature, ValidationLevel level, DateTimeOffset time, Dictionary<string, X509Certificate2> certificates)
    {
        writer.WriteStartElement("SignatureValidationReport", EtsiNamespace);

        writer.WriteStartElement("SignatureIdentifier", EtsiNamespace);
        writer.WriteAttributeString("id", XmlId("S-", signature.Id));
        writer.WriteElementString("HashOnly", EtsiNamespace, "false");
        writer.WriteElementString("DocHashOnly", EtsiNamespace, "false");
        writer.WriteElementString("DAIdentifier", EtsiNamespace, signature.Id);
        writer.WriteEndElement();

        if (signature.Constraints.Count > 0)
        {
            writer.WriteStartElement("ValidationConstraintsEvaluationReport", EtsiNamespace);
            foreach (var constraint in signature.Constraints)
            {
                writer.WriteStartElement("ValidationConstraint", EtsiNamespace);
                writer.WriteElementString("ValidationConstraintIdentifier", EtsiNamespace, "urn:simplesign:constraint:" + constraint.Id);
                writer.WriteStartElement("ConstraintStatus", EtsiNamespace);
                writer.WriteElementString("Status", EtsiNamespace,
                    Etsi + (constraint.Status == ConstraintStatus.NotChecked ? "constraintStatus:disabled" : "constraintStatus:applied"));
                writer.WriteEndElement();
                if (constraint.Status != ConstraintStatus.NotChecked)
                {
                    writer.WriteStartElement("ValidationStatus", EtsiNamespace);
                    writer.WriteElementString("MainIndication", EtsiNamespace, Etsi + "mainindication:" + constraint.Status switch
                    {
                        ConstraintStatus.Passed => "passed",
                        ConstraintStatus.Indeterminate => "indeterminate",
                        _ => "failed",
                    });
                    if (constraint.SubIndication is { } sub && constraint.Status != ConstraintStatus.Passed)
                    {
                        writer.WriteElementString("SubIndication", EtsiNamespace, Etsi + "subindication:" + sub.ToEtsiName());
                    }

                    writer.WriteEndElement();
                }

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        writer.WriteStartElement("ValidationTimeInfo", EtsiNamespace);
        writer.WriteElementString("ValidationTime", EtsiNamespace, DateTime(time));
        writer.WriteStartElement("BestSignatureTime", EtsiNamespace);
        writer.WriteElementString("POETime", EtsiNamespace, DateTime(signature.BestSignatureTime ?? time));
        writer.WriteElementString("TypeOfProof", EtsiNamespace, Etsi + "poetype:validation");
        writer.WriteEndElement();
        writer.WriteEndElement();

        if (signature.ClaimedSigningTime is { } signingTime)
        {
            writer.WriteStartElement("SignatureAttributes", EtsiNamespace);
            writer.WriteStartElement("SigningTime", EtsiNamespace);
            writer.WriteAttributeString("Signed", "true");
            writer.WriteElementString("Time", EtsiNamespace, DateTime(signingTime));
            writer.WriteEndElement();
            writer.WriteEndElement();
        }

        if (signature.SignerCertificate is { } signer)
        {
            string id = "C-" + Convert.ToHexString(SHA256.HashData(signer.RawData));
            certificates.TryAdd(id, signer);
            writer.WriteStartElement("SignerInformation", EtsiNamespace);
            writer.WriteStartElement("SignerCertificate", EtsiNamespace);
            writer.WriteAttributeString("VOReference", id);
            writer.WriteEndElement();
            writer.WriteElementString("Signer", EtsiNamespace, signer.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
            writer.WriteEndElement();
        }

        writer.WriteStartElement("SignatureValidationProcess", EtsiNamespace);
        writer.WriteElementString("SignatureValidationProcessID", EtsiNamespace, Etsi + "validationprocess:" + level switch
        {
            ValidationLevel.ArchivalData => "LTA",
            ValidationLevel.LongTermData => "LTVM",
            _ => "Basic",
        });
        if (signature.Policy is { } policy)
        {
            writer.WriteElementString("SignatureValidationServicePolicy", EtsiNamespace, "urn:simplesign:policy:sha256:" + policy.Digest);
        }

        writer.WriteEndElement();

        writer.WriteStartElement("SignatureValidationStatus", EtsiNamespace);
        writer.WriteElementString("MainIndication", EtsiNamespace, Etsi + "mainindication:" + signature.Indication switch
        {
            SignatureIndication.Valid => "total-passed",
            SignatureIndication.Invalid => "total-failed",
            _ => "indeterminate",
        });
        if (signature.SubIndication is { } subIndication)
        {
            writer.WriteElementString("SubIndication", EtsiNamespace, Etsi + "subindication:" + subIndication.ToEtsiName());
        }

        writer.WriteEndElement();
        writer.WriteEndElement();
    }

    /// <summary>
    /// A simple report (JSON) of <paramref name="signatures"/>, with, per
    /// signature its indication, sub-indication, signer, times, policy, errors and warnings, and the counts.
    /// </summary>
    /// <param name="signatures">The signatures.</param>
    /// <param name="validationTime">The validation time; now when null.</param>
    /// <returns>The JSON document.</returns>
    public static string ToSimpleJson(IEnumerable<SignatureReportEntry> signatures, DateTimeOffset? validationTime = null)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        var list = signatures.ToList();
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("validationTime", (validationTime ?? DateTimeOffset.UtcNow).ToUniversalTime());
            writer.WriteNumber("signaturesCount", list.Count);
            writer.WriteNumber("validSignaturesCount", list.Count(s => s.Indication == SignatureIndication.Valid));
            writer.WriteStartArray("signatures");
            foreach (var signature in list)
            {
                writer.WriteStartObject();
                writer.WriteString("id", signature.Id);
                if (signature.Format is { } format)
                {
                    writer.WriteString("format", format);
                }

                writer.WriteString("indication", signature.Indication switch
                {
                    SignatureIndication.Valid => "TOTAL_PASSED",
                    SignatureIndication.Invalid => "TOTAL_FAILED",
                    _ => "INDETERMINATE",
                });
                if (signature.SubIndication is { } sub)
                {
                    writer.WriteString("subIndication", sub.ToEtsiName());
                }

                if (signature.SignerCertificate is { } signer)
                {
                    writer.WriteString("signedBy", signer.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
                }

                if (signature.ClaimedSigningTime is { } claimed)
                {
                    writer.WriteString("signingTime", claimed.ToUniversalTime());
                }

                if (signature.BestSignatureTime is { } best)
                {
                    writer.WriteString("bestSignatureTime", best.ToUniversalTime());
                }

                if (signature.Policy is { } policy)
                {
                    writer.WriteStartObject("policy");
                    if (policy.Name is { } name)
                    {
                        writer.WriteString("name", name);
                    }

                    writer.WriteString("digest", policy.Digest);
                    writer.WriteEndObject();
                }

                WriteStrings(writer, "errors", signature.Errors);
                WriteStrings(writer, "warnings", signature.Warnings);
                WriteStrings(writer, "infos", [.. signature.Constraints.Where(c => c.Status == ConstraintStatus.Information).Select(c => c.Message)]);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteStrings(Utf8JsonWriter writer, string name, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(name);
        foreach (string value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    private static string DateTime(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>An xs:ID from a free identifier: a prefix and the characters an NCName allows.</summary>
    private static string XmlId(string prefix, string value)
    {
        var id = new StringBuilder(prefix);
        foreach (char c in value)
        {
            id.Append(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_');
        }

        return id.ToString();
    }
}
