using System.Text.Json;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Policies;

namespace SimpleSign.TestBench.Reports;

/// <summary>A validation report (SimpleSign's or DSS's), read for the report viewer.</summary>
/// <param name="Source"><c>simplesign</c> or <c>dss</c>.</param>
/// <param name="Document">The name of the validated file.</param>
/// <param name="ValidationTime">When the validation was made.</param>
/// <param name="Policy">The name of the validation policy applied.</param>
/// <param name="Signatures">The signatures (and document timestamps), in document order.</param>
public sealed record ReportView(string Source, string? Document, string? ValidationTime, string? Policy, IReadOnlyList<ReportSignature> Signatures);

/// <summary>One signature of a report, explained.</summary>
/// <param name="Id">Its identifier in the report.</param>
/// <param name="Kind"><c>signature</c>, <c>counterSignature</c> or <c>timestamp</c> (a document timestamp).</param>
/// <param name="Format">The format and level, as the report gives it.</param>
/// <param name="Indication"><c>Valid</c>, <c>Invalid</c> or <c>Indeterminate</c>.</param>
/// <param name="EtsiIndication">The ETSI indication: TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE.</param>
/// <param name="SubIndication">The ETSI sub-indication, or null.</param>
/// <param name="Explanation">The indication and sub-indication in plain words.</param>
/// <param name="SignedBy">The signer's name.</param>
/// <param name="SigningTime">The signing time the signature claims (or a timestamp's time).</param>
/// <param name="BestSignatureTime">The earliest time the signature is proven to exist.</param>
/// <param name="Chain">The signer's certificate first, then each issuer.</param>
/// <param name="Timestamps">The timestamps over the signature.</param>
/// <param name="Revocation">The revocation data the validation used.</param>
/// <param name="Constraints">The checks, one per check and outcome, failures first.</param>
/// <param name="Errors">The errors the validator gave.</param>
/// <param name="Warnings">The warnings the validator gave.</param>
/// <param name="Infos">The information messages the validator gave.</param>
public sealed record ReportSignature(
    string Id,
    string Kind,
    string? Format,
    string Indication,
    string EtsiIndication,
    string? SubIndication,
    string Explanation,
    string? SignedBy,
    string? SigningTime,
    string? BestSignatureTime,
    IReadOnlyList<ReportCertificate> Chain,
    IReadOnlyList<ReportTimestamp> Timestamps,
    IReadOnlyList<ReportRevocation> Revocation,
    IReadOnlyList<ReportConstraint> Constraints,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Infos);

/// <summary>A certificate of a chain. <paramref name="Trusted"/>: a trust anchor (null when the report does not say).</summary>
public sealed record ReportCertificate(string Name, string? Subject, string? Issuer, string? SerialNumber, string? NotBefore, string? NotAfter, bool SelfSigned, bool? Trusted, string? RevocationStatus);

/// <summary>A timestamp over a signature, with its own outcome.</summary>
public sealed record ReportTimestamp(string? Time, string? Type, string? ProducedBy, string? Indication, string? SubIndication);

/// <summary>A CRL or OCSP response the validation used, and whom it is about.</summary>
public sealed record ReportRevocation(string Type, string? Indication, string? SubIndication, string? ProducedAt, string? ThisUpdate, string? NextUpdate, string? Origin, string? Url, string? Certificate, string? Status)
{
    /// <summary>Who issued it: the CRL issuer or the OCSP responder.</summary>
    public string? Issuer { get; init; }
}

/// <summary>
/// One check and its outcome: <paramref name="Status"/> is <c>pass</c>, <c>warn</c>, <c>fail</c>, <c>info</c> or <c>skip</c>;
/// <paramref name="Title"/> says in plain words what it checks; <paramref name="Messages"/> are what it found, once each.
/// </summary>
public sealed record ReportConstraint(string Key, string Title, string? Standard, string Status, IReadOnlyList<string> Messages, int Count);

/// <summary>Reads a stored validation report, SimpleSign's (<see cref="SimpleSignReport"/>) or DSS's (its REST answer), for the report viewer.</summary>
internal static class ReportReader
{
    private static readonly string[] s_messageKinds = ["Error", "Warning", "Info"];

    /// <summary>The report in <paramref name="json"/>, or null when it is neither SimpleSign's nor DSS's.</summary>
    public static ReportView? Read(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (Property(root, "SimpleReport") is { ValueKind: JsonValueKind.Object })
        {
            return ReadDss(root);
        }

        return Property(root, "signatures") is { ValueKind: JsonValueKind.Array } ? ReadSimpleSign(root) : null;
    }

    /// <summary>The ETSI indication in SimpleSign's terms: TOTAL_PASSED/PASSED → Valid, TOTAL_FAILED/FAILED → Invalid, else Indeterminate.</summary>
    internal static string Indication(string? etsi) => etsi switch
    {
        "TOTAL_PASSED" or "PASSED" => "Valid",
        "TOTAL_FAILED" or "FAILED" => "Invalid",
        _ => "Indeterminate",
    };

    /// <summary>The indication and sub-indication in plain words.</summary>
    internal static string Explain(string indication, string? subIndication) =>
        SubIndications.Explain(subIndication) is { } sub && indication != "Valid"
            ? indication == "Invalid" ? L.T("Not valid: {0}", sub) : L.T("No conclusion: {0}", sub)
            : indication switch
            {
                "Valid" => L.T("Valid: the signed content is intact, the signature verifies and the signer's chain reaches a trusted root."),
                "Invalid" => L.T("Not valid: a check that decides the result failed."),
                _ => L.T("No conclusion: the validator lacks something to decide (trust, revocation data or a proof of time)."),
            };

    // ── SimpleSign ────────────────────────────────────────────────────────

    private static ReportView ReadSimpleSign(JsonElement root)
    {
        var signatures = new List<ReportSignature>();
        foreach (var s in Property(root, "signatures")!.Value.EnumerateArray())
        {
            string etsi = Text(s, "indication") ?? "INDETERMINATE";
            string indication = Indication(etsi);
            string? sub = Text(s, "subIndication");
            string id = Text(s, "id") ?? L.T("Signature {0}", signatures.Count + 1);
            string? format = Text(s, "format");
            var chain = Array(s, "certificates").Select((c, i) => new ReportCertificate(
                CommonName(Text(c, "subject")) ?? "—", Text(c, "subject"), Text(c, "issuer"), Text(c, "serialNumber"),
                Text(c, "notBefore"), Text(c, "notAfter"), Bool(c, "selfSigned") ?? false, null, null)).ToList();
            var constraints = Array(s, "constraints")
                .Select(c => (Id: Text(c, "id") ?? "", Status: Status(Text(c, "status")), Message: Text(c, "message") ?? ""))
                .ToList();
            signatures.Add(new ReportSignature(
                id,
                format == "Document timestamp" ? "timestamp" : id.Contains('.', StringComparison.Ordinal) && id.StartsWith("signer-", StringComparison.Ordinal) ? "counterSignature" : "signature",
                format,
                indication,
                etsi,
                sub,
                Explain(indication, sub),
                Text(s, "signedBy"),
                Text(s, "signingTime"),
                Text(s, "bestSignatureTime"),
                chain,
                [.. Array(s, "timestamps").Select(t => new ReportTimestamp(Text(t, "time"), null, Text(t, "producedBy"), Text(t, "indication"), Text(t, "subIndication")))],
                [.. Array(s, "revocationData").Select(r => new ReportRevocation(Text(r, "type") ?? "?", Text(r, "indication"), Text(r, "subIndication"),
                    Text(r, "producedAt"), Text(r, "thisUpdate"), Text(r, "nextUpdate"), null, null, Text(r, "certificate"), Text(r, "status")) { Issuer = Text(r, "issuer") })],
                Group(constraints),
                Strings(s, "errors"),
                Strings(s, "warnings"),
                Strings(s, "infos")));
        }

        return new ReportView("simplesign", Text(root, "document"), Text(root, "validationTime"), null, signatures);
    }

    /// <summary>A ConstraintStatus name as the viewer's status.</summary>
    private static string Status(string? status) => status switch
    {
        "Passed" => "pass",
        "Warning" => "warn",
        "Failed" => "fail",
        "Indeterminate" => "fail",
        "Information" => "info",
        _ => "skip",
    };

    /// <summary>
    /// The constraints grouped by check and outcome (a check repeated for each certificate or token shows once, with all its
    /// messages), failures first, then warnings, information, passed and not checked; titles from the policy guide.
    /// </summary>
    internal static IReadOnlyList<ReportConstraint> Group(IEnumerable<(string Id, string Status, string Message)> constraints) =>
        [.. constraints
            .GroupBy(c => (Name: c.Id.Split('/')[^1], c.Status))
            .OrderBy(g => Rank(g.Key.Status))
            .Select(g =>
            {
                var guide = PolicyGuide.Of(g.Key.Name);
                return new ReportConstraint(g.Key.Name, guide?.Text ?? Words(g.Key.Name), guide?.Standard, g.Key.Status,
                    [.. g.Select(c => c.Message).Where(m => m.Length > 0).Distinct()], g.Count());
            })];

    private static int Rank(string status) => status switch { "fail" => 0, "warn" => 1, "info" => 2, "pass" => 3, _ => 4 };

    /// <summary>"SigningCertificateKeyUsage" → "Signing certificate key usage".</summary>
    private static string Words(string name)
    {
        var words = new System.Text.StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (i > 0 && char.IsUpper(c) && !char.IsUpper(name[i - 1]))
            {
                words.Append(' ').Append(char.ToLowerInvariant(c));
            }
            else
            {
                words.Append(c);
            }
        }

        return words.ToString();
    }

    // ── DSS ───────────────────────────────────────────────────────────────

    private static ReportView ReadDss(JsonElement root)
    {
        var simple = Property(root, "SimpleReport")!.Value;
        var diagnostic = Property(root, "DiagnosticData");
        var detailed = Property(root, "DetailedReport");
        var certificates = Index(diagnostic, "Certificate");
        var revocations = Index(diagnostic, "Revocation");
        var diagnosticSignatures = Index(diagnostic, "Signature");
        var signatures = new List<ReportSignature>();
        foreach (var item in Array(simple, "signatureOrTimestampOrEvidenceRecord"))
        {
            bool isTimestamp = Property(item, "Signature") is not { ValueKind: JsonValueKind.Object };
            if ((Property(item, "Signature") ?? Property(item, "Timestamp")) is not { ValueKind: JsonValueKind.Object } s)
            {
                continue;
            }

            string id = Text(s, "Id") ?? L.T("Signature {0}", signatures.Count + 1);
            string etsi = Text(s, "Indication") ?? "INDETERMINATE";
            string indication = Indication(etsi);
            string? sub = Text(s, "SubIndication");
            var chain = Array(Property(s, "CertificateChain"), "Certificate").Select(c => DssCertificate(c, certificates)).ToList();
            var timestamps = Array(Property(s, "Timestamps"), "Timestamp")
                .Select(t => new ReportTimestamp(Text(t, "ProductionTime"), TimestampType(t, diagnostic), Text(t, "ProducedBy"), Text(t, "Indication"), Text(t, "SubIndication")))
                .ToList();
            var details = Property(s, "AdESValidationDetails");
            signatures.Add(new ReportSignature(
                id,
                isTimestamp ? "timestamp" : Text(s, "ParentId") is not null ? "counterSignature" : "signature",
                Text(s, "SignatureFormat") ?? (Property(s, "TimestampLevel") is { } level ? Text(level, "value") : null),
                indication,
                etsi,
                sub,
                Explain(indication, sub),
                Text(s, "SignedBy") ?? Text(s, "ProducedBy"),
                Text(s, "SigningTime") ?? Text(s, "ProductionTime"),
                Text(s, "BestSignatureTime"),
                chain,
                timestamps,
                DssRevocation(diagnosticSignatures.GetValueOrDefault(id), revocations, certificates),
                DssConstraints(detailed, id),
                Messages(details, "Error"),
                Messages(details, "Warning"),
                Messages(details, "Info")));
        }

        string? policy = Property(simple, "ValidationPolicy") is { } p ? Text(p, "PolicyName") : null;
        return new ReportView("dss", Text(simple, "DocumentName"), Text(simple, "ValidationTime"), policy, signatures);
    }

    private static ReportCertificate DssCertificate(JsonElement entry, IReadOnlyDictionary<string, JsonElement> certificates)
    {
        string name = Text(entry, "QualifiedName") ?? Text(entry, "Id") ?? "—";
        if (Text(entry, "Id") is not { } id || !certificates.TryGetValue(id, out var c))
        {
            return new ReportCertificate(name, null, null, null, null, null, false, Bool(entry, "trusted"), null);
        }

        string? revocation = Array(c, "CertificateRevocation").Select(r => Text(r, "Status")).FirstOrDefault(s => s is not null);
        return new ReportCertificate(
            name,
            DistinguishedName(c, "SubjectDistinguishedName"),
            DistinguishedName(c, "IssuerDistinguishedName"),
            Text(c, "SerialNumber"),
            Text(c, "NotBefore"),
            Text(c, "NotAfter"),
            Bool(c, "SelfSigned") ?? false,
            Property(c, "Trusted") is { } trusted ? Bool(trusted, "value") : Bool(entry, "trusted"),
            revocation);
    }

    /// <summary>The RFC 2253 form of a DSS distinguished name (it gives the RFC 2253 and the canonical forms).</summary>
    private static string? DistinguishedName(JsonElement certificate, string name)
    {
        var forms = Array(certificate, name).ToList();
        var chosen = forms.FirstOrDefault(f => Text(f, "Format") == "RFC2253");
        return chosen.ValueKind == JsonValueKind.Object ? Text(chosen, "value") : forms.Select(f => Text(f, "value")).FirstOrDefault();
    }

    private static string? TimestampType(JsonElement simpleTimestamp, JsonElement? diagnostic)
    {
        string? id = Text(simpleTimestamp, "Id");
        return id is null ? null : Index(diagnostic, "Timestamp").GetValueOrDefault(id) is { ValueKind: JsonValueKind.Object } t ? Text(t, "Type") : null;
    }

    /// <summary>The revocation data DSS found for the signature, with the certificate each one is about and the status it gives.</summary>
    private static IReadOnlyList<ReportRevocation> DssRevocation(JsonElement signature, IReadOnlyDictionary<string, JsonElement> revocations, IReadOnlyDictionary<string, JsonElement> certificates)
    {
        if (signature.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        var list = new List<ReportRevocation>();
        foreach (var related in Array(Property(signature, "FoundRevocations"), "RelatedRevocation"))
        {
            if (Text(related, "Revocation") is not { } id)
            {
                continue;
            }

            revocations.TryGetValue(id, out var r);
            string? about = null;
            string? status = null;
            foreach (var (_, certificate) in certificates)
            {
                foreach (var entry in Array(certificate, "CertificateRevocation"))
                {
                    if (Text(entry, "Revocation") == id)
                    {
                        about = Text(certificate, "CommonName") ?? DistinguishedName(certificate, "SubjectDistinguishedName");
                        status = Text(entry, "Status");
                    }
                }
            }

            bool known = r.ValueKind == JsonValueKind.Object;
            list.Add(new ReportRevocation(
                Text(related, "Type") ?? (known ? Text(r, "Type") : null) ?? "?",
                null, null,
                known ? Text(r, "ProductionDate") : null,
                known ? Text(r, "ThisUpdate") : null,
                known ? Text(r, "NextUpdate") : null,
                known ? Text(r, "Origin") : null,
                known ? Text(r, "SourceAddress") : null,
                about,
                status)
            {
                Issuer = known && Property(r, "SigningCertificate") is { } signer && Text(signer, "Certificate") is { } issuerId && certificates.TryGetValue(issuerId, out var issuer)
                    ? Text(issuer, "CommonName") ?? DistinguishedName(issuer, "SubjectDistinguishedName")
                    : null,
            });
        }

        return list;
    }

    /// <summary>
    /// Every constraint DSS checked for the signature: those of its validation processes (basic, long-term, archival,
    /// qualification) and of its own building blocks, grouped by check and outcome.
    /// </summary>
    private static IReadOnlyList<ReportConstraint> DssConstraints(JsonElement? detailed, string id)
    {
        if (detailed is not { ValueKind: JsonValueKind.Object } report)
        {
            return [];
        }

        var found = new List<(string Key, string Title, string Status, string? Message)>();
        foreach (var item in Array(report, "signatureOrTimestampOrEvidenceRecord"))
        {
            foreach (var property in item.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Object && Text(property.Value, "Id") == id)
                {
                    Collect(property.Value, found, depth: 0);
                }
            }
        }

        foreach (var block in Array(report, "BasicBuildingBlocks"))
        {
            if (Text(block, "Id") == id)
            {
                Collect(block, found, depth: 0);
            }
        }

        return [.. found
            .GroupBy(c => (c.Key, c.Status))
            .OrderBy(g => Rank(g.Key.Status))
            .Select(g => new ReportConstraint(g.Key.Key, g.First().Title, null, g.Key.Status,
                [.. g.Select(c => c.Message).OfType<string>().Distinct()], g.Count()))];
    }

    /// <summary>The constraints under <paramref name="element"/>, at any depth (the processes nest the building blocks they use).</summary>
    private static void Collect(JsonElement element, List<(string Key, string Title, string Status, string? Message)> found, int depth)
    {
        if (depth > 8 || element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, "Constraint", StringComparison.Ordinal) && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var c in property.Value.EnumerateArray())
                {
                    var name = Property(c, "Name");
                    string key = (name is { ValueKind: JsonValueKind.Object } n ? Text(n, "Key") : null) ?? "?";
                    string title = (name is { ValueKind: JsonValueKind.Object } t ? Text(t, "value") : null) ?? key;
                    string status = Text(c, "Status") switch
                    {
                        "OK" => "pass",
                        "NOT OK" => "fail",
                        "WARNING" => "warn",
                        "INFORMATION" => "info",
                        _ => "skip",
                    };
                    string? message = s_messageKinds.Select(m => Property(c, m) is { ValueKind: JsonValueKind.Object } v ? Text(v, "value") : null)
                        .FirstOrDefault(m => m is not null) ?? Text(c, "AdditionalInfo");
                    found.Add((key, title, status, message));
                }
            }
            else if (property.Value.ValueKind == JsonValueKind.Object)
            {
                Collect(property.Value, found, depth + 1);
            }
            else if (property.Value.ValueKind == JsonValueKind.Array && !string.Equals(property.Name, "ChainItem", StringComparison.Ordinal))
            {
                foreach (var item in property.Value.EnumerateArray())
                {
                    Collect(item, found, depth + 1);
                }
            }
        }
    }

    // ── JSON helpers ──────────────────────────────────────────────────────

    private static Dictionary<string, JsonElement> Index(JsonElement? parent, string name)
    {
        var index = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var item in Array(parent, name))
        {
            if (Text(item, "Id") is { } id)
            {
                index.TryAdd(id, item);
            }
        }

        return index;
    }

    private static JsonElement? Property(JsonElement? element, string name)
    {
        if (element is not { ValueKind: JsonValueKind.Object } e)
        {
            return null;
        }

        foreach (var property in e.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return property.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? null : property.Value;
            }
        }

        return null;
    }

    private static IEnumerable<JsonElement> Array(JsonElement? element, string name) =>
        Property(element, name) is { ValueKind: JsonValueKind.Array } array ? array.EnumerateArray() : [];

    private static string? Text(JsonElement element, string name) => Property(element, name) switch
    {
        { ValueKind: JsonValueKind.String } s => s.GetString(),
        { ValueKind: JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False } v => v.GetRawText(),
        _ => null,
    };

    private static bool? Bool(JsonElement element, string name) => Property(element, name) switch
    {
        { ValueKind: JsonValueKind.True } => true,
        { ValueKind: JsonValueKind.False } => false,
        _ => null,
    };

    private static IReadOnlyList<string> Strings(JsonElement element, string name) =>
        [.. Array(element, name).Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).Distinct()];

    /// <summary>The messages of a DSS details block: <c>{"Error": [{"value": "…", "Key": "…"}]}</c>.</summary>
    private static IReadOnlyList<string> Messages(JsonElement? details, string name) =>
        [.. Array(details, name).Select(m => m.ValueKind == JsonValueKind.String ? m.GetString() : Text(m, "value")).OfType<string>().Distinct()];

    private static string? CommonName(string? subject)
    {
        if (subject is null)
        {
            return null;
        }

        foreach (string part in subject.Split(','))
        {
            string trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..];
            }
        }

        return subject;
    }
}
