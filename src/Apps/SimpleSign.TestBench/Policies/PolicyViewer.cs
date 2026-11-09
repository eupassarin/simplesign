using System.Text;
using System.Text.Json;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Policies;

/// <summary>A policy to show: pasted or edited JSON, an upload, or (neither) the default of <see cref="Kind"/>.</summary>
/// <param name="Kind">"signing" or "validation": the default shown when no JSON is given.</param>
/// <param name="Json">The policy file's text.</param>
/// <param name="UploadId">An uploaded policy file.</param>
public sealed record PolicyViewRequest(string Kind = PolicyViewer.Validation, string? Json = null, string? UploadId = null);

/// <summary>One algorithm of a cryptographic list: its name, and the key size and date it is about.</summary>
public sealed record PolicyAlgorithmView(string Name, int? Size, string? Date);

/// <summary>
/// One element of a policy, with what it means.
/// </summary>
/// <param name="Name">The element name, as in the file.</param>
/// <param name="Path">The path from the root, as SimpleSign reports it (<c>SignatureConstraints/…/KeyUsage</c>).</param>
/// <param name="Kind">section, crypto or constraint.</param>
/// <param name="Level">FAIL, WARN, INFORM or IGNORE (null: the element has no level).</param>
/// <param name="Explanation">What the element means.</param>
/// <param name="Standard">The clause that defines it.</param>
/// <param name="Evaluation">
/// evaluated; toConnect (the validator already has what it needs, the constraint is not wired yet); toImplement (kept,
/// needs new work); or none (a section). The last two are reported as not checked (docs/policies/compatibility.md).
/// </param>
/// <param name="Ids">The values of a multi-value constraint.</param>
/// <param name="Algorithms">The algorithms of a cryptographic list.</param>
/// <param name="Attributes">The other attributes (Unit, Value, Format, UpdateDate, LevelAfterUpdate…).</param>
/// <param name="Children">The child elements.</param>
public sealed record PolicyNodeView(
    string Name,
    string Path,
    string Kind,
    string? Level,
    string Explanation,
    string? Standard,
    string Evaluation,
    IReadOnlyList<string> Ids,
    IReadOnlyList<PolicyAlgorithmView> Algorithms,
    IReadOnlyDictionary<string, string> Attributes,
    IReadOnlyList<PolicyNodeView> Children);

/// <summary>How many constraints a policy has at each level, and how many active ones SimpleSign evaluates, will connect or will implement.</summary>
public sealed record PolicyCounts(int Fail, int Warn, int Inform, int Ignore, int Evaluated, int ToConnect, int ToImplement);

/// <summary>A policy as a tree with explanations, or the reason it cannot be read.</summary>
public sealed record PolicyView(
    string Kind,
    string? Name,
    string? Description,
    string? Digest,
    string Json,
    string? Error,
    PolicyNodeView? Root,
    PolicyCounts? Counts,
    IReadOnlyDictionary<string, string> Levels);

/// <summary>Reads a policy file and explains it element by element, for the policy viewer.</summary>
internal static class PolicyViewer
{
    public const string Signing = "signing";
    public const string Validation = "validation";

    /// <summary>
    /// The constraint names the validation evaluator checks (see <c>ValidationPolicyEvaluator</c>), in the contexts
    /// it checks them: the signature, document timestamps, the trusted lists and the chain model.
    /// </summary>
    internal static readonly HashSet<string> EvaluatedValidationNames = new(StringComparer.Ordinal)
    {
        "AcceptablePolicies", "CA", "CertDigestMatch", "CertDigestPresent", "ExtendedKeyUsage", "KeyUsage", "NotExpired",
        "NotRevoked", "NotSelfSigned", "PolicyHashMatch", "PolicyIds", "ProspectiveCertificateChain", "QcCompliance", "QcSSCD",
        "Recognition", "ReferenceDataIntact", "RevocationDataAvailable", "RevocationFreshness", "SelfSigned", "Signature",
        "SignatureIntact", "SigningCertificatePresent", "SigningTime", "SigningTimeInCertRange", "TimestampDelay",
        "TLFreshness", "TLNotExpired", "TLVersion", "TLWellSigned", "Model",
    };

    /// <summary>Kept constraints that need new work before SimpleSign can evaluate them (docs/policies/compatibility.md).</summary>
    internal static readonly HashSet<string> ToImplementNames = new(StringComparer.Ordinal)
    {
        "StructuralValidation", "DocMDP", "FieldMDP", "SigFieldLock", "FormFillChanges", "AnnotationChanges",
        "UndefinedChanges", "PdfPageDifference", "PdfAnnotationOverlap", "ContentTimeStamp",
        "ContentTimeStampMessageImprint", "RevocationHasInformationAboutCertificate", "TLStructure",
    };

    private static readonly HashSet<string> s_attributes = new(StringComparer.Ordinal) { "Level", "Id", "Algo" };

    /// <summary>The view of a request.</summary>
    public static PolicyView View(PolicyViewRequest request, DocumentStore documents)
    {
        string? json = request.Json;
        if (json is null && request.UploadId is { } uploadId)
        {
            if (!documents.TryGet(uploadId, out var file))
            {
                return Failed(request.Kind, "", L.T("No document or upload '{0}'.", uploadId));
            }

            json = Encoding.UTF8.GetString(file!.Content).TrimStart('﻿');
        }

        string kind = json is null ? request.Kind : KindOf(json) ?? request.Kind;
        try
        {
            if (kind == Signing)
            {
                var policy = json is null ? SigningPolicy.Default : SigningPolicy.FromJson(json);
                return Build(kind, policy.Name, policy.Description, policy.Digest, policy.ToJson());
            }

            var validation = json is null ? ValidationPolicy.Default : ValidationPolicy.FromJson(json);
            return Build(kind, validation.Name, validation.Description, validation.Digest, validation.ToJson());
        }
        catch (InvalidDataException ex)
        {
            return Failed(kind, json ?? "", ex.Message);
        }
    }

    /// <summary>"signing" or "validation" by the root of the file; null when it has neither.</summary>
    internal static string? KindOf(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind != JsonValueKind.Object ? null
                : document.RootElement.TryGetProperty("SigningConstraints", out _) ? Signing
                : document.RootElement.TryGetProperty("ValidationConstraints", out _) ? Validation
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static PolicyView Failed(string kind, string json, string error) =>
        new(kind, null, null, null, json, error, null, null, Levels());

    private static Dictionary<string, string> Levels() =>
        PolicyGuide.Levels.ToDictionary(l => l.Key, l => l.Value.Text, StringComparer.Ordinal);

    private static PolicyView Build(string kind, string? name, string? description, string digest, string json)
    {
        using var document = JsonDocument.Parse(json);
        string rootName = kind == Signing ? "SigningConstraints" : "ValidationConstraints";
        var root = Node(rootName, "", document.RootElement.GetProperty(rootName), kind, isRoot: true);
        int fail = 0, warn = 0, inform = 0, ignore = 0, evaluated = 0, toConnect = 0, toImplement = 0;
        foreach (var node in All(root).Where(n => n.Level is not null))
        {
            switch (node.Level)
            {
                case "FAIL":
                    fail++;
                    break;
                case "WARN":
                    warn++;
                    break;
                case "INFORM":
                    inform++;
                    break;
                default:
                    ignore++;
                    break;
            }

            if (node.Level != "IGNORE")
            {
                switch (node.Evaluation)
                {
                    case "evaluated":
                        evaluated++;
                        break;
                    case "toConnect":
                        toConnect++;
                        break;
                    case "toImplement":
                        toImplement++;
                        break;
                }
            }
        }

        return new(kind, name, description, digest, json, null, root, new PolicyCounts(fail, warn, inform, ignore, evaluated, toConnect, toImplement), Levels());
    }

    private static IEnumerable<PolicyNodeView> All(PolicyNodeView node) => node.Children.SelectMany(All).Prepend(node);

    private static PolicyNodeView Node(string name, string path, JsonElement element, string kind, bool isRoot = false)
    {
        var children = new List<PolicyNodeView>();
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        var ids = new List<string>();
        var algorithms = new List<PolicyAlgorithmView>();
        string? level = null;
        foreach (var property in element.EnumerateObject())
        {
            if (isRoot && property.Name is "$schema" or "Name" or "Description")
            {
                continue;
            }

            switch (property.Name)
            {
                case "Level" when property.Value.ValueKind == JsonValueKind.String:
                    level = property.Value.GetString();
                    break;
                case "Id" when property.Value.ValueKind == JsonValueKind.Array:
                    ids.AddRange(property.Value.EnumerateArray().Select(v => v.ToString()));
                    break;
                case "Algo" when property.Value.ValueKind == JsonValueKind.Array:
                    algorithms.AddRange(property.Value.EnumerateArray().Select(Algorithm));
                    break;
                default:
                    if (property.Value.ValueKind == JsonValueKind.Object)
                    {
                        string childPath = path.Length == 0 ? property.Name : path + "/" + property.Name;
                        children.Add(Node(property.Name, childPath, property.Value, kind));
                    }
                    else if (!s_attributes.Contains(property.Name))
                    {
                        attributes[property.Name] = property.Value.ToString();
                    }

                    break;
            }
        }

        // An element without a level or values is a section, even when it is empty (PDFAConstraints: {}).
        bool empty = level is null && ids.Count == 0 && algorithms.Count == 0 && attributes.Count == 0;
        string nodeKind = name == "Cryptographic" ? "crypto" : children.Count > 0 || isRoot || empty ? "section" : "constraint";
        var guide = PolicyGuide.Of(name) ?? (nodeKind == "section" ? PolicyGuide.Section : PolicyGuide.Constraint);
        return new(name, path, nodeKind, level, guide.Text, guide.Standard, Evaluation(kind, path, name, nodeKind),
            ids, algorithms, attributes, children);
    }

    private static PolicyAlgorithmView Algorithm(JsonElement algorithm) =>
        algorithm.ValueKind == JsonValueKind.Object
            ? new(algorithm.TryGetProperty("Value", out var v) ? v.ToString() : "?",
                algorithm.TryGetProperty("Size", out var size) && size.TryGetInt32(out int bits) ? bits : null,
                algorithm.TryGetProperty("Date", out var date) ? date.ToString() : null)
            : new(algorithm.ToString(), null, null);

    /// <summary>Whether SimpleSign evaluates the element where it is (the signing policy: always), and if not, what is missing.</summary>
    private static string Evaluation(string kind, string path, string name, string nodeKind)
    {
        if (nodeKind == "section")
        {
            return "none";
        }

        if (kind == Signing)
        {
            return "evaluated";
        }

        bool inContext = path.StartsWith("SignatureConstraints/", StringComparison.Ordinal)
            || path.StartsWith("Timestamp/BasicSignatureConstraints/", StringComparison.Ordinal)
            || path == "Timestamp/TimestampDelay"
            || path.StartsWith("TrustedLists/", StringComparison.Ordinal)
            || path is "Model" or "Cryptographic";
        if (nodeKind == "crypto")
        {
            return inContext ? "evaluated" : "toConnect";
        }

        // The cryptographic lists are evaluated with the section that holds them.
        if (path.Contains("/Cryptographic/", StringComparison.Ordinal) || path.StartsWith("Cryptographic/", StringComparison.Ordinal))
        {
            string crypto = path[..(path.LastIndexOf('/'))];
            return Evaluation(kind, crypto, "Cryptographic", "crypto");
        }

        return inContext && EvaluatedValidationNames.Contains(name) ? "evaluated"
            : ToImplementNames.Contains(name) ? "toImplement"
            : "toConnect";
    }
}
