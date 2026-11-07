using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.Cli.Commands;

/// <summary>Parsing shared by the options the CAdES, XAdES and PAdES sign commands have in common.</summary>
internal static class AdesOptionSupport
{
    /// <summary>The revocation source tried first: <c>ocsp</c> or <c>crl</c>. Null when the text is neither.</summary>
    internal static RevocationPreference? ParseRevocationPreference(string? value) => value?.ToLowerInvariant() switch
    {
        "ocsp" or "ocsp-first" => RevocationPreference.OcspFirst,
        "crl" or "crl-first" => RevocationPreference.CrlFirst,
        _ => null,
    };

    /// <summary>The error for an invalid <c>--revocation-preference</c>, or null.</summary>
    internal static string? ValidateRevocationPreference(string? value) =>
        value is not null && ParseRevocationPreference(value) is null
            ? $"Invalid revocation preference: {value}. Valid: ocsp, crl"
            : null;

    /// <summary>The long-term validation options for a <c>--revocation-preference</c> value.</summary>
    internal static LongTermValidationOptions LongTermOptions(string? revocationPreference) =>
        new(CliNetwork.Provider) { RevocationPreference = ParseRevocationPreference(revocationPreference) ?? RevocationPreference.OcspFirst };

    /// <summary>The error for a missing file among the values of <paramref name="option"/>, or null.</summary>
    internal static string? ValidateFiles(string option, IEnumerable<string>? paths)
    {
        string? missing = paths?.FirstOrDefault(path => !File.Exists(path));
        return missing is null ? null : $"File not found ({option}): {missing}";
    }

    /// <summary>The error for an inconsistent policy document request, or null.</summary>
    internal static string? ValidatePolicyDocument(string? policyOid, string? documentPath, string? specification)
    {
        if (documentPath is null)
        {
            return specification is null ? null : "--policy-specification is used with --policy-document";
        }

        if (policyOid is null)
        {
            return "--policy-document requires --policy-oid";
        }

        if (string.IsNullOrWhiteSpace(specification))
        {
            return "--policy-document requires --policy-specification (the OID or URI of the specification that defines the document's syntax)";
        }

        return File.Exists(documentPath) ? null : $"Policy document not found: {documentPath}";
    }

    /// <summary>
    /// The policy declared with the SHA-256 of its document, and the store that carries the document
    /// in the signature.
    /// </summary>
    internal static async Task<(SignaturePolicyReference Policy, SignaturePolicyStore Store)> LoadPolicyAsync(
        string oid, string? uri, string documentPath, string specification, CancellationToken cancellationToken)
    {
        byte[] document = await File.ReadAllBytesAsync(documentPath, cancellationToken);
        return (
            new SignaturePolicyReference(oid, Oids.Sha256, SHA256.HashData(document), uri),
            SignaturePolicyStore.FromDocument(specification, document));
    }

    /// <summary>Reads every file of a repeatable option.</summary>
    internal static async Task<List<ReadOnlyMemory<byte>>> ReadFilesAsync(IEnumerable<string> paths, CancellationToken cancellationToken)
    {
        var files = new List<ReadOnlyMemory<byte>>();
        foreach (string path in paths)
        {
            files.Add(await File.ReadAllBytesAsync(path, cancellationToken));
        }

        return files;
    }

    /// <summary>
    /// Splits <c>PATH[,MIME]</c>. A value that names an existing file is the path as it is, so a
    /// comma in a file name needs no escaping.
    /// </summary>
    internal static (string Path, string? MimeType) SplitPathAndMimeType(string value)
    {
        int comma = value.LastIndexOf(',');
        return comma <= 0 || File.Exists(value)
            ? (value, null)
            : (value[..comma], value[(comma + 1)..].Trim() is { Length: > 0 } mimeType ? mimeType : null);
    }

    /// <summary>Splits <c>URI=PATH[,MIME]</c>. Null when there is no <c>=</c> or a side of it is empty.</summary>
    internal static (string Uri, string Path, string? MimeType)? SplitUriAndPath(string value)
    {
        int equals = value.IndexOf('=', StringComparison.Ordinal);
        if (equals <= 0 || equals == value.Length - 1)
        {
            return null;
        }

        var (path, mimeType) = SplitPathAndMimeType(value[(equals + 1)..]);
        return (value[..equals], path, mimeType);
    }
}
